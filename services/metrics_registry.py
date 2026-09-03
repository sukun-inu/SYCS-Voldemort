"""Netdata へ渡すためのメトリクス。Valkey に集めて、1つの /metrics から出す。

■ なぜ Valkey に集めるのか

素直に作ると、各プロセスが自分のメトリクスを自分の /metrics で出すことになる。
それだと2つ困る。

  1. web は WEB_WORKERS=2 が既定で、uvicorn が同じポートを複数プロセスで
     受ける。**スクレイプがワーカー1個にしか当たらないので、カウンタが
     取りこぼれる。** どのワーカーに当たるかは毎回変わるため、値が上下する
     （カウンタなのに減る）という、いちばん読みにくい壊れ方をする。
  2. bot は HTTP サーバーを持っていない。持たせるとポートが1つ増え、
     Discord のイベントループの隣に別のサーバーが並ぶ。

全プロセスが Valkey へ書き、管理画面の /metrics が読んで出す形にすると、
スクレイプ先が1つで済み、ワーカーの数にも依存しない。

■ 3種類の鍵

  hb:<アプリ>              最後に報告した時刻（エポック秒）。期限を付けない。
  g:<アプリ>:<名前>        瞬間値（ゲージ）。期限を付ける。
  c:<名前>|<ラベル>        累積値（カウンタ）。**期限を付けない。**

ゲージに期限を付けるのは、死んだプロセスの「最後の値」が生きているように
見え続けるのを防ぐため。逆にカウンタへ期限を付けてはいけない。途中で消えると
読む側は「減った」と解釈し、差分がおかしくなる。

■ 生存は「消える」ではなく「0 になる」で表す

死活は sycs_up として必ず 0 か 1 で出す。系列が消える形にすると、Netdata 側で
「無くなったこと」を条件に書く必要があり、値を見るより難しくなる。そのため
心拍の時刻には期限を付けず、読むときに now との差から 0/1 を決めている。

■ Valkey が無くても落ちない

書き込みは services/shared_cache.py 越しなので、繋がらなければ黙って諦める。
読み出し（render）は空の結果を返す。**メトリクスが取れないことでアプリが
落ちてはいけない。** 監視のために可用性を下げるのは本末転倒になる。
"""

from __future__ import annotations

import threading
import time
from typing import Iterable

from envutil import env_float
from services.shared_cache import SharedCache, shared_cache

# 名前空間。shared_cache が付ける "sycs:" のさらに下。
NAMESPACE = "metrics"

# 出力するメトリクス名の接頭辞。Netdata 側の設定（go.d/prometheus.conf）でこの
# 名前を拾うので、変えると向こうの設定も直す必要がある。
METRIC_PREFIX = "sycs"

# ゲージの既定の寿命。報告の間隔（既定30秒）より十分長く、かつ「死んだのに
# 残っている」と言われない程度に短くする。
_DEFAULT_GAUGE_TTL_SECONDS = 120

# 心拍がこれより古いアプリは落ちている（sycs_up=0）とみなす。
_DEFAULT_STALE_AFTER_SECONDS = 90.0


def _escape_label_value(value: str) -> str:
    """Prometheus のラベル値として安全な形にする。

    エスケープを省くと、値に " や改行が混ざった時点で**その行以降の出力全体が
    壊れる。** Netdata 側からは「メトリクスが1つ欠けた」ではなく「読めない」に
    見えるので、原因を追いにくい。
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(labels: dict[str, str] | None) -> str:
    """ラベルを {k="v",...} の形にする。空なら空文字。

    並びを固定している（sorted）。固定しないと、同じ内容なのに出力の文字列が
    毎回変わり、差分を見比べられない。
    """
    if not labels:
        return ""
    inner = ",".join(f'{key}="{_escape_label_value(value)}"' for key, value in sorted(labels.items()))
    return "{" + inner + "}"


def _format_value(value: float) -> str:
    """Prometheus の値として出す。整数は小数点を付けずに出す。

    付けたままでも読めるが、桁の多いカウンタが指数表記になると
    (1e+06 のように) 目で追えなくなる。
    """
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


def _encode_counter_key(name: str, labels: dict[str, str] | None) -> str:
    """カウンタの鍵。名前とラベルを "|" で連結する。

    ラベルの並びを sorted で固定している。**固定しないと、同じカウンタが
    ラベルの順番違いで別の鍵になり、2つに分かれて数えられる。**
    """
    if not labels:
        return name
    joined = ",".join(f"{key}={value}" for key, value in sorted(labels.items()))
    return f"{name}|{joined}"


def _decode_counter_key(key: str) -> tuple[str, dict[str, str]]:
    """_encode_counter_key の逆。壊れていたらラベル無しとして扱う。

    ここで例外を出すと、Valkey に1つ変な鍵が入っているだけで /metrics 全体が
    500 になる。1つ落としても他のメトリクスは出したい。
    """
    name, _, joined = key.partition("|")
    if not joined:
        return name, {}
    labels: dict[str, str] = {}
    for pair in joined.split(","):
        label_key, sep, label_value = pair.partition("=")
        if sep and label_key:
            labels[label_key] = label_value
    return name, labels


class CounterBuffer:
    """カウンタをプロセス内に溜めておく入れ物。

    ■ なぜ溜めるのか

    リクエストのたびに Valkey へ INCR しに行くと、1リクエストあたり往復1回ぶん
    （ローカルでも 0.5ms 前後）が critical path に乗る。数えるためにリクエストを
    遅くするのは順序が逆なので、溜めて定期的にまとめて流す。

    ■ なぜ差分（delta）で持つのか

    流したあと 0 に戻す形にしている。累積値を持って「毎回 SET する」形にすると、
    プロセスが再起動した瞬間に Valkey 側の値が巻き戻る。差分を INCR で足す形なら、
    誰が再起動しても Valkey 側の累積は減らない。

    スレッド安全にしてある。管理画面のリクエストはイベントループ上だが、
    監視スレッドから触る余地を残しておくため。
    """

    def __init__(self) -> None:
        """空の入れ物を作る。"""
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}

    def add(self, name: str, labels: dict[str, str] | None = None, amount: int = 1) -> None:
        """1件数える。ここは絶対に例外を出さないこと（リクエスト経路から呼ばれる）。"""
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + amount

    def drain(self) -> list[tuple[str, dict[str, str], int]]:
        """溜まったぶんを取り出して空にする。

        取り出しと空にするのを1つのロックの中で行う。分けると、その隙間に
        入った数え上げが失われる。
        """
        with self._lock:
            items = list(self._counts.items())
            self._counts.clear()
        return [(name, dict(labels), count) for (name, labels), count in items]

    def restore(self, items: list[tuple[str, dict[str, str], int]]) -> None:
        """流せなかったぶんを戻す。

        **これが無いと、Valkey が一時的に落ちている間の計数が捨てられる。**
        drain したあと送信に失敗したら、必ずこれで戻すこと。
        """
        for name, labels, count in items:
            self.add(name, labels, count)


_BUFFER = CounterBuffer()


def counters() -> CounterBuffer:
    """プロセス共通のカウンタ入れ物。"""
    return _BUFFER


class MetricsRegistry:
    """メトリクスの書き込みと、Prometheus 形式での組み立て。"""

    def __init__(
        self,
        shared: SharedCache | None = None,
        *,
        gauge_ttl_seconds: int = _DEFAULT_GAUGE_TTL_SECONDS,
        stale_after_seconds: float = _DEFAULT_STALE_AFTER_SECONDS,
    ) -> None:
        """shared を省略すると、環境変数から作られた共有キャッシュを使う。"""
        self._shared = shared
        self.gauge_ttl_seconds = max(1, int(gauge_ttl_seconds))
        self.stale_after_seconds = max(1.0, float(stale_after_seconds))

    @property
    def shared(self) -> SharedCache:
        """共有キャッシュ。ここまで遅らせるのは、import 時に環境変数を読まないため。"""
        if self._shared is None:
            self._shared = shared_cache()
        return self._shared

    async def heartbeat(self, app: str) -> None:
        """このアプリが生きていることを記録する。定期的に呼ぶこと。

        期限を付けない。付けると系列が消えて、Netdata 側で「無くなったこと」を
        条件に書く必要が出る（モジュール冒頭）。
        """
        await self.shared.set_value(NAMESPACE, f"hb:{app}", str(time.time()))

    async def set_gauge(self, app: str, name: str, value: float) -> None:
        """瞬間値を記録する。期限付きなので、報告を止めたら消える。"""
        await self.shared.set_value(
            NAMESPACE,
            f"g:{app}:{name}",
            _format_value(float(value)),
            ttl_seconds=self.gauge_ttl_seconds,
        )

    async def incr_counter(self, name: str, labels: dict[str, str] | None = None, amount: int = 1) -> None:
        """累積値を増やす。原子的に増やすので、複数プロセスから同時に呼んでよい。"""
        await self.shared.incr(NAMESPACE, f"c:{_encode_counter_key(name, labels)}", amount=amount)

    async def render(self, *, extra: Iterable[tuple[str, dict[str, str] | None, float, str, str]] = ()) -> str:
        """Prometheus のテキスト形式を組み立てる。

        extra は「このプロセスでその場で測れるもの」を足す口
        （名前・ラベル・値・種別・説明の組）。Valkey を経由させる必要が無い
        値まで書き込みに行くと、スクレイプのたびに書き込みが走る。

        Valkey に繋がらないときは、extra だけで組み立てた結果を返す。**空を
        返さないこと。** 空だと Netdata 側は「収集器が壊れた」と扱い、
        「Valkey が落ちている」という本当の情報が伝わらない。
        """
        items = await self.shared.scan_values(NAMESPACE)
        now = time.time()

        lines: list[str] = []
        # モジュール直下の counters() と名前がぶつからないよう _series を付ける。
        # 同名にすると、この関数の中から counters() を呼べなくなる（実際に一度
        # 隠してしまった）。
        gauge_series: dict[str, list[tuple[dict[str, str], float]]] = {}
        counter_series: dict[str, list[tuple[dict[str, str], float]]] = {}

        up: list[tuple[dict[str, str], float]] = []
        age: list[tuple[dict[str, str], float]] = []

        for key, raw in sorted(items.items()):
            value = _parse_float(raw)
            if value is None:
                continue
            if key.startswith("hb:"):
                app = key[len("hb:") :]
                seconds = max(0.0, now - value)
                up.append(({"app": app}, 1.0 if seconds < self.stale_after_seconds else 0.0))
                age.append(({"app": app}, seconds))
            elif key.startswith("g:"):
                app, _, name = key[len("g:") :].partition(":")
                if name:
                    gauge_series.setdefault(name, []).append(({"app": app}, value))
            elif key.startswith("c:"):
                name, labels = _decode_counter_key(key[len("c:") :])
                counter_series.setdefault(name, []).append((labels, value))

        if up:
            lines += _block("up", "gauge", "1 なら報告が届いている、0 なら止まっている", up)
            lines += _block("heartbeat_age_seconds", "gauge", "最後の報告からの経過秒数", age)

        # 共有キャッシュ自体が生きているか。**これを出しておかないと、
        # 「Valkey が落ちてメトリクスが空になった」のか「本当に静かだった」のかを
        # 区別できない。**
        lines += _block(
            "shared_cache_available",
            "gauge",
            "共有キャッシュ（Valkey）へ書き読みできているか",
            [({}, 1.0 if self.shared.available else 0.0)],
        )

        for name, series in sorted(gauge_series.items()):
            lines += _block(name, "gauge", f"{name}（各アプリが報告した瞬間値）", series)
        for name, series in sorted(counter_series.items()):
            lines += _block(name, "counter", f"{name}（累積）", series)
        for name, extra_labels, value, kind, help_text in extra:
            lines += _block(name, kind, help_text, [(extra_labels or {}, value)])

        return "\n".join(lines) + "\n"


def _parse_float(raw: str) -> float | None:
    """Valkey から来た文字列を数値にする。読めなければ None（その1件だけ捨てる）。"""
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _block(
    name: str,
    kind: str,
    help_text: str,
    series: list[tuple[dict[str, str], float]],
) -> list[str]:
    """1つのメトリクスの HELP・TYPE・値の行をまとめて作る。

    HELP と TYPE は、同じメトリクス名について1回だけ出すこと。複数回出すと
    Prometheus の形式として不正で、収集器が行を捨てる。
    """
    if not series:
        return []
    full = f"{METRIC_PREFIX}_{name}"
    lines = [f"# HELP {full} {help_text}", f"# TYPE {full} {kind}"]
    for labels, value in sorted(series, key=lambda pair: sorted(pair[0].items())):
        lines.append(f"{full}{_format_labels(labels)} {_format_value(value)}")
    return lines


_INSTANCE: MetricsRegistry | None = None


def metrics_registry() -> MetricsRegistry:
    """メトリクスの登録簿を返す（1プロセスに1つ）。"""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = MetricsRegistry(
            gauge_ttl_seconds=int(env_float("METRICS_GAUGE_TTL_SECONDS", _DEFAULT_GAUGE_TTL_SECONDS, minimum=5.0)),
            stale_after_seconds=env_float("METRICS_STALE_AFTER_SECONDS", _DEFAULT_STALE_AFTER_SECONDS, minimum=5.0),
        )
    return _INSTANCE


def set_metrics_registry(instance: MetricsRegistry | None) -> None:
    """登録簿を差し替える（テスト用）。None を渡すと次回作り直す。"""
    global _INSTANCE
    _INSTANCE = instance
