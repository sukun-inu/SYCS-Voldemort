import json
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from envutil import env_float


_APP_STARTED_AT = time.time()
_REQUEST_TIMESTAMPS: deque[float] = deque()
_REQUEST_HISTORY_SECONDS = 60
_TPS_WINDOW_SECONDS = 15
_FILE_LOCK = threading.Lock()
_MONITOR_LOCK = threading.Lock()

# インシデント記録の保持上限。全文を読んで末尾から取り出す作りなので、
# 際限なく増えると読み出しがそのぶん重くなる。
_INCIDENT_MAX_LINES = 2000
_INCIDENT_TRIM_BYTES = 512 * 1024  # ここを超えたときだけ行数を数えに行く
_MONITOR_STARTED = False
_LAST_ALERT_AT: dict[str, float] = {}


def record_request() -> None:
    """TPS 計測用に1リクエスト分の時刻を記録する。metrics_middleware から /static 以外の全リクエストで呼ばれる。

    呼ぶたびに _prune_requests も走らせる。専用の掃除タイミングを別に
    設けていないので、ここで一緒に処理しないと _REQUEST_TIMESTAMPS が
    リクエストが来続ける限り際限なく伸びる。
    """
    now = time.time()
    _REQUEST_TIMESTAMPS.append(now)
    _prune_requests(now)


def record_error_response(status_code: int, request_info: dict[str, Any]) -> None:
    """5xx のレスポンスだけをインシデントとして記録する。

    4xx（未認証・入力ミスなど日常的に起きるもの）まで拾うとインシデント
    一覧がノイズで埋もれ、本当に見るべき障害が流れてしまう。
    """
    if status_code < 500:
        return
    record_incident(
        kind="http_error",
        severity="critical",
        title=f"HTTP {status_code}",
        message="管理UIで 5xx レスポンスが発生しました。",
        metadata={"status_code": status_code, **request_info},
    )


def record_exception(exception: BaseException, request_info: dict[str, Any]) -> None:
    """metrics_middleware の最終防波堤（app.py 参照）が拾った未捕捉例外をインシデント化する。

    message を500文字で切るのは、例外によっては str() が巨大な文字列
    （長いクエリやスタック情報を埋め込んだメッセージ等）を返すことがあり、
    それを丸ごと jsonl に書くとインシデント一覧の1行が異常に重くなるため。
    """
    record_incident(
        kind="exception",
        severity="critical",
        title=type(exception).__name__,
        message=str(exception)[:500] or "Unhandled exception",
        metadata=request_info,
    )


def start_background_monitor(logger: Any | None = None) -> None:
    """バックグラウンド監視スレッドを起動する。

    app.py は `app = create_app()` をモジュール読み込み時に実行するため、
    テストでの再インポートなどで create_app() が複数回呼ばれることがある。
    _MONITOR_STARTED のガードが無いと、そのたびに監視スレッドが増殖する。
    daemon=True にしているのは、プロセス終了時にこの無限ループ
    （_monitor_loop）のせいで終了がブロックされないようにするため。
    """
    global _MONITOR_STARTED
    with _MONITOR_LOCK:
        if _MONITOR_STARTED:
            return
        _MONITOR_STARTED = True

    try:
        _monitor_dir().mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        if logger:
            logger.warning("admin monitor dir init failed: %s", exc)

    thread = threading.Thread(
        target=_monitor_loop,
        args=(logger,),
        name="admin-health-monitor",
        daemon=True,
    )
    thread.start()


def load_tone(percent: float, alert_at: float) -> str:
    """メーターの色。しきい値（アラートを記録する値）と同じ物差しで決める。

    色を固定にしていると、90% でも 5% でも同じ見た目になり、
    「色が付いている＝何かある」という読み方ができなくなる。
    """
    if percent >= alert_at:
        return "danger"
    if percent >= alert_at * 0.8:
        return "warning"
    return "success"


def sla_tone(percent: float) -> str:
    """SLA 表示の色。しきい値は load_tone と違い固定（99.9% / 99.0%）。

    「スリーナイン」慣習に合わせた値で、環境変数化していない。CPU/メモリ/TPS
    のような運用でチューニングする類の値ではなく、SLA の目標値そのものなので、
    ここを動かすなら数字の意味を理解した上でコードごと変えるべき、という判断。
    """
    if percent >= 99.9:
        return "success"
    if percent >= 99.0:
        return "warning"
    return "danger"


def collect_host_metrics() -> dict:
    """ダッシュボードの4指標（CPU/Memory/TPS/SLA）をまとめて1回で組み立てる。

    psutil.cpu_percent(interval=0.1) はブロッキング呼び出し（0.1秒待つ）。
    interval=None（前回呼び出しからの平均）にすると、呼び出し間隔がバラバラな
    場合に数値が安定しないため、多少待ってでも都度その場の値を取る方を選んでいる。
    """
    now = time.time()
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    tps = _request_tps(now)
    tps_target = env_float("ADMIN_TPS_TARGET", 50.0, minimum=0.01)
    tps_percent = _clamp_percent((tps / tps_target) * 100)
    boot_time = psutil.boot_time()
    sla_percent = _month_to_date_sla_percent(now)

    return {
        "updated_at": datetime.now().strftime("%H:%M:%S"),
        "metrics": {
            "cpu": {
                "label": "CPU",
                "percent": _clamp_percent(cpu_percent),
                "display": f"{cpu_percent:.1f}%",
                "detail": f"論理コア {psutil.cpu_count(logical=True) or 1}",
                "tone": load_tone(cpu_percent, env_float("ADMIN_CPU_ALERT_PERCENT", 90.0)),
            },
            "memory": {
                "label": "Memory",
                "percent": _clamp_percent(memory.percent),
                "display": f"{memory.percent:.1f}%",
                "detail": f"{_format_bytes(memory.used)} / {_format_bytes(memory.total)}",
                "tone": load_tone(memory.percent, env_float("ADMIN_MEMORY_ALERT_PERCENT", 90.0)),
            },
            "tps": {
                "label": "TPS",
                "percent": tps_percent,
                # 目盛りは目標に対する割合、数字は実測値。"0.4%" とだけ出ていると
                # 秒間リクエスト数が 0.4 なのか、目標の 0.4% なのか読めない。
                "display": f"{tps:.2f} req/s",
                "detail": f"目標 {tps_target:g} req/s の {tps_percent:.0f}%",
                "tone": load_tone(tps_percent, env_float("ADMIN_TPS_ALERT_PERCENT", 100.0)),
            },
            "sla": {
                "label": "SLA",
                "percent": _clamp_percent(sla_percent),
                "display": f"{sla_percent:.2f}%",
                "detail": f"記録済み停止 {_format_duration(_downtime_seconds_month_to_date(now))}",
                "tone": sla_tone(sla_percent),
            },
        },
        "runtime": {
            "admin_app": _format_duration(now - _APP_STARTED_AT),
            "host": _format_duration(now - boot_time),
        },
    }


def list_incidents(limit: int = 20) -> list[dict[str, Any]]:
    """ダッシュボード表示用のインシデント一覧。新しい順、_public_incident で整形済み。

    ファイルは末尾に追記されていくので reversed(lines) で新しい順にする。
    limit を1〜200に丸めているのは、0以下や巨大な値を渡されても
    「何も返らない」「全件読み込む」といった意図しない挙動にしないため。
    """
    limit = max(1, min(int(limit), 200))
    path = _incidents_file()
    if not path.exists():
        return []

    with _FILE_LOCK:
        lines = path.read_text(encoding="utf-8").splitlines()

    incidents: list[dict[str, Any]] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            incident = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(incident, dict):
            incidents.append(_public_incident(incident))
        if len(incidents) >= limit:
            break
    return incidents


def record_incident(
    *,
    kind: str,
    severity: str,
    title: str,
    message: str,
    metadata: dict[str, Any] | None = None,
    start_epoch: float | None = None,
    end_epoch: float | None = None,
    duration_seconds: float | None = None,
) -> dict[str, Any]:
    """インシデント（障害・エラー・ダウンタイム）を1件、incidents.jsonl に永続化する。

    全ての record_* / _record_* 系はここに集約する。呼び出し元ごとに書き込み
    形式を変えていないので、list_incidents や _downtime_seconds_for_period
    といった読み出し側が kind で分岐するだけで済む。
    """
    now = time.time()
    incident = {
        "id": uuid.uuid4().hex,
        "kind": kind,
        "severity": severity,
        "title": title,
        "message": message,
        "created_epoch": now,
        "created_at": _iso(now),
        "start_epoch": start_epoch,
        "start_at": _iso(start_epoch) if start_epoch else None,
        "end_epoch": end_epoch,
        "end_at": _iso(end_epoch) if end_epoch else None,
        "duration_seconds": round(duration_seconds, 3) if duration_seconds is not None else None,
        "metadata": metadata or {},
    }
    _append_jsonl(_incidents_file(), incident)
    return incident


def _monitor_loop(logger: Any | None) -> None:
    """start_background_monitor が起動するスレッド本体。プロセスが生きている限り回り続ける。

    起動直後に一度だけ _record_startup_downtime/_write_heartbeat を実行してから
    interval 秒おきのループへ入る。ループ内の try/except は「1回のtick失敗で
    監視スレッド自体が死んで二度と復活しない」事態を避けるためのもの
    （daemon スレッドなので落ちても誰も再起動しない）。
    """
    try:
        _record_startup_downtime()
        _write_heartbeat()
    except Exception as exc:
        if logger:
            logger.warning("admin monitor startup failed: %s", exc)

    interval = env_float("ADMIN_MONITOR_INTERVAL_SECONDS", 30.0, minimum=5.0)
    while True:
        time.sleep(interval)
        try:
            metrics = collect_host_metrics()
            _write_heartbeat()
            _record_threshold_alerts(metrics)
        except Exception as exc:
            if logger:
                logger.warning("admin monitor tick failed: %s", exc)


def _record_startup_downtime() -> None:
    """前回の heartbeat から今回の起動までの空白を、プロセス停止期間として記録する。

    heartbeat は動いている間しか更新されない。次に起動したときの
    「last_seen からどれだけ経っているか」が、そのままダウンタイムの実測値
    になる（プロセスクラッシュ・デプロイでの再起動のどちらも同じ形で拾える）。
    grace 以内の差は通常の再起動・再デプロイの範囲として無視する。
    """
    heartbeat = _read_json(_heartbeat_file())
    last_seen = heartbeat.get("last_seen_epoch") if isinstance(heartbeat, dict) else None
    if not isinstance(last_seen, (int, float)):
        return

    now = time.time()
    grace = env_float("ADMIN_DOWNTIME_GRACE_SECONDS", 120.0, minimum=1.0)
    downtime = now - float(last_seen)
    if downtime <= grace:
        return

    record_incident(
        kind="downtime",
        severity="critical",
        title="管理UIダウンタイム",
        message="前回 heartbeat から復帰までの空白をダウンタイムとして記録しました。",
        start_epoch=float(last_seen),
        end_epoch=now,
        duration_seconds=downtime,
        metadata={"grace_seconds": grace, "source": "startup_heartbeat_gap"},
    )


def _record_threshold_alerts(metrics: dict[str, Any]) -> None:
    """CPU/メモリ/TPS がしきい値を超えていたら、指標ごとにアラートを記録する。

    collect_host_metrics の tone 判定（load_tone）と閾値は同じ環境変数を見て
    いるが、ここは別経路。画面の色分けはリクエストのたびに再計算されるだけ
    だが、こちらは監視ループから呼ばれてインシデントとして残す側。
    """
    thresholds = {
        "cpu": env_float("ADMIN_CPU_ALERT_PERCENT", 90.0),
        "memory": env_float("ADMIN_MEMORY_ALERT_PERCENT", 90.0),
        "tps": env_float("ADMIN_TPS_ALERT_PERCENT", 100.0),
    }
    metric_map = metrics.get("metrics", {})
    if not isinstance(metric_map, dict):
        return

    for key, threshold in thresholds.items():
        metric = metric_map.get(key)
        if not isinstance(metric, dict):
            continue
        percent = float(metric.get("percent") or 0)
        if percent < threshold:
            continue
        _record_alert_with_cooldown(
            key=f"threshold:{key}",
            kind="resource_alert",
            severity="warning",
            title=f"{metric.get('label', key)} 使用率アラート",
            # display は指標ごとに単位が違う（TPS は req/s）。しきい値は割合なので割合で書く
            message=f"{percent:.1f}% がしきい値 {threshold:g}% を超えました。",
            metadata={"metric": key, "percent": percent, "threshold": threshold, "detail": metric.get("detail")},
        )


def _record_alert_with_cooldown(
    *,
    key: str,
    kind: str,
    severity: str,
    title: str,
    message: str,
    metadata: dict[str, Any],
) -> None:
    """key ごとにクールダウンを掛けてから record_incident する。

    _monitor_loop は既定30秒おきに tick する。クールダウン無しだと、
    しきい値を超えたまま張り付いている間、tick のたびに同じアラートが
    量産されてインシデント一覧が同一件名で埋まる。
    """
    now = time.time()
    cooldown = env_float("ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS", 300.0, minimum=0.0)
    last_at = _LAST_ALERT_AT.get(key, 0)
    if now - last_at < cooldown:
        return
    _LAST_ALERT_AT[key] = now
    record_incident(kind=kind, severity=severity, title=title, message=message, metadata=metadata)


def _write_heartbeat() -> None:
    """「生きていた最後の時刻」をファイルへ書く。_record_startup_downtime が次回起動時に読む相手。

    app_started_epoch も一緒に残しておくのは、heartbeat.json だけを見ても
    「このプロセスがいつから動いているか」と「直近まで動いていたか」を
    混同しないようにするため。
    """
    now = time.time()
    _write_json(
        _heartbeat_file(),
        {
            "last_seen_epoch": now,
            "last_seen_at": _iso(now),
            "pid": os.getpid(),
            "app_started_epoch": _APP_STARTED_AT,
            "app_started_at": _iso(_APP_STARTED_AT),
        },
    )


def _request_tps(now: float) -> float:
    """直近 _TPS_WINDOW_SECONDS 秒の平均 req/s。ウィンドウは保持期間（_REQUEST_HISTORY_SECONDS）より短い。

    表示用のTPSは短いウィンドウ（変化に追従してほしい）、保持は長め
    （ダッシュボードのポーリング間隔がずれても取りこぼさない）という別々の
    目的があるため、2つの秒数を分けて持っている。
    """
    _prune_requests(now)
    window_start = now - _TPS_WINDOW_SECONDS
    count = sum(1 for timestamp in _REQUEST_TIMESTAMPS if timestamp >= window_start)
    return count / _TPS_WINDOW_SECONDS


def _prune_requests(now: float) -> None:
    """_REQUEST_HISTORY_SECONDS より古い記録を先頭から捨てる。

    _REQUEST_TIMESTAMPS は record_request が append するだけで常に時刻昇順
    なので、先頭（最古）から見て cutoff を下回らなくなった時点で止めてよい。
    途中の要素だけ抜くような操作は想定していない。
    """
    cutoff = now - _REQUEST_HISTORY_SECONDS
    while _REQUEST_TIMESTAMPS and _REQUEST_TIMESTAMPS[0] < cutoff:
        _REQUEST_TIMESTAMPS.popleft()


def _month_to_date_sla_percent(now: float) -> float:
    """月初から今この瞬間までの稼働率。ダッシュボードの SLA 指標そのもの。

    period_seconds を `max(..., 1)` で下限を設けているのは、月が始まった
    直後（now がほぼ month_start）にゼロ除算するのを避けるため。
    """
    current = datetime.fromtimestamp(now, timezone.utc)
    month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
    period_seconds = max(now - month_start, 1)
    downtime = _downtime_seconds_for_period(month_start, now)
    uptime = max(period_seconds - downtime, 0)
    return _clamp_percent((uptime / period_seconds) * 100)


def _downtime_seconds_month_to_date(now: float) -> float:
    """collect_host_metrics の detail 表示（「記録済み停止 ○○」）用。

    _month_to_date_sla_percent と同じ期間定義を使う。
    """
    current = datetime.fromtimestamp(now, timezone.utc)
    month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
    return _downtime_seconds_for_period(month_start, now)


def _downtime_seconds_for_period(period_start: float, period_end: float) -> float:
    """kind="downtime" のインシデントのうち、指定期間と重なった秒数だけを合算する。

    インシデントの start/end をそのまま足すと、月初より前に始まって月をまたいで
    続いたダウンタイムまで期間内の秒数として過大に数えてしまう。
    max(start, period_start) / min(end, period_end) で期間との重なり部分だけに
    切り詰めてから加算する。
    """
    total = 0.0
    for incident in _iter_incidents():
        if incident.get("kind") != "downtime":
            continue
        start = incident.get("start_epoch")
        end = incident.get("end_epoch")
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            continue
        overlap_start = max(float(start), period_start)
        overlap_end = min(float(end), period_end)
        if overlap_end > overlap_start:
            total += overlap_end - overlap_start
    return total


def _iter_incidents() -> list[dict[str, Any]]:
    """全インシデントを生データのまま返す（_public_incident の整形をかけない）内部用。

    list_incidents（画面向け）とは別に用意しているのは、SLA計算
    （_downtime_seconds_for_period）が start_epoch/end_epoch という生の数値を
    必要とするため。_public_incident はそれらを duration 文字列に変換して
    しまい、計算には使えない。
    """
    path = _incidents_file()
    if not path.exists():
        return []

    incidents: list[dict[str, Any]] = []
    with _FILE_LOCK:
        lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        try:
            incident = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(incident, dict):
            incidents.append(incident)
    return incidents


def _public_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """list_incidents が画面へ返す1件分の形へ整形する。生の epoch フィールドは出さない。

    created_epoch/start_epoch/end_epoch はサーバ内部の計算（_downtime_seconds_for_period
    等）専用の値で、画面側はローカライズ済みの created_at と duration
    （_format_duration 済みの文字列）だけを表示に使う。get() にデフォルトを
    与えているのは、古い形式で保存された行に欠けているキーがあっても
    一覧描画自体は止めないため。
    """
    duration = incident.get("duration_seconds")
    return {
        "id": incident.get("id"),
        "kind": incident.get("kind", "unknown"),
        "severity": incident.get("severity", "info"),
        "title": incident.get("title", "Incident"),
        "message": incident.get("message", ""),
        "created_at": incident.get("created_at", ""),
        "duration": _format_duration(duration) if isinstance(duration, (int, float)) else None,
        "metadata": incident.get("metadata", {}),
    }


def _monitor_dir() -> Path:
    """heartbeat/incidents の保存先。ADMIN_MONITOR_DIR > SETTINGS_DIR > このファイルからの相対パスの順で決める。

    SETTINGS_DIR を後ろで参照するのは、settings.json 一式と同じボリューム
    （デプロイ環境で永続化される場所）に監視データも一緒に置くのがデフォルトで、
    それとは別の置き場が必要なときだけ ADMIN_MONITOR_DIR で個別に上書きできる
    ようにするため。
    """
    default_dir = Path(__file__).resolve().parent.parent / "data"
    settings_dir = Path(os.getenv("SETTINGS_DIR", str(default_dir)))
    return Path(os.getenv("ADMIN_MONITOR_DIR", str(settings_dir / "admin_monitor")))


def _heartbeat_file() -> Path:
    """_write_heartbeat / _record_startup_downtime が読み書きする単一ファイルのパス。"""
    return _monitor_dir() / "heartbeat.json"


def _incidents_file() -> Path:
    """record_incident が追記し、list_incidents/_iter_incidents が読む単一ファイルのパス。"""
    return _monitor_dir() / "incidents.jsonl"


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    """record_incident の実際の書き込み。追記のたびに _trim_jsonl で上限チェックまで行う。

    _FILE_LOCK を取るのは、監視スレッド（_monitor_loop）とリクエスト処理
    スレッドが同時に record_incident を呼びうるため。呼び出しごとに追記＋
    トリム判定を1セットにして、この2つが割り込み合わないようにしている。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with _FILE_LOCK:
        with path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")
        _trim_jsonl(path)


def _trim_jsonl(path: Path) -> None:
    """行数の上限を超えたら古い行から捨てる。

    admin.log は RotatingFileHandler で回しているのに、こちらは追記のみで
    上限が無かった。読み出しはファイル全文をメモリに載せるので、放っておくと
    増え続けたぶんだけ遅く・重くなる。呼び出し元が _FILE_LOCK を持っている前提。
    """
    try:
        if path.stat().st_size <= _INCIDENT_TRIM_BYTES:
            return
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) <= _INCIDENT_MAX_LINES:
            return
        kept = lines[-_INCIDENT_MAX_LINES:]
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """heartbeat.json の書き込み。一時ファイルへ書いてから replace() で入れ替える（tmp.replace は原子的操作）。

    直接 path へ書くと、書き込み途中でプロセスが落ちた場合に heartbeat.json が
    壊れたJSONのまま残る。次回起動時の _record_startup_downtime が
    _read_json で読めずに「ダウンタイム不明」扱いになってしまうため、
    tmp+replace で「壊れた途中状態」を作らないようにしている。
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    with _FILE_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    """heartbeat.json の読み込み。壊れていても例外を投げず空 dict で返す。

    _record_startup_downtime はこの戻り値が空でも「heartbeat が無い＝
    ダウンタイム計算をスキップ」として扱う設計なので、ここで例外を上げると
    監視スレッドの起動処理そのものが落ちる（_monitor_loop 側の except は
    拾うが、本来ここで吸収すべき想定内の異常）。
    """
    if not path.exists():
        return {}
    with _FILE_LOCK:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return data if isinstance(data, dict) else {}


def _iso(epoch: float | None = None) -> str:
    """epoch を UTC の ISO8601 文字列にする。record_incident が created_at 等の表示用文字列を作るのに使う。

    timezone.utc を明示しているのは、fromtimestamp にタイムゾーンを渡さないと
    ホストのローカルタイムで解釈され、サーバの実行環境によって同じ epoch でも
    違う時刻文字列になってしまうため。
    """
    value = time.time() if epoch is None else epoch
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _clamp_percent(value: float) -> float:
    """メーター系の数値を表示可能な 0〜100% に丸める。TPSの実測が目標を超えると100%を超えうるため必要。"""
    return round(min(max(float(value), 0.0), 100.0), 2)


def _format_bytes(value: float) -> str:
    """メモリ使用量の表示（例: "1.2 GB"）。collect_host_metrics の detail 表示専用の整形。"""
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _format_duration(seconds: float) -> str:
    """秒数を "2h 30m" のような人間向け表示に丸める。runtime 表示とインシデント duration の両方が使う共通の整形。

    上位2単位までしか出さない（日→時間で止め、分・秒は捨てる、等）。
    稼働時間やダウンタイムの表示で「3日と4時間と12分と5秒」まで細かく出しても
    読み手には粒度が細かすぎるだけなので、目安として読める粒度に絞っている。
    負の秒数は 0 に丸める（クロックのずれ等で負の duration が来ても "0s" 表示に倒す）。
    """
    total = max(int(seconds), 0)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"
