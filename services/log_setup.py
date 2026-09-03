"""プロセスのログをファイルへ落とす設定。全プロセスがここを通る。

■ なぜ1箇所にまとめるか

以前は main.py と webapp_admin/app.py がそれぞれ
`RotatingFileHandler(maxBytes=1_000_000, backupCount=3)` を書いていて、
**合計 4MB を超えた分は消えていた。** 混んだ日は半日ぶんも残らない。
CDN と Web に至ってはファイルへ落としておらず、コンテナの標準出力が
流れていくだけだった。

■ どう変えたか

日付で回して、既定 3,650 日（10年）保管する。1日1ファイルなので
「いつのログか」がファイル名で分かり、古いものから順に消える。
回した後のファイルは gzip で畳む——10年ぶんを素で置くと、1日 5MB でも
18GB になる。テキストログは 10 分の1前後まで縮む。

**現在書いているファイルは畳まない。** `tail -f` で追えなくなるため。

■ 畳んだ名前と、掃除の関係

`TimedRotatingFileHandler` は「namer が付けた名前」で古いファイルを探して
消す。畳んだ結果が `bot.log.2026-09-03.gz` なのに namer が
`bot.log.2026-09-03` を返すと、**掃除が1件も見つけられず 10年ぶんが
永久に残る。** namer と rotator は必ず同じ名前を指すこと。

■ 保管日数を変えるとき

`LOG_RETENTION_DAYS` で日数を渡す。0 以下や数値以外は既定へ倒れる
（envutil.env_int の作法に合わせている）。**減らすと、その場では消えない**
——次に日付が変わったときの掃除で、超過分がまとめて消える。
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from envutil import env_int

logger = logging.getLogger(__name__)

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# 10年。ユーザー状態の履歴（USER_STATE_RETENTION_DAYS）と同じ既定にしてある。
DEFAULT_RETENTION_DAYS = 3650

# 畳んだファイルに付ける拡張子。namer と rotator の両方が使う。
GZIP_SUFFIX = ".gz"


def gzip_namer(default_name: str) -> str:
    """回した先のファイル名。`bot.log.2026-09-03.gz`。

    掃除（getFilesToDelete）はこの名前でディスクを探すので、rotator が
    実際に作る名前と必ず一致させること。
    """
    return default_name + GZIP_SUFFIX


def gzip_rotator(source: str, dest: str) -> None:
    """回し終えたファイルを gzip で畳む。dest は namer が付けた `.gz` つきの名前。

    畳めなかった場合は `.gz` を外した素の名前で残す。**ログの後始末で本体を
    止めない**（ディスクが一杯・権限が無いといった理由で失敗しうる）。
    ただし素で残したものは掃除の対象から外れるので、標準エラーへ出して
    気づけるようにする——ここで logging を使うと、回している最中の
    ハンドラへ書き戻すことになるので使わない。
    """
    try:
        with open(source, "rb") as raw, gzip.open(dest, "wb") as packed:
            shutil.copyfileobj(raw, packed)
        os.remove(source)
    except Exception as exc:  # pragma: no cover - ディスク都合でしか起きない
        plain = dest[: -len(GZIP_SUFFIX)] if dest.endswith(GZIP_SUFFIX) else dest
        try:
            os.replace(source, plain)
        except OSError:
            pass
        print(
            f"[log_setup] ログを畳めませんでした（{plain} を素のまま残しました。"
            f"このファイルは保管日数の掃除に入りません）: {exc}",
            file=sys.stderr,
        )


def install_file_logging(log_dir: Path, filename: str, *, level: int = logging.INFO) -> Path:
    """root ロガーへ、日付で回すファイルハンドラを1つ足す。

    同じファイルへのハンドラが既にあれば足さない（uvicorn の reload や
    テストでの再 import で二重に書き込まれるのを防ぐ）。戻り値は書き込む
    ファイルのパスで、呼び出し側がログに出せるようにしてある。
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / filename

    root = logging.getLogger()
    for existing in root.handlers:
        if isinstance(existing, TimedRotatingFileHandler) and Path(getattr(existing, "baseFilename", "")) == path:
            return path

    days = env_int("LOG_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, minimum=1)
    handler = TimedRotatingFileHandler(
        path,
        when="midnight",
        interval=1,
        backupCount=days,
        encoding="utf-8",
    )
    handler.suffix = "%Y-%m-%d"
    handler.namer = gzip_namer
    handler.rotator = gzip_rotator
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.setLevel(level)
    root.addHandler(handler)
    return path


# 既定で信頼するプロキシの帯域。
#
# ループバックだけでは**足りなかった。** compose 構成では、リバースプロキシから
# 見た接続元は Docker のブリッジゲートウェイ（172.19.0.1 など）になる。
# 127.0.0.1/32 しか信頼していなかったため uvicorn が X-Forwarded-For を捨て、
# アクセスログが 172.19.0.1 で埋まっていた（＝直す前と同じ状態）。
#
# 172.16.0.0/12 は Docker がブリッジに使う既定の帯域。家庭・社内の LAN で
# よく使われる 192.168.0.0/16 と 10.0.0.0/8 は**入れていない**——このアプリは
# ポートを公開するので、同じ LAN から直接叩いてヘッダを偽装できてしまう。
# その構成で使うなら TRUSTED_PROXY_CIDRS に明示すること。
DEFAULT_TRUSTED_PROXIES = "127.0.0.1/32,::1/128,172.16.0.0/12"


def trusted_proxies() -> str:
    """uvicorn の `forwarded_allow_ips` へ渡す、信頼するプロキシの一覧。

    リバースプロキシの向こう側から来ると、TCP の接続元はプロキシ自身
    （compose なら Docker のブリッジゲートウェイ）になる。**アクセスログも
    レート制限も、全部その1つのIPとして記録される。** 誰が来たのか
    分からないので、攻撃元も、よく使っている人も区別が付かない。

    `X-Forwarded-For` を見れば本当の接続元が分かるが、**そのヘッダは
    誰でも自分で付けられる。** 直接つないできた相手が信頼するプロキシの
    帯域に入っているときだけ見ること。ここを `*` にすると、外から直接
    叩いてヘッダを偽装するだけで別人になりすませる。

    webapp/security.py の `load_trusted_proxy_cidrs()` と同じ環境変数・同じ
    既定を読む——**片方だけ広げると、レート制限とアクセスログで別のIPを
    見る**ことになる。
    """
    raw = os.getenv("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_PROXIES).strip()
    return raw or "127.0.0.1"


# 一度警告した接続元。同じ相手で毎リクエスト警告すると、ログがそれで埋まる。
_WARNED_PEERS: set[str] = set()


def warn_if_forwarded_ignored(peer_ip: str | None, forwarded_for: str | None) -> None:
    """信頼していない相手から X-Forwarded-For が来たら、1回だけ警告する。

    **この設定の間違いは、黙って元に戻る形で失敗する。** ヘッダが捨てられる
    だけなので例外も出ず、ログにはプロキシのIPが並び続ける。「直したはず
    なのに変わらない」と気づくまで時間がかかった（実際にそうなった）ので、
    何を足せばよいかを名指しで出す。

    同じ相手では1回しか出さない。毎リクエスト出すと、本当の異常が埋もれる。
    """
    if not peer_ip or not forwarded_for or peer_ip in _WARNED_PEERS:
        return
    _WARNED_PEERS.add(peer_ip)
    logger.warning(
        "[proxy] %s から X-Forwarded-For が来ましたが、信頼していないので無視しました。"
        "アクセス元はこのIPとして記録されます。プロキシならば TRUSTED_PROXY_CIDRS に "
        "%s/32 を足してください（現在の設定: %s）",
        peer_ip,
        peer_ip,
        trusted_proxies(),
    )
