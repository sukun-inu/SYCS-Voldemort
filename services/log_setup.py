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
import json
import logging
import os
import shutil
import sys
from datetime import datetime
from functools import lru_cache
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any

from envutil import env_int

logger = logging.getLogger(__name__)

# `%(category)s` は CategoryFormatter が埋める。素の logging.Formatter へ
# この書式を渡すと KeyError になるので、必ず install_* 越しに使うこと。
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(category)s] %(name)s: %(message)s"

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


# ── ログの分類（イベントビューアーで言う「ソース」）────────────────

# ロガー名からカテゴリを引く表。**接頭辞は素の文字列一致で、長いものが勝つ。**
#
# 分類を各ファイルの手打ち接頭辞（`logger.info("[tts] ...")`）に頼ると、
# 必ず揺れる。実際この時点で `[SECURITY]` と `[security]`、`[TTS]` と
# `[tts_service]`、`[BOT]` と `[BOT_SETUP]` が混在していた。全ファイルが
# `getLogger(__name__)` を使っているので、**モジュール名から引けば、
# 呼び出し側は1行も書かなくてよい**（＝次に足すモジュールで書き忘れない）。
#
# 素の startswith にしてあるのは、このリポジトリのモジュール名が
# `djaudio_service` / `djaudio_cache` のように接頭辞で系列を作っているため。
# ドット境界で照合すると `services.djaudio` が1つも当たらず、5モジュールを
# 個別に並べることになる。代わりに `services.djaudio_cdn` のような
# 「系列の中の例外」は、長い方が勝つ規則で拾う。
CATEGORY_RULES: tuple[tuple[str, str], ...] = (
    # 音声
    ("services.voice_session", "voice"),
    ("events.voice", "voice"),
    ("services.tts", "tts"),
    ("commands.tts_commands", "tts"),
    ("services.djaudio", "djaudio"),
    ("commands.djaudio_commands", "djaudio"),
    # 保護・監視。誤検知を追うときはこの1カテゴリだけ見れば済むようにまとめる。
    ("services.security_service", "security"),
    ("services.spam_detection", "security"),
    ("services.raid_detection", "security"),
    ("services.url_safety", "security"),
    ("services.virustotal_service", "security"),
    ("services.content_moderation", "security"),
    # 通知・定期処理
    ("services.earthquake_service", "earthquake"),
    ("services.news_service", "news"),
    ("services.welcome_service", "welcome"),
    ("services.sticky_service", "sticky"),
    ("services.reaction_role_service", "reactionrole"),
    ("services.metal_service", "metal"),
    ("commands.metal_commands", "metal"),
    ("webapp.forecast", "metal"),
    ("services.chatgpt_service", "ai"),
    ("services.groq_client", "ai"),
    # 状態
    ("services.settings_store", "settings"),
    ("services.user_state", "userstate"),
    ("events.user_state_sync", "userstate"),
    ("services.guild_retention", "userstate"),
    ("services.logging_service", "auditlog"),
    ("commands.logging_commands", "auditlog"),
    # Bot の入口
    ("main", "bot"),
    ("bot_setup", "bot"),
    ("events", "bot"),
    ("commands", "command"),
    ("discord", "discord"),
    # HTTP を話すもの
    ("webapp_admin.api.dev", "dev"),
    ("services.dev_signals", "dev"),
    ("services.dev_test_notify", "dev"),
    ("webapp_admin.metrics", "metrics"),
    ("webapp_admin.prometheus_view", "metrics"),
    ("services.metrics_reporter", "metrics"),
    ("services.metrics_registry", "metrics"),
    ("webapp_admin", "admin"),
    ("cdn_main", "cdn"),
    ("services.djaudio_cdn", "cdn"),
    ("webapp", "web"),
    ("web_main", "web"),
    ("admin_main", "admin"),
    ("uvicorn", "http"),
    ("aiohttp", "http"),
    ("httpx", "http"),
    ("httpcore", "http"),
    ("slowapi", "http"),
    ("starlette", "http"),
    ("fastapi", "http"),
    ("services.http_client", "http"),
    # 土台
    ("config", "system"),
    ("envutil", "system"),
    ("services.log_setup", "system"),
    # イベントループの停止だけは独立したカテゴリにする。他と混ぜると、
    # いちばん探したいときに system の中から拾い出すことになる。
    ("services.loop_watchdog", "stall"),
    ("services.shared_cache", "system"),
    ("services.ttl_cache", "system"),
    ("services.discord_utils", "discord"),
    ("alembic", "system"),
    ("sqlalchemy", "system"),
    ("asyncio", "system"),
    ("apscheduler", "system"),
    ("watchfiles", "system"),
    ("redis", "system"),
    ("PIL", "system"),
    # `logging.info(...)` を直に呼んだ行。root ロガーなので name は "root" になる。
    # 素通しにすると起動直後の数行だけが分類外に落ちて、目立つ場所で表が
    # 効いていないように見える。
    ("root", "system"),
    ("yt_dlp", "djaudio"),
    ("mutagen", "djaudio"),
)

# どの規則にも当たらなかったロガーの行き先。
#
# 機械的な導出（末尾の `_service` を落とす等）へ倒す手もあるが、そうすると
# **分類し忘れたモジュールが「それらしいカテゴリ」を名乗って紛れ込む。**
# 当たらないものは当たらないと分かる形にして、テスト側で拾う
# （tests の LogCategoryTests がリポジトリ全体を走査している）。
DEFAULT_CATEGORY = "other"

# 長い接頭辞から順に並べ替えたもの。表の記載順に依存させないため、ここで1回だけ畳む。
_SORTED_CATEGORY_RULES: tuple[tuple[str, str], ...] = tuple(
    sorted(CATEGORY_RULES, key=lambda rule: len(rule[0]), reverse=True)
)


@lru_cache(maxsize=1024)
def category_for(logger_name: str) -> str:
    """ロガー名からカテゴリを引く。当たらなければ DEFAULT_CATEGORY。

    ログ1行ごとに呼ばれるので lru_cache を掛けている。ロガー名は
    モジュール名の集合＝有限（このリポジトリでは 66 個）なので、
    キャッシュが際限なく育つことはない。
    """
    for prefix, category in _SORTED_CATEGORY_RULES:
        if logger_name.startswith(prefix):
            return category
    return DEFAULT_CATEGORY


class CategoryFormatter(logging.Formatter):
    """`%(category)s` を埋めてから整形する、テキストログ用の整形器。

    カテゴリを Filter で付けなかったのは、**Filter がハンドラの持ち物で、
    親ロガーへ伝播した記録には掛からない**ため。root へ付けても、
    `getLogger("services.foo")` から上がってきた記録は root のフィルタを
    通らずに root のハンドラへ届く。つまり `%(category)s` を含む書式は
    KeyError で落ちる。整形器側で埋めれば、この書式を使うハンドラでは
    必ず値が入っている。
    """

    def format(self, record: logging.LogRecord) -> str:
        """record にカテゴリを載せてから、通常どおり整形する。"""
        record.category = category_for(record.name)
        return super().format(record)


# JSON へ写さない LogRecord の属性。ここに無いものは「呼び出し側が extra= で
# 足した項目」とみなして payload へ入れる（guild_id など）。
_STANDARD_RECORD_KEYS = frozenset(
    {
        "args",
        "asctime",
        "category",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
        "message",
    }
)

# extra で足した値のうち、1件あたりに許す文字数。長い本文をそのまま入れると
# 1行が肥大して、管理画面が末尾N行を読むときの費用が跳ね上がる。
_EXTRA_VALUE_MAX = 512


class JsonlFormatter(logging.Formatter):
    """1行1件の JSON（JSON Lines）へ整形する。管理画面が絞り込むための形。

    テキストログと別に持つ理由は、**テキストを正規表現で割る方式が、本文に
    改行が入った瞬間に崩れる**から。例外のスタックトレースは必ず改行を含むので、
    「レベルで色を分ける」程度でも既に破綻していた（管理画面は直前の行の色を
    引き継ぐ小細工でごまかしている）。カテゴリで絞る・期間で切る・本文を
    検索する、のどれもが構造を要求するので、最初から構造で書き出す。

    人が `tail -f` する先はテキストログのまま残す。片方だけにすると、
    **障害のときに端末から素早く読む手段が無くなる。**
    """

    def format(self, record: logging.LogRecord) -> str:
        """1件を JSON 文字列にする。"""
        payload: dict[str, Any] = {
            # ローカル時刻＋オフセット付き。UTC 固定にすると、運用者が
            # ログの時刻とチャットの時刻を頭の中で足し引きすることになる。
            "time": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "category": category_for(record.name),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        elif record.exc_text:
            payload["exc"] = record.exc_text
        payload.update(_extra_fields(record))
        # ensure_ascii=False は日本語をそのまま出すため。改行はここで \n へ
        # 逃がされるので、1件が必ず1行に収まる（JSON Lines の前提）。
        return json.dumps(payload, ensure_ascii=False)


def _extra_fields(record: logging.LogRecord) -> dict[str, Any]:
    """`extra=` で足された、JSON に載せられる値だけを取り出す。

    載せる型を絞っているのは、**任意のオブジェクトを json.dumps へ渡すと
    TypeError でログ自体が消える**ため。ログの都合で本体を止めないという
    gzip_rotator と同じ方針で、載せられないものは黙って捨てる。
    """
    extras: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _STANDARD_RECORD_KEYS or key.startswith("_"):
            continue
        if isinstance(value, str):
            extras[key] = value[:_EXTRA_VALUE_MAX]
        elif isinstance(value, (int, float, bool)) or value is None:
            extras[key] = value
    return extras


def _install_rotating_handler(
    log_dir: Path,
    filename: str,
    formatter: logging.Formatter,
    level: int,
) -> Path:
    """root へ、日付で回すファイルハンドラを1つ足す。既にあれば足さない。

    install_file_logging（テキスト）と install_structured_logging（JSONL）の
    共通部分。回し方・畳み方・保管日数を1箇所に置いておかないと、**片方だけ
    掃除が効かない**という、ディスクが埋まるまで気づけない壊れ方をする。
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
    handler.setFormatter(formatter)
    handler.setLevel(level)
    root.addHandler(handler)
    return path


def install_file_logging(log_dir: Path, filename: str, *, level: int = logging.INFO) -> Path:
    """root ロガーへ、日付で回すテキストのファイルハンドラを1つ足す。

    同じファイルへのハンドラが既にあれば足さない（uvicorn の reload や
    テストでの再 import で二重に書き込まれるのを防ぐ）。戻り値は書き込む
    ファイルのパスで、呼び出し側がログに出せるようにしてある。
    """
    return _install_rotating_handler(log_dir, filename, CategoryFormatter(LOG_FORMAT), level)


def install_structured_logging(log_dir: Path, filename: str, *, level: int = logging.INFO) -> Path:
    """root ロガーへ、日付で回す JSONL のファイルハンドラを1つ足す。

    テキスト版と**両方**設置する前提。片方に寄せない理由は JsonlFormatter の
    docstring に書いた（端末から読む手段と、画面から絞る手段の両方が要る）。

    保管日数はテキスト版と同じ LOG_RETENTION_DAYS を見る。日数を別々にすると、
    「テキストには残っているのに JSON には無い日」ができて、画面と端末で
    見える範囲が食い違う。
    """
    return _install_rotating_handler(log_dir, filename, JsonlFormatter(), level)


def install_console_logging(*, level: int = logging.INFO) -> None:
    """標準エラーへの出力を、カテゴリ付きの書式で設置する。

    `logging.basicConfig(format=LOG_FORMAT)` を置き換えるためのもの。
    basicConfig は素の logging.Formatter を作るので、`%(category)s` を含む
    LOG_FORMAT を渡すと **1行目のログで KeyError になり、そのプロセスの
    コンソール出力が丸ごと死ぬ**（logging は整形の失敗を握りつぶして
    標準エラーへ書くだけなので、例外にもならず静かに壊れる）。

    既に同じ整形器のハンドラが root にあれば足さない。
    """
    root = logging.getLogger()
    for existing in root.handlers:
        if isinstance(existing, logging.StreamHandler) and isinstance(existing.formatter, CategoryFormatter):
            return
    handler = logging.StreamHandler()
    handler.setFormatter(CategoryFormatter(LOG_FORMAT))
    root.addHandler(handler)
    root.setLevel(level)


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
