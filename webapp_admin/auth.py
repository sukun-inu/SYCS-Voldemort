import asyncio
import logging
import os
import time
from typing import Optional, cast
from urllib.parse import urlencode

import aiohttp

from envutil import env_int, env_raw
from services.ttl_cache import TTLCache

logger = logging.getLogger(__name__)

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "http://localhost:5001/admin/callback")
# config.py の DISCORD_BOT_TOKEN(env_raw、前後空白を除去)と読み方を揃える。
# ここだけ素の os.environ.get のままだと、同じトークンでも前後に空白が付いた
# ときにこちらだけ弾かれる/一致しないという取りこぼしが起きる。
DISCORD_BOT_TOKEN = env_raw("DISCORD_BOT_TOKEN") or ""
DISCORD_OAUTH_PROMPT = os.environ.get("DISCORD_OAUTH_PROMPT", "").strip().lower()
if DISCORD_OAUTH_PROMPT and DISCORD_OAUTH_PROMPT not in {"none", "consent"}:
    logger.warning("DISCORD_OAUTH_PROMPT=%s は無効なため無視します。", DISCORD_OAUTH_PROMPT)
    DISCORD_OAUTH_PROMPT = ""

_API = "https://discord.com/api/v10"
_SCOPES = "identify guilds"
_ADMINISTRATOR_BIT = 0x8

_TIMEOUT = aiohttp.ClientTimeout(total=10)


def get_oauth_url(state: str) -> str:
    """Discord の認可画面へ飛ばす URL を組み立てる。

    `state` はここでは検証しない。呼び出し側（views/auth_views.py）がセッションへ
    保存し、コールバック側で一致を確認する CSRF 対策なので、渡す値の生成・保存
    まで含めて呼び出し側の責務。
    """
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
    }
    if DISCORD_OAUTH_PROMPT in {"none", "consent"}:
        params["prompt"] = DISCORD_OAUTH_PROMPT
    return f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"


async def exchange_code(code: str) -> Optional[dict]:
    """OAuth の認可コードをアクセストークンへ交換する。失敗は例外にせず None。

    呼び出し側（コールバックハンドラ）はここで例外を捕まえる作りにしておらず、
    None を「認証失敗」として案内画面へ落とす前提。ここで例外を投げる実装に
    変えると、その分岐が素通りしてユーザーに 500 が出る。
    """
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.post(
                f"{_API}/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": DISCORD_REDIRECT_URI,
                },
            ) as resp:
                resp.raise_for_status()
                # aiohttp の json() は Any を返す。Discord のレスポンスが常に
                # オブジェクトである保証を型に落とし込むだけで、中身は見ていない。
                return cast(Optional[dict], await resp.json())
    except Exception:
        return None


async def get_user_info(access_token: str) -> Optional[dict]:
    """ログインしてきた本人の Discord アカウント情報（id・username 等）を取る。

    exchange_code と同じく、失敗は None で返して呼び出し側にログイン失敗
    画面を出させる（例外を伝播させない）。
    """
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/users/@me",
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                resp.raise_for_status()
                # aiohttp の json() は Any を返す。Discord のレスポンスが常に
                # オブジェクトである保証を型に落とし込むだけで、中身は見ていない。
                return cast(Optional[dict], await resp.json())
    except Exception:
        return None


async def get_user_guilds(access_token: str) -> list[dict]:
    """本人が所属する全ギルド（Bot の参加有無・権限は問わない）を取る。

    この結果だけでは「管理できるギルド」は決まらない。get_admin_guilds() が
    permissions ビットと _get_bot_guild_ids() の両方で絞り込むための材料。
    失敗時は空リスト（呼び出し側は「管理できるギルドが無い」と区別できない
    が、ログイン導線としては同じ「サーバーがありません」表示で扱って問題ない）。
    """
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/users/@me/guilds",
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                resp.raise_for_status()
                # aiohttp の json() は Any を返す。Discord のレスポンスが常に
                # 配列である保証を型に落とし込むだけで、中身は見ていない。
                return cast("list[dict]", await resp.json())
    except Exception:
        return []


async def _get_bot_guild_ids() -> set[int]:
    """Bot が実際に参加しているギルドIDの集合。

    「本人が管理者権限を持つギルド」だけでは不十分で、Bot がそのギルドに
    いなければ管理画面から操作できるものが無い。get_admin_guilds() はこの
    集合との積を取って一覧を絞る。トークン未設定・取得失敗時は空集合を返し、
    その場合 get_admin_guilds() は誰にとっても「管理できるギルドが無い」に
    なる（フェイルクローズ。取得できないからといって全ギルドを許可はしない）。
    """
    if not DISCORD_BOT_TOKEN:
        logger.warning("DISCORD_BOT_TOKEN が未設定のため Bot ギルド一覧を取得できません。")
        return set()
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/users/@me/guilds",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            ) as resp:
                resp.raise_for_status()
                ids = {int(g["id"]) for g in await resp.json()}
                if not ids:
                    logger.warning("Bot がどのサーバーにも参加していません。")
                return ids
    except Exception as e:
        logger.warning("Bot ギルド一覧取得失敗: %s", e)
        return set()


_guild_count_cache: tuple[int, float] | None = None
_guild_count_lock = asyncio.Lock()
_GUILD_COUNT_TTL = 300


async def get_bot_guild_count() -> int:
    """Bot が参加しているサーバー数を返す（5分キャッシュ）。"""
    global _guild_count_cache
    now = time.time()
    if _guild_count_cache and now - _guild_count_cache[1] < _GUILD_COUNT_TTL:
        return _guild_count_cache[0]

    async with _guild_count_lock:
        now = time.time()
        if _guild_count_cache and now - _guild_count_cache[1] < _GUILD_COUNT_TTL:
            return _guild_count_cache[0]

        count = 0
        if DISCORD_BOT_TOKEN:
            try:
                async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                    async with session.get(
                        f"{_API}/users/@me/guilds?limit=200",
                        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                    ) as resp:
                        resp.raise_for_status()
                        count = len(await resp.json())
            except Exception as e:
                logger.warning("get_bot_guild_count: Discord API 失敗、フォールバックを使用: %s", e)

        if count == 0:
            try:
                from services.settings_store import get_all_guild_ids

                count = len(get_all_guild_ids())
            except Exception as e:
                logger.warning("get_bot_guild_count: settings_store フォールバックも失敗: %s", e)

        _guild_count_cache = (count, now)
        return count


async def get_admin_guilds(access_token: str) -> list[dict]:
    """ユーザーが administrator 権限を持ち、Botが参加しているギルド一覧。"""
    user_guilds, bot_ids = await asyncio.gather(
        get_user_guilds(access_token),
        _get_bot_guild_ids(),
    )
    result: list[dict[str, str | None]] = []
    for g in user_guilds:
        try:
            guild_id = int(g["id"])
            if (int(g.get("permissions", 0)) & _ADMINISTRATOR_BIT) and guild_id in bot_ids:
                icon = g.get("icon")
                result.append(
                    {
                        "id": str(guild_id),
                        "name": str(g.get("name") or "Unknown"),
                        "icon": icon if isinstance(icon, str) else None,
                    }
                )
        except (TypeError, ValueError):
            continue
    return result


# チャンネル一覧のキャッシュ。
#
# テキストとボイスは同じ /guilds/{id}/channels から取れるのに、以前は種類ごとに
# 別々のリクエストを投げていた。そのうえキャッシュが無かったため、5秒ごとに
# 更新する画面（VC録音パネル）を開いているだけで毎5秒2本の呼び出しが飛び、
# Discord から 429 を返され続けた。1回だけ取って共有し、短時間は使い回す。
_guild_channels_cache: dict[int, tuple[list[dict], float]] = {}
_guild_channels_locks: dict[int, asyncio.Lock] = {}
# 429 を食らったギルドは、この時刻まで取りに行かない
_guild_channels_cooldown: dict[int, float] = {}
_GUILD_CHANNELS_TTL = 60.0
_GUILD_CHANNELS_COOLDOWN_DEFAULT = 30.0
_GUILD_CHANNELS_COOLDOWN_MAX = 300.0


def _retry_after(resp) -> float:
    """429 応答の Retry-After を秒数として読む。無い/壊れていれば既定の待ち時間。

    Discord が値を返さない・数値でない場合に例外を伝播させると 429 処理その
    ものが失敗してクールダウンに入れず、レート制限を食らったまま叩き続ける
    ことになる。既定値へ倒して必ずクールダウンさせる。
    """
    try:
        return max(0.0, float(resp.headers.get("Retry-After", "")))
    except (TypeError, ValueError):
        return _GUILD_CHANNELS_COOLDOWN_DEFAULT


async def _fetch_guild_channels(guild_id: int) -> list[dict]:
    """そのギルドの全チャンネルを1回だけ取り、TTL のあいだ使い回す。

    取得に失敗しても、古い内容が残っていればそれを返す。空を返すと画面の
    ドロップダウンが消えて設定できなくなるので、鮮度より「出せること」を優先する。
    """
    now = time.time()
    cached = _guild_channels_cache.get(guild_id)
    if cached and now - cached[1] < _GUILD_CHANNELS_TTL:
        return cached[0]

    lock = _guild_channels_locks.setdefault(guild_id, asyncio.Lock())
    async with lock:
        # 待っているあいだに他の呼び出しが取ってきているかもしれない
        now = time.time()
        cached = _guild_channels_cache.get(guild_id)
        if cached and now - cached[1] < _GUILD_CHANNELS_TTL:
            return cached[0]

        # 429 直後は叩かない（叩くほど解除が遠のく）
        until = _guild_channels_cooldown.get(guild_id, 0.0)
        if now < until:
            return cached[0] if cached else []

        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                async with session.get(
                    f"{_API}/guilds/{guild_id}/channels",
                    headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                ) as resp:
                    if resp.status == 429:
                        wait = min(_retry_after(resp), _GUILD_CHANNELS_COOLDOWN_MAX)
                        _guild_channels_cooldown[guild_id] = time.time() + wait
                        logger.warning(
                            "チャンネル一覧がレート制限されました guild_id=%s: %.0f秒待ちます",
                            guild_id,
                            wait,
                        )
                        return cached[0] if cached else []
                    resp.raise_for_status()
                    data = await resp.json()
        except Exception as exc:
            # 黙って空を返すと、画面には「一覧を取得できませんでした」とだけ出て
            # 原因が追えない。理由を必ずログへ残す。
            from webapp_admin.api.dev import describe_exception

            logger.warning(
                "チャンネル一覧の取得に失敗 guild_id=%s: %s",
                guild_id,
                describe_exception(exc, timeout=_TIMEOUT.total),
            )
            return cached[0] if cached else []

        channels = data if isinstance(data, list) else []
        _guild_channels_cache[guild_id] = (channels, time.time())
        _guild_channels_cooldown.pop(guild_id, None)
        return channels


def _of_type(channels: list[dict], channel_type: int) -> list[dict]:
    """種類でフィルタし、Discord のチャンネル一覧に見えている並び順（position）に揃える。

    API はテキスト/ボイスを分けずに1本の配列で返すため、種類ごとに切り出す
    のはここで行う。position で並べないと、Discord クライアントでの表示順と
    管理画面のプルダウンの順番が食い違う。
    """
    return sorted(
        [c for c in channels if c.get("type") == channel_type],
        key=lambda c: c.get("position", 0),
    )


async def get_guild_channels(guild_id: int) -> list[dict]:
    """テキストチャンネル (type=0) のみ返す。"""
    return _of_type(await _fetch_guild_channels(guild_id), 0)


async def get_guild_voice_channels(guild_id: int) -> list[dict]:
    """ボイスチャンネル (type=2) のみ返す。"""
    return _of_type(await _fetch_guild_channels(guild_id), 2)


_USER_INFO_CACHE_TTL = 600
# 利用者1人ごとに鍵が増えるので、件数にも上限を置く（従来は追い出しが無かった）
_user_info_cache: TTLCache[int, Optional[dict]] = TTLCache(
    ttl=_USER_INFO_CACHE_TTL,
    max_entries=2000,
)
_user_info_cache_lock = asyncio.Lock()
_USER_INFO_MISS = object()  # 「取得できなかった」も覚えて叩き直しを防ぐ


async def get_discord_user(user_id: int) -> Optional[dict]:
    """DiscordユーザーIDから基本情報（表示名・アバター等）を取得する（10分キャッシュ）。

    見つからない/取得失敗時は None。設定ページで「生のユーザーID」を表示せず
    名前解決して見せるために使う（チャンネル/ロールと同様の扱いに揃える）。
    """
    cached = _user_info_cache.get(user_id)
    if cached is not None:
        return None if cached is _USER_INFO_MISS else cached

    if not DISCORD_BOT_TOKEN:
        return None

    async with _user_info_cache_lock:
        cached = _user_info_cache.get(user_id)
        if cached is not None:
            return None if cached is _USER_INFO_MISS else cached

        data: Optional[dict] = None
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                async with session.get(
                    f"{_API}/users/{user_id}",
                    headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
        except Exception as e:
            logger.warning("get_discord_user(%s) 失敗: %s", user_id, e)

        # 取得できなかったことも覚える。None をそのまま入れると get() の
        # 「見つからない」と区別が付かず、失敗のたびに叩き直してしまう。
        # _USER_INFO_MISS は object() の番兵で、キャッシュの値の型そのものでは
        # ない。is 比較でしか使わないので、キャッシュへ入れる際は型だけ合わせる。
        miss = cast(Optional[dict], _USER_INFO_MISS)
        _user_info_cache.set(user_id, data if data is not None else miss)
        return data


async def get_discord_users(user_ids: list[int]) -> dict[int, Optional[dict]]:
    """複数ユーザーIDをまとめて解決する（並列取得、内部はキャッシュ経由）。"""
    unique_ids = list(dict.fromkeys(user_ids))
    if not unique_ids:
        return {}
    results = await asyncio.gather(*[get_discord_user(uid) for uid in unique_ids])
    return dict(zip(unique_ids, results))


async def get_guild_roles(guild_id: int) -> list[dict]:
    """管理されていないロール（@everyone 除く）を返す。"""
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/guilds/{guild_id}/roles",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            ) as resp:
                resp.raise_for_status()
                return sorted(
                    [r for r in await resp.json() if r.get("name") != "@everyone"],
                    key=lambda r: -r.get("position", 0),
                )
    except Exception as exc:
        # 黙って空を返すと、画面には「一覧を取得できませんでした」とだけ出て
        # 原因が追えない。理由を必ずログへ残す。
        from webapp_admin.api.dev import describe_exception

        logger.warning(
            "ロール一覧の取得に失敗 guild_id=%s: %s",
            guild_id,
            describe_exception(exc, timeout=_TIMEOUT.total),
        )
        return []


# 管理権限の再確認をどれくらい信用し続けるか（秒）。
ADMIN_GUILDS_MAX_AGE_SECONDS = env_int("ADMIN_GUILDS_MAX_AGE_SECONDS", 300, minimum=60)


async def user_still_admin(guild_id: int, user_id: int) -> bool | None:
    """Bot トークンで「その利用者が今もそのギルドの管理者か」を確かめる。

    管理権限の一覧はログイン時に取得してセッションへ焼き込まれるため、Discord 側で
    権限を外されてもセッションが切れるまで管理できてしまう。ギルド選択のたびに
    ここで見直す。

    利用者の OAuth トークンはセッションに保存しない（SessionMiddleware は署名する
    だけで暗号化しないため）。代わりに Bot トークンでメンバーとロールを引き、
    権限ビットを自分で組み立てる。

    戻り値: True=管理者 / False=管理者ではない / None=確認できなかった
    （Discord 側の障害でログイン中の利用者を締め出さないよう、判断を保留する）
    """
    if not DISCORD_BOT_TOKEN:
        return None

    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(f"{_API}/guilds/{guild_id}", headers=headers) as resp:
                if resp.status == 404:
                    return False  # Bot が抜けている / ギルドが消えた
                resp.raise_for_status()
                guild = await resp.json()

            async with session.get(f"{_API}/guilds/{guild_id}/members/{user_id}", headers=headers) as resp:
                if resp.status == 404:
                    return False  # もうそのサーバーにいない
                resp.raise_for_status()
                member = await resp.json()
    except Exception as e:
        logger.warning("user_still_admin: 確認できませんでした guild=%s: %s", guild_id, e)
        return None

    if str(guild.get("owner_id")) == str(user_id):
        return True

    held = {str(r) for r in member.get("roles", [])}
    permissions = 0
    for role in guild.get("roles", []):
        if str(role.get("id")) in held or str(role.get("id")) == str(guild_id):  # @everyone
            try:
                permissions |= int(role.get("permissions", 0))
            except (TypeError, ValueError):
                continue
    return bool(permissions & _ADMINISTRATOR_BIT)
