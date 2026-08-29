"""防災科研（NIED）強震モニタを毎秒見て、緊急地震速報を最短で流す。

■ なぜ増やすのか

いまの地震通知は P2PQuake の WebSocket 1本に依存している。あそこは気象庁の
発表を中継する経路で、内容は正確だが、経路が詰まれば何も出ない。災害速報は
「片方が黙ったら気づけない」が最悪なので、系統の違う入口をもう1つ持つ。

強震モニタは防災科研が自前の観測網から出しており、EEW を1秒ごとの JSON で
公開している。P2PQuake とは配信元も経路も別なので、同時に詰まる可能性が低い。

■ この経路をどう扱うか

強震モニタは HTTPS を持たない（実測で 443 は接続タイムアウト、80 のみ応答）。
経路上で書き換えられても検知できないので、ここから来た値は**速報値**として
扱い、画面にもそう出す。気象庁の発表（P2PQuake 経由）が届いたらそちらが正。

■ 参照した口（すべて実際に応答を確認）

    http://www.kmoni.bosai.go.jp/webservice/hypo/eew/{YYYYMMDDHHMMSS}.json
      → 200。EEW が無いときは result.message が「データがありません」
    http://www.kmoni.bosai.go.jp/data/map_img/RealTimeImg/jma_s/{YYYYMMDD}/
        {YYYYMMDDHHMMSS}.jma_s.gif
      → 200。352x400 の GIF。観測点の揺れが色で載る（こちらは別途）
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import aiohttp

logger = logging.getLogger(__name__)

_JST = timezone(timedelta(hours=9))
_EEW_URL = "http://www.kmoni.bosai.go.jp/webservice/hypo/eew/{stamp}.json"
_UA = "SYCS-Voldemort (Discord disaster alert bot)"

# 見に行く間隔。1秒より短くしても新しいファイルは出ない（公開が毎秒のため）。
POLL_SECONDS = 1.0
# 現在時刻から何秒戻った時刻を要求するか。
# 強震モニタは処理と配信に時間がかかるため、いまこの瞬間の時刻を投げても
# まだ無い。実測で1秒前は空振りが多く、2秒前で安定して取れる。
DELAY_SECONDS = 2.0
# 取得に失敗し続けたときの待ち。詰まっている相手を毎秒叩き続けない。
_BACKOFF_MAX = 30.0


@dataclass(frozen=True)
class KmoniEew:
    """強震モニタが返した緊急地震速報 1件。"""

    report_id: str
    report_num: int
    is_final: bool
    is_cancel: bool
    is_training: bool
    region_name: str
    magnitude: float | None
    depth_km: int | None
    intensity: str            # 予測される最大震度（"5-" のような表記）
    origin_time: str          # 発生時刻（YYYYMMDDHHMMSS）
    latitude: float | None
    longitude: float | None

    @property
    def key(self) -> tuple[str, int]:
        return (self.report_id, self.report_num)


def _as_float(value) -> float | None:
    try:
        text = str(value).strip().lstrip("N").lstrip("E")
        return float(text) if text else None
    except (TypeError, ValueError):
        return None


def _as_int(value) -> int | None:
    try:
        return int(str(value).strip().rstrip("km"))
    except (TypeError, ValueError):
        return None


def parse_eew(payload: dict) -> KmoniEew | None:
    """強震モニタの応答を1件の速報にする。EEW が無ければ None。

    「データがありません」は異常ではなく通常の状態（地震が起きていない）。
    ここでログを出すと毎秒流れるので黙って None を返す。
    """
    if not isinstance(payload, dict):
        return None
    result = payload.get("result") or {}
    if result.get("status") != "success":
        return None
    if not payload.get("report_id") or not payload.get("region_name"):
        return None

    return KmoniEew(
        report_id=str(payload.get("report_id", "")),
        report_num=_as_int(payload.get("report_num")) or 0,
        is_final=str(payload.get("is_final", "")).lower() in ("true", "1"),
        is_cancel=str(payload.get("is_cancel", "")).lower() in ("true", "1"),
        is_training=str(payload.get("is_training", "")).lower() in ("true", "1"),
        region_name=str(payload.get("region_name", "")),
        magnitude=_as_float(payload.get("magunitude")),   # 綴りは配信元のまま
        depth_km=_as_int(payload.get("depth")),
        intensity=str(payload.get("calcintensity", "")),
        origin_time=str(payload.get("origin_time", "")),
        latitude=_as_float(payload.get("latitude")),
        longitude=_as_float(payload.get("longitude")),
    )


def should_announce(current: KmoniEew, seen: dict[str, KmoniEew]) -> bool:
    """この報を流すか決める。

    続報は数秒おきに何度も出る。全部流すと1回の地震でチャンネルが埋まるので、
    「知らせる価値が増えたとき」だけにする。

      - 初報                      … 流す
      - 取消                      … 流す（誤報だったと伝えないと危ない）
      - 予測震度が上がった        … 流す（避難の判断が変わる）
      - 最終報                    … 流す（確定値として残す）
      - それ以外の続報            … 流さない

    訓練報は絶対に流さない。本物と区別が付かない形で出すと、次の本番で
    信じてもらえなくなる。
    """
    if current.is_training:
        return False

    previous = seen.get(current.report_id)
    if previous is None:
        return True
    if current.is_cancel and not previous.is_cancel:
        return True
    if _intensity_rank(current.intensity) > _intensity_rank(previous.intensity):
        return True
    if current.is_final and not previous.is_final:
        return True
    return False


# 予測震度の表記（"5-" など）を大小比較できる数にする。
_INTENSITY_ORDER = {
    "0": 0, "1": 10, "2": 20, "3": 30, "4": 40,
    "5-": 45, "5+": 50, "6-": 55, "6+": 60, "7": 70,
    "5弱": 45, "5強": 50, "6弱": 55, "6強": 60,
}


def _intensity_rank(text: str) -> int:
    return _INTENSITY_ORDER.get(str(text).strip(), -1)


def stamp_for(now: datetime | None = None, delay: float = DELAY_SECONDS) -> str:
    """要求する時刻。強震モニタは JST の秒単位で並んでいる。"""
    moment = (now or datetime.now(_JST)) - timedelta(seconds=delay)
    return moment.astimezone(_JST).strftime("%Y%m%d%H%M%S")


async def fetch_eew(session: aiohttp.ClientSession,
                    now: datetime | None = None) -> KmoniEew | None:
    """いまの緊急地震速報を1件取る。無ければ None。"""
    url = _EEW_URL.format(stamp=stamp_for(now))
    async with session.get(url, headers={"User-Agent": _UA},
                           timeout=aiohttp.ClientTimeout(total=3)) as response:
        if response.status != 200:
            raise aiohttp.ClientResponseError(
                response.request_info, response.history, status=response.status)
        # 配信側は text/plain で返すことがあるので、型を見ずに読む
        payload = await response.json(content_type=None)
    return parse_eew(payload)


# 予測震度の表記 → 既存の内部スケール（10〜70）。min_scale の判定に使う。
_TO_INTERNAL = {"1": 10, "2": 20, "3": 30, "4": 40, "5-": 45, "5+": 50,
                "6-": 55, "6+": 60, "7": 70,
                "5弱": 45, "5強": 50, "6弱": 55, "6強": 60}

# 気象庁が警報を出す目安（震度5弱以上）。ここを境に通知の種類を分ける。
_WARNING_FROM = 45


def internal_scale(text: str) -> int:
    return _TO_INTERNAL.get(str(text).strip(), -1)


def build_embed(eew: KmoniEew):
    """速報の Embed。出どころと確度を必ず添える。"""
    import discord

    from config import BOT_ICON_URL
    from services.earthquake_service import _SCALE_COLORS, _SCALE_DISPLAY

    scale = internal_scale(eew.intensity)
    if eew.is_cancel:
        title = "緊急地震速報 取消"
        colour = discord.Color.dark_grey()
        body = f"さきほどの{eew.region_name}の速報は取り消されました。"
    else:
        kind = "警報" if scale >= _WARNING_FROM else "予報"
        title = f"緊急地震速報（{kind}）"
        colour = _SCALE_COLORS.get(scale, discord.Color.orange())
        shown = _SCALE_DISPLAY.get(scale, eew.intensity or "不明")
        body = f"{eew.region_name}で地震。予測される最大震度は {shown}。"

    embed = discord.Embed(title=title, description=body, color=colour)
    if not eew.is_cancel:
        if eew.magnitude is not None:
            embed.add_field(name="規模", value=f"M{eew.magnitude:.1f}", inline=True)
        if eew.depth_km is not None:
            embed.add_field(name="深さ", value=f"{eew.depth_km}km", inline=True)
        embed.add_field(name="報", value=f"第{eew.report_num}報"
                        + ("（最終）" if eew.is_final else ""), inline=True)

    # 出どころを隠さない。強震モニタは HTTPS を持たず、値は速報値。
    # 気象庁の発表が届いたらそちらが正、ということまで書く。
    embed.set_footer(
        text="防災科研 強震モニタ（速報値）・気象庁の発表で更新されます",
        icon_url=BOT_ICON_URL or discord.utils.MISSING,
    )
    return embed


async def _announce(bot, eew: KmoniEew) -> int:
    from services.earthquake_service import _collect_targets, _dispatch

    scale = internal_scale(eew.intensity)
    notify_type = "eew_warning" if scale >= _WARNING_FROM else "eew_forecast"
    # 取消はどちらの購読者にも届けたい。強いほうの種別で拾う。
    if eew.is_cancel:
        notify_type = "eew_warning"

    targets = _collect_targets(bot, notify_type=notify_type, max_scale=scale)
    if not targets:
        return 0
    return await _dispatch(targets, tag="kmoni", embed=build_embed(eew))


async def run_kmoni_eew(bot) -> None:
    """強震モニタの緊急地震速報を毎秒見て、変化があったら流す。

    受信と送信を分ける。送信（Discord API）は数百ミリ秒かかることがあるので、
    ここで待つと次の秒の取得が遅れる。災害速報で1秒の遅れは許されないため、
    送信は投げっぱなしにして、ループは取得だけを続ける。
    """
    from services.earthquake_service import _spawn

    seen: dict[str, KmoniEew] = {}
    backoff = 0.0

    while True:
        try:
            # 接続を使い回す（毎秒 TCP を張り直すと、その分だけ遅れる）
            async with aiohttp.ClientSession() as session:
                logger.info("[kmoni] 強震モニタの監視を開始（%.0f秒ごと）", POLL_SECONDS)
                backoff = 0.0
                while True:
                    started = asyncio.get_running_loop().time()
                    try:
                        eew = await fetch_eew(session)
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        # 毎秒叩くので、1回の失敗は普通に起きる。黙って次へ。
                        logger.debug("[kmoni] 取得に失敗: %s", e)
                        eew = None

                    if eew is not None and should_announce(eew, seen):
                        logger.info("[kmoni] %s 第%d報 最大震度%s%s",
                                    eew.region_name, eew.report_num, eew.intensity,
                                    "（取消）" if eew.is_cancel else "")
                        _spawn(_announce(bot, eew))
                    if eew is not None:
                        seen[eew.report_id] = eew
                        if len(seen) > 64:            # 古い報は捨てる
                            seen.pop(next(iter(seen)))

                    # 取得にかかった分を差し引いて、間隔を一定に保つ
                    elapsed = asyncio.get_running_loop().time() - started
                    await asyncio.sleep(max(0.0, POLL_SECONDS - elapsed))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            backoff = min(_BACKOFF_MAX, (backoff or 1.0) * 2)
            logger.warning("[kmoni] 監視が落ちました。%.0f秒後に再開: %s", backoff, e)
            await asyncio.sleep(backoff)
