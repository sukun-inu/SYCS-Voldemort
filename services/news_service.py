import hashlib
import html
import logging
import re
import time
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import aiohttp
import discord
from discord.ext.commands import Bot

from config import BOT_ICON_URL, JST as _JST
from services.settings_store import (
    get_all_guild_ids,
    get_news_feeds,
    update_news_feed_state,
)

logger = logging.getLogger(__name__)

_RSS_BASE = "https://news.google.com/rss/search?q={query}&hl=ja&gl=JP&ceid=JP:ja"
_HEADERS  = {"User-Agent": "Mozilla/5.0 (compatible; DiscordBot/1.0)"}


def _url_hash(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def _strip_html(raw: str, max_len: int = 300) -> str:
    """HTML タグを除去してプレーンテキストを返す。"""
    text = html.unescape(raw or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


def _format_pub_date(raw: str) -> str:
    """RFC 822 日付文字列 → 'YYYY年M月D日 H:MM' (JST)。失敗時はそのまま返す。"""
    try:
        dt = parsedate_to_datetime(raw).astimezone(_JST)
        return f"{dt.year}年{dt.month}月{dt.day}日 {dt.hour}:{dt.minute:02d}"
    except Exception:
        return raw


async def _fetch_articles(session: aiohttp.ClientSession, query: str) -> list[dict]:
    url = _RSS_BASE.format(query=quote(query))
    try:
        async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                logger.warning("[news_service] RSS fetch status=%s query=%s", resp.status, query)
                return []
            text = await resp.text()
    except Exception as e:
        logger.exception("[news_service] RSS fetch error query=%s: %s", query, e)
        return []

    articles: list[dict] = []
    try:
        root    = ET.fromstring(text)
        channel = root.find("channel")
        if channel is None:
            return []
        for item in channel.findall("item"):
            title_el = item.find("title")
            link_el  = item.find("link")
            if title_el is None or link_el is None:
                continue

            pub_el    = item.find("pubDate")
            desc_el   = item.find("description")
            source_el = item.find("source")

            # タイトルに " - 配信元" が含まれることがあるため分割して保持
            full_title = (title_el.text or "").strip()
            if " - " in full_title:
                article_title, source_from_title = full_title.rsplit(" - ", 1)
            else:
                article_title, source_from_title = full_title, ""

            source = (source_el.text or "").strip() if source_el is not None else source_from_title

            desc_raw  = desc_el.text if desc_el is not None else ""
            desc_text = _strip_html(desc_raw or "")
            # タイトルと重複する場合は除去
            if desc_text.lower().startswith(article_title.lower()[:30]):
                desc_text = ""

            articles.append({
                "title":   article_title,
                "link":    (link_el.text or "").strip(),
                "pubDate": (pub_el.text or "") if pub_el is not None else "",
                "desc":    desc_text,
                "source":  source,
            })
    except ET.ParseError as e:
        logger.exception("[news_service] RSS parse error: %s", e)

    return articles


async def run_news_feeds(bot: Bot) -> None:
    now = time.time()
    async with aiohttp.ClientSession() as session:
        for guild_id in get_all_guild_ids():
            feeds = get_news_feeds(guild_id)
            for feed_id, feed in feeds.items():
                interval_sec = int(feed.get("interval", 60)) * 60
                if now - float(feed.get("last_run", 0)) < interval_sec:
                    continue

                query:      str       = feed.get("query", "")
                channel_id: int       = int(feed.get("channel_id", 0))
                seen:       list[str] = list(feed.get("seen_hashes", []))

                if not query or not channel_id:
                    continue

                guild = bot.get_guild(guild_id)
                if guild is None:
                    continue
                channel = guild.get_channel(channel_id)
                if not isinstance(channel, discord.TextChannel):
                    continue

                articles    = await _fetch_articles(session, query)
                new_articles = [a for a in articles if _url_hash(a["link"]) not in seen]

                for article in reversed(new_articles[:5]):
                    h = _url_hash(article["link"])
                    try:
                        embed = discord.Embed(
                            title=article["title"],
                            url=article["link"],
                            color=discord.Color.blue(),
                        )
                        if article["desc"]:
                            embed.description = article["desc"]
                        if article["source"]:
                            embed.set_author(name=article["source"])
                        if article["pubDate"]:
                            embed.set_footer(text=_format_pub_date(article["pubDate"]), icon_url=BOT_ICON_URL)
                        await channel.send(embed=embed)
                        seen.append(h)
                    except Exception as e:
                        logger.exception("[news_service] send error feed=%s: %s", feed_id, e)

                update_news_feed_state(guild_id, feed_id, now, seen)
