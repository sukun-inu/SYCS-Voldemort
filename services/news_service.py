import hashlib
import html
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlparse

import aiohttp
import discord
from groq import AsyncGroq
from discord.ext.commands import Bot

from config import BOT_ICON_URL, GROQ_API_KEY, JST as _JST
from services.groq_client import create_chat_completion, get_groq_client
from services.settings_store import (
    get_all_guild_ids,
    get_news_feeds,
    update_news_feed_state,
)

logger = logging.getLogger(__name__)

_RSS_BASE = "https://news.google.com/rss/search?q={query}&hl=ja&gl=JP&ceid=JP:ja"
_HEADERS  = {"User-Agent": "Mozilla/5.0 (compatible; DiscordBot/1.0)"}
# 記事本文へのサムネイル画像は取れない。Google News RSS の <link> は
# 実際の配信元へは直接飛ばず（HTTP のリダイレクトではなく、Google 側の
# JS で解決する中間ページ止まり）、5件のリンクを実際に fetch して確認した
# ところ、どれも news.google.com に留まり og:image も無かった。
# 代わりに <source url="..."> に入っている配信元ドメインから favicon を
# 取り、「文字だけ」を避ける（追加のリクエストが要らず、信頼性が高い）。
_FAVICON_SERVICE = "https://www.google.com/s2/favicons?sz=128&domain={domain}"
_NEWS_SUMMARY_MODEL = os.getenv("NEWS_SUMMARY_MODEL", "openai/gpt-oss-120b")
_NEWS_SUMMARY_MAX_CHARS = 400
_NEWS_SUMMARY_CACHE_TTL_SEC = 6 * 3600
_GROQ_BUCKET = "news_summary"

_summary_cache: dict[str, tuple[str, float]] = {}


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


def _get_groq_client() -> AsyncGroq | None:
    if not GROQ_API_KEY:
        return None
    return get_groq_client(timeout=20.0, bucket=_GROQ_BUCKET)


def _normalize_summary_text(text: str, max_len: int = _NEWS_SUMMARY_MAX_CHARS) -> str:
    clean = str(text or "").strip()
    clean = re.sub(r"[ \t]+", " ", clean)
    clean = re.sub(r"\n{3,}", "\n\n", clean)
    clean = re.sub(r"^要約[:：]\s*", "", clean)
    if len(clean) <= max_len:
        return clean
    return clean[:max_len - 1].rstrip() + "…"


async def _summarize_article(article: dict) -> str:
    """Groq で 400文字以内要約を生成。失敗時は空文字。"""
    body_parts = [
        f"タイトル: {article.get('title', '')}".strip(),
        f"配信元: {article.get('source', '')}".strip(),
        f"本文抜粋: {article.get('desc', '')}".strip(),
        f"URL: {article.get('link', '')}".strip(),
    ]
    source_text = "\n".join(p for p in body_parts if p and not p.endswith(":"))
    if not source_text:
        return ""

    cache_key = _url_hash(f"{article.get('link', '')}|{article.get('title', '')}|{article.get('desc', '')}")
    now = time.time()
    cached = _summary_cache.get(cache_key)
    if cached and now - cached[1] < _NEWS_SUMMARY_CACHE_TTL_SEC:
        return cached[0]

    client = _get_groq_client()
    if client is None:
        return ""

    try:
        response = await create_chat_completion(
            client,
            bucket=_GROQ_BUCKET,
            model=_NEWS_SUMMARY_MODEL,
            temperature=0.2,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "あなたはニュース要約アシスタントです。"
                        "事実のみを簡潔に日本語で要約してください。"
                        "推測・断定・誇張表現は避け、400文字以内で出力してください。"
                        "前置きや箇条書き記号は不要です。"
                    ),
                },
                {"role": "user", "content": source_text},
            ],
        )
        content = (response.choices[0].message.content or "").strip()
        summary = _normalize_summary_text(content)
        if summary:
            _summary_cache[cache_key] = (summary, now)
        return summary
    except Exception as e:
        logger.warning("[news_service] summarize failed url=%s: %s", article.get("link", ""), e)
        return ""


def _favicon_url(source_url: str) -> str | None:
    """配信元の favicon URL を作る。取れなければ None（Embed に何も足さない）。"""
    domain = urlparse(source_url or "").netloc
    if not domain:
        return None
    return _FAVICON_SERVICE.format(domain=quote(domain))


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
            # <source url="https://..."> に配信元サイトのドメインが入っている
            # （favicon を引くのに使う。記事本文へのリンクとは別物）。
            source_url = (source_el.get("url") or "").strip() if source_el is not None else ""

            desc_raw  = desc_el.text if desc_el is not None else ""
            desc_text = _strip_html(desc_raw or "")
            # タイトルと重複する場合は除去
            if desc_text.lower().startswith(article_title.lower()[:30]):
                desc_text = ""

            articles.append({
                "title":     article_title,
                "link":      (link_el.text or "").strip(),
                "pubDate":   (pub_el.text or "") if pub_el is not None else "",
                "desc":      desc_text,
                "source":    source,
                "sourceUrl": source_url,
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
                        summary = await _summarize_article(article)
                        embed = discord.Embed(
                            title=article["title"],
                            url=article["link"],
                            color=discord.Color.blue(),
                        )
                        if article["desc"]:
                            embed.description = article["desc"]
                        if summary:
                            embed.add_field(name="要約 (Groq)", value=summary, inline=False)
                        # 記事の写真は取れない（Google News の <link> は実際の配信元へ
                        # 直接飛ばず、素朴な追跡では og:image に届かない）。せめて
                        # 配信元の favicon を出し、文字だけの並びにしない。
                        favicon = _favicon_url(article.get("sourceUrl", ""))
                        if article["source"]:
                            embed.set_author(name=article["source"], icon_url=favicon)
                        if favicon:
                            embed.set_thumbnail(url=favicon)
                        if article["pubDate"]:
                            embed.set_footer(text=_format_pub_date(article["pubDate"]), icon_url=BOT_ICON_URL)
                        await channel.send(embed=embed)
                        seen.append(h)
                    except Exception as e:
                        logger.exception("[news_service] send error feed=%s: %s", feed_id, e)

                update_news_feed_state(guild_id, feed_id, now, seen)
