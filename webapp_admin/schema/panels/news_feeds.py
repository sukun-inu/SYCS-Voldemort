"""ニュースフィードパネル。"""

from __future__ import annotations

import uuid
from typing import Any

from services.settings_store import (
    add_news_feed,
    get_news_feeds,
    remove_news_feed,
    update_news_feed,
)
from webapp_admin.schema.types import Collection, Field, Panel, Section, Widget

MAX_FEEDS = 10


def _list(guild_id: int) -> list[dict[str, Any]]:
    feeds = get_news_feeds(guild_id)
    rows: list[dict[str, Any]] = []
    for feed_id, feed in feeds.items():
        if not isinstance(feed, dict):
            continue
        rows.append(
            {
                "id": str(feed_id),
                "channel_id": str(feed.get("channel_id") or ""),
                "query": feed.get("query", ""),
                "interval": int(feed.get("interval") or 60),
                "last_run": feed.get("last_run"),
            }
        )
    return rows


def _add(guild_id: int, data: dict[str, Any]) -> str:
    feed_id = uuid.uuid4().hex[:8]
    add_news_feed(
        guild_id,
        feed_id,
        int(data["channel_id"]),
        str(data["query"]),
        int(data.get("interval") or 60),
    )
    return feed_id


def _update(guild_id: int, feed_id: str, data: dict[str, Any]) -> bool:
    return update_news_feed(
        guild_id,
        feed_id,
        int(data["channel_id"]),
        str(data["query"]),
        int(data.get("interval") or 60),
    )


PANEL = Panel(
    id="news-feeds",
    title="ニュースフィード",
    icon="bi-newspaper",
    group="自動通知",
    path="/admin/settings/news-feeds",
    window=(820, 640),
    badge=lambda guild_id: len(get_news_feeds(guild_id)),
    sections=(
        Section(
            "フィード",
            collections=(
                Collection(
                    key="feeds",
                    label="登録済みフィード",
                    item_label="フィード",
                    max_items=MAX_FEEDS,
                    list=_list,
                    add=_add,
                    update=_update,
                    remove=remove_news_feed,
                    help=f"最大 {MAX_FEEDS} 件まで登録できます。",
                    item_fields=(
                        Field("channel_id", "送信先チャンネル", Widget.CHANNEL, required=True, nullable=False),
                        Field("query", "検索クエリ", Widget.TEXT, required=True, nullable=False, max_len=200),
                        Field("interval", "取得間隔（分）", Widget.INT, default=60, min=5, max=1440, nullable=False),
                    ),
                ),
            ),
        ),
    ),
)
