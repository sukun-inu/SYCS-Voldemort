from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Index, Numeric, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy base."""


class MetalPriceDaily(Base):
    __tablename__ = "metal_price_daily"
    __table_args__ = (
        UniqueConstraint("metal_key", "snapshot_date", name="uq_metal_price_daily_key_date"),
        Index("ix_metal_price_daily_snapshot_date", "snapshot_date"),
        Index("ix_metal_price_daily_metal_key_date", "metal_key", "snapshot_date"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    metal_key: Mapped[str] = mapped_column(String(32), nullable=False)
    metal_code: Mapped[str] = mapped_column(String(16), nullable=False)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)
    price_per_gram: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    delta_from_previous: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class PushSubscription(Base):
    __tablename__ = "push_subscription"
    __table_args__ = (
        UniqueConstraint("endpoint", name="uq_push_subscription_endpoint"),
        Index("ix_push_subscription_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    endpoint: Mapped[str] = mapped_column(String(1024), nullable=False)
    p256dh_key: Mapped[str] = mapped_column(String(512), nullable=False)
    auth_key: Mapped[str] = mapped_column(String(512), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class NotificationDispatch(Base):
    __tablename__ = "notification_dispatch"
    __table_args__ = (
        UniqueConstraint("notification_type", "snapshot_date", name="uq_notification_dispatch_type_date"),
        Index("ix_notification_dispatch_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    notification_type: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)
    detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class WeeklyForecastMeta(Base):
    __tablename__ = "weekly_forecast_meta"
    __table_args__ = (
        Index("ix_weekly_forecast_meta_as_of_date", "as_of_date"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    horizon_days: Mapped[int] = mapped_column(nullable=False, default=7)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    model_description: Mapped[str] = mapped_column(String(255), nullable=False)
    usd_jpy_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    usd_jpy_source: Mapped[str] = mapped_column(String(64), nullable=False, default="Stooq")
    usd_jpy_latest: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    usd_jpy_weekly_change_pct: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    news_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    news_source: Mapped[str] = mapped_column(String(64), nullable=False, default="Google News RSS")
    news_sentiment_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    news_article_counts_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    news_headlines_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class WeeklyForecastDaily(Base):
    __tablename__ = "weekly_forecast_daily"
    __table_args__ = (
        UniqueConstraint("metal_key", "forecast_date", name="uq_weekly_forecast_daily_key_date"),
        Index("ix_weekly_forecast_daily_as_of_date", "as_of_date"),
        Index("ix_weekly_forecast_daily_forecast_date", "forecast_date"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    metal_key: Mapped[str] = mapped_column(String(32), nullable=False)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    forecast_date: Mapped[date] = mapped_column(Date, nullable=False)
    start_price_per_gram: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    projected_price_per_gram: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    price_per_gram: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    delta_from_previous: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True)
    projected_change_pct_7d: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    implied_daily_return_pct: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    drivers_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class ForecastAccuracyLog(Base):
    """週次予測の的中率を後から検証するための記録。WeeklyForecastDailyは
    リフレッシュのたびに上書き削除されるため、予測時点のスナップショットを
    別テーブルに残し、対象日の実勢価格が判明した時点で答え合わせする。"""

    __tablename__ = "forecast_accuracy_log"
    __table_args__ = (
        UniqueConstraint("metal_key", "as_of_date", "forecast_date", name="uq_forecast_accuracy_key_asof_date"),
        Index("ix_forecast_accuracy_forecast_date", "forecast_date"),
        Index("ix_forecast_accuracy_metal_forecast_date", "metal_key", "forecast_date"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    metal_key: Mapped[str] = mapped_column(String(32), nullable=False)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    forecast_date: Mapped[date] = mapped_column(Date, nullable=False)
    horizon_offset_days: Mapped[int] = mapped_column(nullable=False)
    predicted_price_per_gram: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    model_variant: Mapped[str] = mapped_column(String(32), nullable=False)
    actual_price_per_gram: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True)
    error_pct: Mapped[Decimal | None] = mapped_column(Numeric(12, 6), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class UserStateCurrent(Base):
    __tablename__ = "user_state_current"
    __table_args__ = (
        UniqueConstraint("guild_id", "user_id", name="uq_user_state_current_guild_user"),
        Index("ix_user_state_current_guild_status", "guild_id", "status"),
        Index("ix_user_state_current_guild_last_event_at", "guild_id", "last_event_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    is_in_guild: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_banned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_timed_out: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    timed_out_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    roles_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    abilities_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    last_event_type: Mapped[str | None] = mapped_column(String(48), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_joined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_left_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class UserStateEvent(Base):
    __tablename__ = "user_state_event"
    __table_args__ = (
        Index("ix_user_state_event_guild_user_event_at", "guild_id", "user_id", "event_at"),
        Index("ix_user_state_event_guild_event_type_event_at", "guild_id", "event_type", "event_at"),
        Index("ix_user_state_event_event_at", "event_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    status_after: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    actor_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    event_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
