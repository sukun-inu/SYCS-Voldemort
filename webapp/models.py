from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import Date, DateTime, Index, Numeric, String, UniqueConstraint, func
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
