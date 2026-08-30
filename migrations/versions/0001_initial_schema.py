"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-07

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "metal_price_daily",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("metal_key", sa.String(length=32), nullable=False),
        sa.Column("metal_code", sa.String(length=16), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("price_per_gram", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("delta_from_previous", sa.Numeric(precision=18, scale=4), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("metal_key", "snapshot_date", name="uq_metal_price_daily_key_date"),
    )
    op.create_index("ix_metal_price_daily_snapshot_date", "metal_price_daily", ["snapshot_date"])
    op.create_index(
        "ix_metal_price_daily_metal_key_date",
        "metal_price_daily",
        ["metal_key", "snapshot_date"],
    )

    op.create_table(
        "push_subscription",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("endpoint", sa.String(length=1024), nullable=False),
        sa.Column("p256dh_key", sa.String(length=512), nullable=False),
        sa.Column("auth_key", sa.String(length=512), nullable=False),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint", name="uq_push_subscription_endpoint"),
    )
    op.create_index("ix_push_subscription_created_at", "push_subscription", ["created_at"])

    op.create_table(
        "notification_dispatch",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("notification_type", sa.String(length=64), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("detail", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "notification_type",
            "snapshot_date",
            name="uq_notification_dispatch_type_date",
        ),
    )
    op.create_index(
        "ix_notification_dispatch_created_at",
        "notification_dispatch",
        ["created_at"],
    )

    op.create_table(
        "weekly_forecast_meta",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("as_of_date", sa.Date(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("horizon_days", sa.Integer(), nullable=False),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("model_description", sa.String(length=255), nullable=False),
        sa.Column("usd_jpy_available", sa.Boolean(), nullable=False),
        sa.Column("usd_jpy_source", sa.String(length=64), nullable=False),
        sa.Column("usd_jpy_latest", sa.Numeric(precision=18, scale=6), nullable=True),
        sa.Column("usd_jpy_weekly_change_pct", sa.Numeric(precision=18, scale=6), nullable=True),
        sa.Column("news_available", sa.Boolean(), nullable=False),
        sa.Column("news_source", sa.String(length=64), nullable=False),
        sa.Column("news_sentiment_json", sa.Text(), nullable=False),
        sa.Column("news_article_counts_json", sa.Text(), nullable=False),
        sa.Column("news_headlines_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_weekly_forecast_meta_as_of_date",
        "weekly_forecast_meta",
        ["as_of_date"],
    )

    op.create_table(
        "weekly_forecast_daily",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("metal_key", sa.String(length=32), nullable=False),
        sa.Column("as_of_date", sa.Date(), nullable=False),
        sa.Column("forecast_date", sa.Date(), nullable=False),
        sa.Column("start_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("projected_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("price_per_gram", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("delta_from_previous", sa.Numeric(precision=18, scale=4), nullable=True),
        sa.Column("projected_change_pct_7d", sa.Numeric(precision=12, scale=6), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=12, scale=6), nullable=False),
        sa.Column("implied_daily_return_pct", sa.Numeric(precision=12, scale=6), nullable=False),
        sa.Column("drivers_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "metal_key",
            "forecast_date",
            name="uq_weekly_forecast_daily_key_date",
        ),
    )
    op.create_index(
        "ix_weekly_forecast_daily_as_of_date",
        "weekly_forecast_daily",
        ["as_of_date"],
    )
    op.create_index(
        "ix_weekly_forecast_daily_forecast_date",
        "weekly_forecast_daily",
        ["forecast_date"],
    )


def downgrade() -> None:
    op.drop_table("weekly_forecast_daily")
    op.drop_table("weekly_forecast_meta")
    op.drop_table("notification_dispatch")
    op.drop_table("push_subscription")
    op.drop_table("metal_price_daily")
