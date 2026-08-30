"""forecast accuracy log

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-20

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "forecast_accuracy_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("metal_key", sa.String(length=32), nullable=False),
        sa.Column("as_of_date", sa.Date(), nullable=False),
        sa.Column("forecast_date", sa.Date(), nullable=False),
        sa.Column("horizon_offset_days", sa.Integer(), nullable=False),
        sa.Column("predicted_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("model_variant", sa.String(length=32), nullable=False),
        sa.Column("actual_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=True),
        sa.Column("error_pct", sa.Numeric(precision=12, scale=6), nullable=True),
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
            "as_of_date",
            "forecast_date",
            name="uq_forecast_accuracy_key_asof_date",
        ),
    )
    op.create_index(
        "ix_forecast_accuracy_forecast_date",
        "forecast_accuracy_log",
        ["forecast_date"],
    )
    op.create_index(
        "ix_forecast_accuracy_metal_forecast_date",
        "forecast_accuracy_log",
        ["metal_key", "forecast_date"],
    )


def downgrade() -> None:
    op.drop_table("forecast_accuracy_log")
