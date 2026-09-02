"""forecast interval bounds

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-20

点予測をやめて予測区間(レンジ)を返すモデルへ移行したため、区間の下限・上限を保存する。
既存行には値が無いので、いずれも nullable で追加する。

forecast_accuracy_log の within_interval は「実勢価格が予測区間に収まったか」を記録する。
区間予測にとって被覆率は最も本質的な品質指標(名目80%なら実測も80%であるべき)で、
これが無いと精度を評価できない。
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """区間予測(上限・下限)と被覆率(within_interval)用のカラムを追加する。

    全カラム nullable で、既定値は入れない。追加時点の既存行は NULL の
    まま残る。過去分は元々「点予測」しか無く、区間の下限・上限を後から
    作れないため、デフォルト値で埋めようとすると嘘の値になる。
    """
    op.add_column(
        "weekly_forecast_daily",
        sa.Column("lower_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=True),
    )
    op.add_column(
        "weekly_forecast_daily",
        sa.Column("upper_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=True),
    )
    op.add_column(
        "forecast_accuracy_log",
        sa.Column("lower_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=True),
    )
    op.add_column(
        "forecast_accuracy_log",
        sa.Column("upper_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=True),
    )
    op.add_column(
        "forecast_accuracy_log",
        sa.Column("within_interval", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    """追加した5カラムを削除する。保存済みの区間・被覆率の値も消える。"""
    op.drop_column("forecast_accuracy_log", "within_interval")
    op.drop_column("forecast_accuracy_log", "upper_price_per_gram")
    op.drop_column("forecast_accuracy_log", "lower_price_per_gram")
    op.drop_column("weekly_forecast_daily", "upper_price_per_gram")
    op.drop_column("weekly_forecast_daily", "lower_price_per_gram")
