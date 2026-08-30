"""forecast baseline comparison

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-20

為替・ニュース・AI判定による中心値の傾き(tilt)が本当に予測を良くしているかは、
一度も検証されていない。過去の履歴を再現できないため後追いでは確かめられないので、
予測のたびに「傾きを掛けない予測(=予測時点の現在価格)」を一緒に記録し、
答え合わせ時に両者の誤差を比較できるようにする。

これは同時に「予測が何もしないより良いか」を本番で常時測ることにもなる。
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "forecast_accuracy_log",
        sa.Column("baseline_price_per_gram", sa.Numeric(precision=18, scale=4), nullable=True),
    )
    op.add_column(
        "forecast_accuracy_log",
        sa.Column("tilt_pct_per_day", sa.Numeric(precision=12, scale=6), nullable=True),
    )
    op.add_column(
        "forecast_accuracy_log",
        sa.Column("baseline_error_pct", sa.Numeric(precision=12, scale=6), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("forecast_accuracy_log", "baseline_error_pct")
    op.drop_column("forecast_accuracy_log", "tilt_pct_per_day")
    op.drop_column("forecast_accuracy_log", "baseline_price_per_gram")
