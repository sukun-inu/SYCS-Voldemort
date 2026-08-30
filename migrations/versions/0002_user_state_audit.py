"""user state audit tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-09

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_state_current",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("display_name", sa.String(length=128), nullable=True),
        sa.Column("avatar_url", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("is_in_guild", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_banned", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_timed_out", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("timed_out_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("roles_json", sa.Text(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("abilities_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("last_event_type", sa.String(length=48), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_left_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("guild_id", "user_id", name="uq_user_state_current_guild_user"),
    )
    op.create_index(
        "ix_user_state_current_guild_status",
        "user_state_current",
        ["guild_id", "status"],
    )
    op.create_index(
        "ix_user_state_current_guild_last_event_at",
        "user_state_current",
        ["guild_id", "last_event_at"],
    )

    op.create_table(
        "user_state_event",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("status_after", sa.String(length=32), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_name", sa.String(length=128), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("payload_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_user_state_event_guild_user_event_at",
        "user_state_event",
        ["guild_id", "user_id", "event_at"],
    )
    op.create_index(
        "ix_user_state_event_guild_event_type_event_at",
        "user_state_event",
        ["guild_id", "event_type", "event_at"],
    )
    op.create_index(
        "ix_user_state_event_event_at",
        "user_state_event",
        ["event_at"],
    )


def downgrade() -> None:
    op.drop_table("user_state_event")
    op.drop_table("user_state_current")
