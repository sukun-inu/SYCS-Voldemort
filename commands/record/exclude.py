"""本人が自分を録音対象から外す／戻す（/record exclude）。

register_recording_commands() 分割前の commands/recording_commands.py から
そのまま切り出した（経緯は commands/record/__init__.py を参照）。
ここだけ管理者専用ではない（本人が自分に対して使う）。
"""

from typing import cast

import discord
from discord import app_commands

from commands.interaction_utils import send_ephemeral
from services import recording_service as recording
from services.settings_store import awrite, get_recording_settings, set_recording_excluded_users


def register(group: app_commands.Group) -> None:
    @group.command(name="exclude", description="自分を録音の対象から外す／戻します")
    @app_commands.describe(exclude="True で除外、False で解除")
    async def record_exclude(interaction: discord.Interaction, exclude: bool = True):
        if interaction.guild is None:
            await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
            return

        # guild_id は guild とは別属性で、上のチェックでは絞り込みが効かない。
        # guild が非 None である以上、guild_id も必ず非 None。
        guild_id = cast(int, interaction.guild_id)
        settings = get_recording_settings(guild_id)
        excluded = set(settings.get("excluded_user_ids", []))
        user_id = interaction.user.id

        if exclude:
            excluded.add(user_id)
            message = "以後、このサーバーの録音では貴様の声は記録されぬ。" "\n※ 進行中の録音にも即時反映される。"
        else:
            excluded.discard(user_id)
            message = "除外を解除した。以後の録音では貴様の声も記録される。"

        await awrite(set_recording_excluded_users, guild_id, sorted(excluded))

        # 進行中のセッションにも反映する（設定だけ変えて今の録音に効かないと紛らわしい）
        session = recording.get_session(guild_id)
        if session is not None:
            session.excluded_user_ids = set(excluded)

        await send_ephemeral(interaction, message)
