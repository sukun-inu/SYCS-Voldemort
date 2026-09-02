"""on_member_join / on_member_remove / on_member_update / on_member_ban / on_member_unban。

setup_events(bot) の巨大クロージャからそのまま切り出した。on_member_update
（元146行）はニックネーム/ロール/タイムアウトの3ブロックが並んでいるだけ
だったので、そのままヘルパーへ割った。
"""

from __future__ import annotations

import logging

import discord
from discord.ext.commands import Bot
from services.logging_service import log_action
from services.user_state_service import record_user_state_event
from services.welcome_service import send_goodbye, send_welcome
from config import JST as _JST

from events._util import _safe
from events.user_state_sync import _find_recent_audit_entry

logger = logging.getLogger(__name__)


async def _handle_nickname_change(bot: Bot, before: discord.Member, after: discord.Member) -> None:
    """ログ通知(log_action)とユーザー状態の永続化(record_user_state_event)を
    それぞれ別の _safe でくるむ。1つの _safe でまとめると、log_action の
    失敗（ログチャンネル未設定・Discord側の一時エラー等）で
    record_user_state_event まで巻き込まれて呼ばれなくなり、あとから
    ニックネーム変更の履歴を追えなくなる。逆に永続化側が失敗しても通知は
    飛ばしたい。
    """
    if before.nick == after.nick:
        return
    await _safe(
        log_action(
            bot,
            after.guild.id,
            "INFO",
            f"{after.mention} のニックネームが変更されました。",
            user=after,
            fields={
                "旧": before.nick or "(なし)",
                "新": after.nick or "(なし)",
            },
        ),
        "on_member_update nickname log_action",
    )
    await _safe(
        record_user_state_event(
            guild_id=after.guild.id,
            user_id=after.id,
            event_type="member_nickname_changed",
            status_after="active",
            user=after,
            in_guild=True,
            is_banned=False,
            timed_out_until=after.timed_out_until,
            payload={
                "before_nickname": before.nick,
                "after_nickname": after.nick,
            },
        ),
        "on_member_update nickname user_state persist",
    )


async def _handle_role_change(bot: Bot, before: discord.Member, after: discord.Member) -> None:
    """通知と永続化を別の _safe にくるむ理由は _handle_nickname_change と
    同じ。is_default()（@everyone ロール）を除いて集合を作っているが、
    @everyone は全メンバーが常に同じものを1つだけ持つため before/after
    どちらの集合にも等しく含まれ、除外してもしなくても差分の結果自体は
    変わらない。
    """
    before_roles = set(r.id for r in before.roles if not r.is_default())
    after_roles = set(r.id for r in after.roles if not r.is_default())
    added_roles = [r for r in after.roles if r.id in (after_roles - before_roles)]
    removed_roles = [r for r in before.roles if r.id in (before_roles - after_roles)]

    if not (added_roles or removed_roles):
        return

    fields = {}
    if added_roles:
        fields["追加されたロール"] = " ".join(r.mention for r in added_roles)
    if removed_roles:
        fields["削除されたロール"] = " ".join(r.mention for r in removed_roles)
    await _safe(
        log_action(
            bot,
            after.guild.id,
            "INFO",
            f"{after.mention} のロールが変更されました。",
            user=after,
            fields=fields,
        ),
        "on_member_update role log_action",
    )
    await _safe(
        record_user_state_event(
            guild_id=after.guild.id,
            user_id=after.id,
            event_type="member_role_changed",
            status_after="active",
            user=after,
            in_guild=True,
            is_banned=False,
            timed_out_until=after.timed_out_until,
            payload={
                "added_roles": [
                    {"id": int(r.id), "name": str(r.name), "position": int(r.position)} for r in added_roles
                ],
                "removed_roles": [
                    {"id": int(r.id), "name": str(r.name), "position": int(r.position)} for r in removed_roles
                ],
            },
        ),
        "on_member_update role user_state persist",
    )


async def _handle_timeout_change(bot: Bot, before: discord.Member, after: discord.Member) -> None:
    """タイムアウト付与は ERROR レベル、解除は INFO レベルでログを分ける
    （付与はモデレーションアクションとして目立たせたいが、解除は通常運用の
    一部として扱う）。通知と永続化を別の _safe にくるむ理由は
    _handle_nickname_change と同じ。
    """
    before_timeout = before.timed_out_until
    after_timeout = after.timed_out_until
    if before_timeout == after_timeout:
        return

    if after_timeout is not None:
        until_jst = after_timeout.astimezone(_JST).strftime("%Y/%m/%d %H:%M")
        await _safe(
            log_action(
                bot,
                after.guild.id,
                "ERROR",
                f"{after.mention} がタイムアウトされました。",
                user=after,
                fields={"解除日時 (JST)": until_jst},
                embed_color=discord.Color.orange(),
            ),
            "on_member_update timeout log_action",
        )
        await _safe(
            record_user_state_event(
                guild_id=after.guild.id,
                user_id=after.id,
                event_type="member_timeout_set",
                status_after="active",
                user=after,
                in_guild=True,
                is_banned=False,
                timed_out_until=after_timeout,
                payload={
                    "timed_out_until": after_timeout.isoformat(),
                },
            ),
            "on_member_update timeout user_state persist",
        )
    else:
        await _safe(
            log_action(
                bot,
                after.guild.id,
                "INFO",
                f"{after.mention} のタイムアウトが解除されました。",
                user=after,
            ),
            "on_member_update timeout_clear log_action",
        )
        await _safe(
            record_user_state_event(
                guild_id=after.guild.id,
                user_id=after.id,
                event_type="member_timeout_cleared",
                status_after="active",
                user=after,
                in_guild=True,
                is_banned=False,
                timed_out_until=None,
                payload={},
            ),
            "on_member_update timeout_clear user_state persist",
        )


# --------------------------
# メンバー参加・退出
# --------------------------
async def _on_member_join(bot: Bot, member: discord.Member) -> None:
    """log_action・record_user_state_event・send_welcome を別々の _safe で
    くるむ理由は _handle_nickname_change と同じ（ウェルカムメッセージ送信の
    失敗が監査ログや状態記録を巻き込んで消えないようにするため）。
    """
    joined_at = member.joined_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if member.joined_at else "(不明)"
    created_at = member.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if member.created_at else "(不明)"
    await _safe(
        log_action(
            bot,
            member.guild.id,
            "INFO",
            f"{member.mention} がサーバーに参加しました。",
            user=member,
            fields={
                "ユーザーID": str(member.id),
                "アカウント作成日": created_at,
                "参加日時": joined_at,
                "メンバー数": str(member.guild.member_count or 0),
            },
        ),
        "on_member_join log_action",
    )

    await _safe(
        record_user_state_event(
            guild_id=member.guild.id,
            user_id=member.id,
            event_type="member_join",
            status_after="active",
            user=member,
            in_guild=True,
            is_banned=False,
            timed_out_until=member.timed_out_until,
            payload={
                "joined_at": member.joined_at.isoformat() if member.joined_at else None,
                "account_created_at": member.created_at.isoformat() if member.created_at else None,
                "member_count": int(member.guild.member_count or 0),
            },
        ),
        "on_member_join user_state persist",
    )

    await _safe(send_welcome(member), "on_member_join welcome")


async def _on_member_remove(bot: Bot, member: discord.Member) -> None:
    """退出が実は kick だったかを監査ログで見分け、event_type/status_after を
    member_leave から member_kick へ差し替える。この監査ログ照会自体は
    _safe ではなく try/except+logger.debug で囲む——ここで例外が出ても、
    以降の log_action・record_user_state_event は member_leave 扱いのまま
    必ず実行したいため（監査ログの照会失敗と、退出そのものの記録は独立の
    事象）。ログ通知と永続化を別の _safe にくるむ理由は
    _handle_nickname_change と同じ。
    """
    roles = [r.mention for r in member.roles if not r.is_default()]
    event_type = "member_leave"
    status_after = "left"
    actor_user: discord.abc.User | None = None
    audit_reason: str | None = None

    try:
        kick_entry = await _find_recent_audit_entry(
            member.guild,
            action=discord.AuditLogAction.kick,
            target_user_id=member.id,
        )
        if kick_entry is not None:
            event_type = "member_kick"
            status_after = "kicked"
            actor_user = kick_entry.user
            audit_reason = kick_entry.reason
    except Exception as e:
        logger.debug("[BOT_SETUP] on_member_remove kick lookup failed: %s", e)

    await _safe(
        log_action(
            bot,
            member.guild.id,
            "INFO",
            f"{member.mention} がサーバーから退出しました。",
            user=member,
            fields={
                "ユーザーID": str(member.id),
                "保有ロール": " ".join(roles) if roles else "なし",
                "メンバー数": str(member.guild.member_count or 0),
            },
        ),
        "on_member_remove log_action",
    )

    await _safe(
        record_user_state_event(
            guild_id=member.guild.id,
            user_id=member.id,
            event_type=event_type,
            status_after=status_after,
            user=member,
            actor=actor_user,
            reason=audit_reason,
            in_guild=False,
            is_banned=False,
            timed_out_until=member.timed_out_until,
            payload={
                "member_count": int(member.guild.member_count or 0),
                "roles": [
                    {"id": int(r.id), "name": str(r.name), "position": int(r.position)}
                    for r in member.roles
                    if not r.is_default()
                ],
            },
        ),
        "on_member_remove user_state persist",
    )

    await _safe(send_goodbye(member), "on_member_remove goodbye")


# --------------------------
# メンバー情報変更（ニックネーム・ロール・タイムアウト）
# --------------------------
async def _on_member_update(bot: Bot, before: discord.Member, after: discord.Member) -> None:
    """ニックネーム・ロール・タイムアウトの3判定を順に呼ぶだけ（元は146行の
    1関数だったものを分割した経緯はモジュール docstring 参照）。3つは
    互いに独立した判定・通知なので、この呼び出し順自体に意味は無い。
    """
    await _handle_nickname_change(bot, before, after)
    await _handle_role_change(bot, before, after)
    await _handle_timeout_change(bot, before, after)


# --------------------------
# BAN / BAN 解除
# --------------------------
async def _on_member_ban(bot: Bot, guild: discord.Guild, user: discord.User) -> None:
    """実行者・理由を監査ログから引く部分は _on_member_remove の kick 検出と
    同じ形（照会失敗を try/except+logger.debug で吸収し、以降のログ通知・
    永続化は actor 情報が取れなくても必ず実行する）。member ではなく user を
    受け取るのは、BAN されたユーザーは既にギルドから外れておりメンバー
    キャッシュに残っていないことがあるため。
    """
    actor_user: discord.abc.User | None = None
    audit_reason: str | None = None
    try:
        ban_entry = await _find_recent_audit_entry(
            guild,
            action=discord.AuditLogAction.ban,
            target_user_id=user.id,
        )
        if ban_entry is not None:
            actor_user = ban_entry.user
            audit_reason = ban_entry.reason
    except Exception as e:
        logger.debug("[BOT_SETUP] on_member_ban audit lookup failed: %s", e)

    await _safe(
        log_action(
            bot,
            guild.id,
            "ERROR",
            f"{user.mention} が BAN されました。",
            user=user,
            fields={
                "ユーザーID": str(user.id),
                "ユーザー名": str(user),
            },
            embed_color=discord.Color.red(),
        ),
        "on_member_ban log_action",
    )

    await _safe(
        record_user_state_event(
            guild_id=guild.id,
            user_id=user.id,
            event_type="member_ban",
            status_after="banned",
            user=user,
            actor=actor_user,
            reason=audit_reason,
            in_guild=False,
            is_banned=True,
            payload={},
        ),
        "on_member_ban user_state persist",
    )


async def _on_member_unban(bot: Bot, guild: discord.Guild, user: discord.User) -> None:
    """_on_member_ban と対になる BAN 解除版。監査ログ照会の扱い・user を
    受け取る理由は _on_member_ban 参照。
    """
    actor_user: discord.abc.User | None = None
    audit_reason: str | None = None
    try:
        unban_entry = await _find_recent_audit_entry(
            guild,
            action=discord.AuditLogAction.unban,
            target_user_id=user.id,
        )
        if unban_entry is not None:
            actor_user = unban_entry.user
            audit_reason = unban_entry.reason
    except Exception as e:
        logger.debug("[BOT_SETUP] on_member_unban audit lookup failed: %s", e)

    await _safe(
        log_action(
            bot,
            guild.id,
            "INFO",
            f"{user.mention} の BAN が解除されました。",
            user=user,
            fields={
                "ユーザーID": str(user.id),
                "ユーザー名": str(user),
            },
        ),
        "on_member_unban log_action",
    )

    await _safe(
        record_user_state_event(
            guild_id=guild.id,
            user_id=user.id,
            event_type="member_unban",
            status_after="unbanned",
            user=user,
            actor=actor_user,
            reason=audit_reason,
            in_guild=False,
            is_banned=False,
            payload={},
        ),
        "on_member_unban user_state persist",
    )


def register(bot: Bot) -> None:
    """5個のイベントハンドラを bot へ登録する。

    実処理は上の _on_member_*(bot, ...) にあり、ここは discord.py へ
    「この名前のイベントとして受け取る」ことを伝える薄い配線だけを持つ
    （@bot.event は関数の __name__ を見て bot.on_member_join 等へ
    setattr するため、ラッパー自体は on_member_join という名前で無いといけない）。
    """

    @bot.event
    async def on_member_join(member: discord.Member):
        """discord.pyへの薄い配線。実処理は_on_member_joinへ委譲（配線の
        事情はregister()のdocstring参照）。
        """
        await _on_member_join(bot, member)

    @bot.event
    async def on_member_remove(member: discord.Member):
        """実処理は_on_member_removeへ委譲。配線の事情はregister()のdocstring参照。"""
        await _on_member_remove(bot, member)

    @bot.event
    async def on_member_update(before: discord.Member, after: discord.Member):
        """実処理は_on_member_updateへ委譲。配線の事情はregister()のdocstring参照。"""
        await _on_member_update(bot, before, after)

    @bot.event
    async def on_member_ban(guild: discord.Guild, user: discord.User):
        """実処理は_on_member_banへ委譲。配線の事情はregister()のdocstring参照。"""
        await _on_member_ban(bot, guild, user)

    @bot.event
    async def on_member_unban(guild: discord.Guild, user: discord.User):
        """実処理は_on_member_unbanへ委譲。配線の事情はregister()のdocstring参照。"""
        await _on_member_unban(bot, guild, user)
