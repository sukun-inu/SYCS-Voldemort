"""セキュリティの判定の作り直し（トラッカーの rust-09。本人が 2026-11-28 に決めた 8 つ、B13-sec）を固定する。

S1 措置の形 → Discord のタイムアウト（危険は 24 時間。権限が無ければいまどおり全ロールを外す）
S2 スパムだけのとき → スパムと数えた投稿を消して 10 分のタイムアウト（権限が無ければ消すだけ）
S3 スパムの数え方 → 「同じ内容の繰り返し」（60 秒に 3 回）と「量の多さ」（10 秒に 8 回）に分ける
S4 VC の荒らし → 名前を見ず「入って間もない人」で見る。数に入った全員に措置し、二重に措置しない
S5 新規メンバーの見方 → アカウントの作成日（ID から）も見る（NEW_ACCOUNT）
S6 URL の抜き出し → Discord の書き方（隠しリンク・括弧・飾りの記号・招待）を読み解く
S7 バイパス → 管理者は設定を読む前に飛ばす。飛ばした通知はログファイルだけ
S8 結果の表示 → 見出しと色を、実際に取った措置から決める

数え方そのものの境界（窓・回数・掃除）は tests/test_services_moderation.py の SpamDetectionTests・
RaidDetectionTests が見る。どれも、直す前のコードでは落ちる理由を HANDBACK に書いてある。
"""

import asyncio
import datetime
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="security-decisions-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="security-decisions-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import services.content_moderation as content_moderation  # noqa: E402
import services.raid_detection as raid_detection  # noqa: E402
import services.security_service as sec  # noqa: E402
import services.spam_detection as spam_detection  # noqa: E402

RED = discord.Color.red()
ORANGE = discord.Color.orange()
GOLD = discord.Color.gold()
GREEN = discord.Color.green()


class _Forbidden(discord.Forbidden):
    """権限不足（discord.Forbidden）。応答を組み立てずに作る。"""

    def __init__(self):
        """文だけを持たせる。"""
        Exception.__init__(self, "403 Forbidden (error code: 50013): Missing Permissions")


class _NotFound(discord.NotFound):
    """既に消えていた（discord.NotFound）。応答を組み立てずに作る。"""

    def __init__(self):
        """文だけを持たせる。"""
        Exception.__init__(self, "404 Not Found (error code: 10008): Unknown Message")


def _snowflake(days_ago: float) -> int:
    """days_ago 日前に作ったアカウントの ID（snowflake）。"""
    return discord.utils.time_snowflake(discord.utils.utcnow() - datetime.timedelta(days=days_ago))


def _member(
    uid=5,
    *,
    can_timeout=True,
    roles=(),
    joined_days_ago=400.0,
    admin=False,
    voice_channel=None,
):
    """検査に通る Member。Bot のタイムアウトの権限・管理者・参加日時・VC を決められる。"""
    member = Mock(spec=discord.Member)
    member.id = uid
    member.bot = False
    me = SimpleNamespace(guild_permissions=SimpleNamespace(moderate_members=can_timeout))
    member.guild = SimpleNamespace(id=1, me=me)
    member.guild_permissions = SimpleNamespace(administrator=admin, manage_guild=True, manage_messages=True)
    member.roles = [SimpleNamespace(id=1, is_default=lambda: True)] + [
        SimpleNamespace(id=r, is_default=lambda: False) for r in roles
    ]
    joined = None if joined_days_ago is None else discord.utils.utcnow() - datetime.timedelta(days=joined_days_ago)
    member.joined_at = joined
    member.voice = SimpleNamespace(channel=SimpleNamespace(id=voice_channel)) if voice_channel else None
    member.mention = f"<@{uid}>"
    member.timeout = AsyncMock()
    member.remove_roles = AsyncMock()
    return member


def _message(member, content="x", *, message_id=1000, channel_id=77):
    """検査するメッセージ（消すと記録する）。"""
    return SimpleNamespace(
        id=message_id,
        author=member,
        guild=member.guild,
        channel=SimpleNamespace(id=channel_id),
        content=content,
        attachments=[],
        delete=AsyncMock(),
    )


class _Clock:
    """time モジュールの代わり（時刻を手で進める）。"""

    def __init__(self, now=1_000_000.0):
        """始めの時刻。"""
        self.now = now

    def time(self):
        """いまの時刻。"""
        return self.now


class _SecurityCase(unittest.TestCase):
    """スパムと VC の荒らしの記録を空にし、時刻を止める（各テストの共通の下ごしらえ）。"""

    def setUp(self):
        """記録を退避して空にし、時刻を止める。"""
        saved = (
            {k: list(v) for k, v in spam_detection._user_posts.items()},
            {k: list(v) for k, v in raid_detection._vc_join_history.items()},
            {k: dict(v) for k, v in raid_detection._vc_enforced.items()},
        )
        spam_detection._user_posts.clear()
        raid_detection._vc_join_history.clear()
        raid_detection._vc_enforced.clear()
        self.addCleanup(self._restore, saved)
        self.clock = _Clock()
        for module in (spam_detection, raid_detection):
            p = patch.object(module, "time", self.clock)
            p.start()
            self.addCleanup(p.stop)
        self.logged = []
        self.sent = []
        self.deleted_by_id = []

    @staticmethod
    def _restore(saved):
        """退避した記録を戻す。"""
        posts, joins, enforced = saved
        spam_detection._user_posts.clear()
        spam_detection._user_posts.update(posts)
        raid_detection._vc_join_history.clear()
        raid_detection._vc_join_history.update(joins)
        raid_detection._vc_enforced.clear()
        raid_detection._vc_enforced.update(enforced)

    async def _log_action(self, bot, guild_id, level, message, user=None, fields=None, embed_color=None):
        """log_action の代わり。水準・見出し・項目・色・作者を控える。"""
        self.logged.append(
            SimpleNamespace(level=level, message=message, fields=fields or {}, color=embed_color, user=user)
        )

    async def _send_log_embed(self, bot, guild_id, level, embed):
        """send_log_embed の代わり。水準と Embed を控える（進み具合の Embed は書き換えない）。"""
        self.sent.append((level, embed))

    async def _delete_message(self, bot, channel_id, message_id):
        """ID での削除の代わり。消した場所を控える。"""
        self.deleted_by_id.append((channel_id, message_id))

    def _check(self, message, *, gpt="SAFE", trusted=None, delete=None):
        """本物の handle_security_for_message を、外のもの（設定・Groq・ログ・削除）だけ差し替えて回す。"""
        with (
            patch.object(sec, "get_trusted_user_ids", trusted or (lambda g: [])),
            patch.object(sec, "get_bypass_role_ids", lambda g: []),
            patch.object(sec, "get_response_channel_id", lambda g: None),
            patch.object(sec, "gpt_assess", AsyncMock(return_value=gpt)),
            patch.object(sec, "log_action", self._log_action),
            patch.object(sec, "send_log_embed", self._send_log_embed),
            patch.object(sec, "delete_message", delete or self._delete_message),
            patch.object(sec.logger, "warning"),
            patch.object(sec.logger, "error"),
        ):
            asyncio.run(sec.handle_security_for_message(Mock(), message))

    def _final(self):
        """最後の「メッセージセキュリティ検査」のログ。"""
        finals = [entry for entry in self.logged if entry.message == "メッセージセキュリティ検査"]
        self.assertEqual(len(finals), 1, self.logged)
        return finals[0]

    def _join_vc(self, member, *, bypass=None):
        """本物の handle_security_for_voice_join に VC 777 への参加を 1 回渡す（bypass で判定を替えられる）。"""
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=SimpleNamespace(id=777, mention="<#777>"))
        with (
            patch.object(sec, "get_trusted_user_ids", lambda g: []),
            patch.object(sec, "get_bypass_role_ids", lambda g: []),
            patch.object(sec, "is_security_bypassed", bypass or sec.is_security_bypassed),
            patch.object(sec, "log_action", self._log_action),
            patch.object(sec.logger, "error"),
        ):
            asyncio.run(sec.handle_security_for_voice_join(Mock(), member, before, after))


class DangerTimeoutTests(_SecurityCase):
    """S1: 危険なものは 24 時間のタイムアウト。権限が無ければいまどおり全ロールを外す。"""

    def test_defaults_match_the_decision(self):
        """既定は危険 24 時間・スパム 10 分。上限は Discord の 28 日。"""
        self.assertEqual(sec.SECURITY_TIMEOUT_DANGER_SECONDS, 86400)
        self.assertEqual(sec.SECURITY_TIMEOUT_SPAM_SECONDS, 600)
        self.assertEqual(sec.TIMEOUT_MAX_SECONDS, 28 * 24 * 3600)

    def test_a_dangerous_post_is_deleted_and_the_author_timed_out_for_a_day(self):
        """危険なら投稿を消して 24 時間のタイムアウト。ロールは外さない。理由は「セキュリティ違反」。"""
        member = _member(roles=[11, 12])
        message = _message(member)
        self._check(message, gpt="DANGEROUS")
        message.delete.assert_awaited_once()
        member.timeout.assert_awaited_once_with(datetime.timedelta(seconds=86400), reason="セキュリティ違反")
        member.remove_roles.assert_not_awaited()
        final = self._final()
        self.assertEqual(final.fields["タイムアウト"], "24 時間")
        self.assertNotIn("剥がしたロール", final.fields)

    def test_without_the_permission_all_roles_are_stripped_as_before(self):
        """Bot にタイムアウトの権限が無いサーバーでは、いまどおり全ロールを 1 つずつ外す。"""
        member = _member(can_timeout=False, roles=[11, 12])
        self._check(_message(member), gpt="DANGEROUS")
        member.timeout.assert_not_awaited()
        self.assertEqual([c.args[0].id for c in member.remove_roles.await_args_list], [11, 12])
        final = self._final()
        self.assertEqual(final.fields["剥がしたロール"], "<@&11> <@&12>")
        self.assertEqual(final.fields["措置"], "消してロールを外した")

    def test_a_refused_timeout_is_reported_and_roles_are_not_tried(self):
        """タイムアウトが断られても、ロールを外すことは試さない（同じ理由で失敗する）。失敗として報告する。"""
        member = _member(roles=[11])
        member.timeout = AsyncMock(side_effect=_Forbidden())
        self._check(_message(member), gpt="DANGEROUS")
        member.remove_roles.assert_not_awaited()
        final = self._final()
        self.assertEqual(final.fields["タイムアウトできなかった（権限不足）"], "24 時間")
        self.assertEqual(final.fields["措置"], "消して 24 時間のタイムアウト（一部失敗）")

    def test_the_length_follows_the_setting(self):
        """長さは SECURITY_TIMEOUT_DANGER_SECONDS で変えられる。"""
        member = _member()
        with patch.object(sec, "SECURITY_TIMEOUT_DANGER_SECONDS", 3600):
            self._check(_message(member), gpt="DANGEROUS")
        member.timeout.assert_awaited_once_with(datetime.timedelta(seconds=3600), reason="セキュリティ違反")
        self.assertEqual(self._final().fields["タイムアウト"], "1 時間")

    def test_a_failed_bypass_check_still_withholds_everything(self):
        """バイパスの判定に失敗したら、消さず・タイムアウトせず・外さない（いまの作法のまま）。"""

        def boom(_):
            """設定が読めない。"""
            raise RuntimeError("設定が読めない")

        member = _member(roles=[11])
        message = _message(member)
        self._check(message, gpt="DANGEROUS", trusted=boom)
        message.delete.assert_not_awaited()
        member.timeout.assert_not_awaited()
        member.remove_roles.assert_not_awaited()
        self.assertTrue(any("要確認" in entry.message for entry in self.logged))
        self.assertEqual(self._final().fields["措置"], "措置を見送った（要確認）")

    def test_the_permission_is_read_from_the_bot_member(self):
        """権限は guild.me.guild_permissions.moderate_members。分からないときは持っていない扱い。"""
        self.assertTrue(sec.can_timeout(_member().guild))
        self.assertFalse(sec.can_timeout(_member(can_timeout=False).guild))
        self.assertFalse(sec.can_timeout(SimpleNamespace(id=1, me=None)))
        self.assertFalse(sec.can_timeout(SimpleNamespace(id=1)))
        self.assertFalse(sec.can_timeout(Mock()), "真偽の値でないものを権限ありにした")


class SpamOnlyTests(_SecurityCase):
    """S2: スパムだけなら、スパムと数えた投稿を消して 10 分のタイムアウト（権限が無ければ消すだけ）。"""

    def _spam_twice(self, member):
        """同じ内容の前の投稿を 2 件記録する（ID 100・101、チャンネル 70・71）。"""
        for message_id, channel_id in ((100, 70), (101, 71)):
            spam_detection.check_spam(1, member.id, channel_id, message_id, "限定セール", [])
            self.clock.now += 5

    def test_the_counted_posts_are_deleted_and_the_author_timed_out_for_ten_minutes(self):
        """3 回目で、前の 2 件（ID で）とこの投稿を 1 件ずつ消し、10 分のタイムアウト。ロールは外さない。"""
        member = _member(roles=[11])
        self._spam_twice(member)
        message = _message(member, "限定セール")
        self._check(message)
        self.assertEqual(self.deleted_by_id, [(70, 100), (71, 101)])
        message.delete.assert_awaited_once()
        member.timeout.assert_awaited_once_with(datetime.timedelta(seconds=600), reason="セキュリティ違反")
        member.remove_roles.assert_not_awaited()
        final = self._final()
        self.assertEqual(final.fields["消した投稿"], "3件")
        self.assertEqual(final.fields["措置"], "消して 10 分のタイムアウト")
        self.assertEqual(final.fields["スパム回数"], "3")

    def test_without_the_permission_the_posts_are_only_deleted(self):
        """権限が無いサーバーでは消すだけ（ロールは外さない）。"""
        member = _member(can_timeout=False, roles=[11])
        self._spam_twice(member)
        message = _message(member, "限定セール")
        self._check(message)
        message.delete.assert_awaited_once()
        member.timeout.assert_not_awaited()
        member.remove_roles.assert_not_awaited()
        self.assertEqual(self._final().fields["措置"], "消した")

    def test_spam_with_danger_takes_the_day_timeout(self):
        """スパムに加えて危険な材料があれば、24 時間のタイムアウトが勝つ（スパムの投稿も消す）。"""
        member = _member()
        self._spam_twice(member)
        self._check(_message(member, "限定セール"), gpt="DANGEROUS")
        self.assertEqual(len(self.deleted_by_id), 2)
        member.timeout.assert_awaited_once_with(datetime.timedelta(seconds=86400), reason="セキュリティ違反")

    def test_a_post_already_gone_does_not_stop_the_rest(self):
        """前の投稿が既に消えていても（NotFound）止めず、消せなかった数にも入れない。"""
        member = _member()
        self._spam_twice(member)
        tried = []

        async def delete(bot, channel_id, message_id):
            """1 件目は既に消えている。"""
            tried.append(message_id)
            if message_id == 100:
                raise _NotFound()

        message = _message(member, "限定セール")
        self._check(message, delete=delete)
        self.assertEqual(tried, [100, 101])
        message.delete.assert_awaited_once()
        final = self._final()
        self.assertEqual(final.fields["消した投稿"], "3件")
        self.assertNotIn("消せなかった投稿", final.fields)

    def test_a_delete_failure_is_reported(self):
        """消せなかった投稿があれば、項目に出し、見出しに「（一部失敗）」を足す。ほかは消し続ける。"""
        member = _member()
        self._spam_twice(member)

        async def delete(bot, channel_id, message_id):
            """1 件目は消せない。"""
            if message_id == 100:
                raise discord.HTTPException(Mock(status=500, reason="boom"), "boom")

        message = _message(member, "限定セール")
        self._check(message, delete=delete)
        message.delete.assert_awaited_once()
        final = self._final()
        self.assertEqual((final.fields["消した投稿"], final.fields["消せなかった投稿"]), ("2件", "1件"))
        self.assertEqual(final.fields["措置"], "消して 10 分のタイムアウト（一部失敗）")

    def test_a_post_is_deleted_by_id_with_a_partial_message(self):
        """ID での削除は discord.py の PartialMessage.delete（bot.get_partial_messageable から）。"""
        bot = Mock()
        partial = bot.get_partial_messageable.return_value.get_partial_message.return_value
        partial.delete = AsyncMock()
        asyncio.run(sec.delete_message(bot, 70, 100))
        bot.get_partial_messageable.assert_called_once_with(70)
        bot.get_partial_messageable.return_value.get_partial_message.assert_called_once_with(100)
        partial.delete.assert_awaited_once()


class SpamCountingTests(_SecurityCase):
    """S3: スパムの数え方（AI に渡す文とログの文。数え方の境界は SpamDetectionTests）。"""

    def test_the_old_constants_are_gone_and_the_new_defaults_match(self):
        """古い定数は無い。新しい既定は 60 秒に 3 回・10 秒に 8 回。"""
        self.assertFalse(hasattr(spam_detection, "SPAM_REPEAT_THRESHOLD"))
        self.assertFalse(hasattr(spam_detection, "SPAM_TIME_WINDOW"))
        self.assertEqual((spam_detection.SPAM_REPEAT_COUNT, spam_detection.SPAM_REPEAT_WINDOW_SECONDS), (3, 60))
        self.assertEqual((spam_detection.SPAM_FLOOD_COUNT, spam_detection.SPAM_FLOOD_WINDOW_SECONDS), (8, 10))

    def test_the_ai_is_told_which_condition_hit(self):
        """AI に渡す文は、当たった条件ごとに 1 行（何の条件で・何回か。繰り返しはチャンネルの数も）。"""
        spam = spam_detection.SpamCheck(repeat=True, repeat_count=3, repeat_channels=2, flood=True, flood_count=8)
        lines = content_moderation._context_lines(spam, False, False)
        self.assertEqual(
            lines[:2],
            [
                "【スパム警告】直近60秒間に同じ内容を3回投稿しています（2チャンネル）。",
                "【スパム警告】直近10秒間に8回メッセージを送信しています。",
            ],
        )
        self.assertEqual(content_moderation._context_lines(spam_detection.SpamCheck(repeat_count=2), False, False), [])

    def test_the_log_lines_say_which_condition_hit(self):
        """ログの「スパム検出（…）」も、当たった条件ごとに 1 行。"""
        spam = spam_detection.SpamCheck(
            repeat=True, repeat_count=3, repeat_channels=2, flood=True, flood_count=8, min_interval=0.5
        )
        self.assertEqual(
            sec._spam_logs(spam),
            ["スパム検出（同じ内容を3回/60秒、2チャンネル）", "スパム検出（8回/10秒、最短間隔0.5秒）"],
        )

    def test_the_check_records_where_the_post_was(self):
        """検査はこの投稿の場所（チャンネル・メッセージの ID）と内容で数える（あとで消すため）。"""
        member = _member()
        message = _message(member, "同じ", message_id=4242, channel_id=55)
        self._check(message)
        posts = spam_detection._user_posts[(1, member.id)]
        self.assertEqual([(p.channel_id, p.message_id) for p in posts], [(55, 4242)])
        self.assertEqual(posts[0].key, spam_detection.content_key("同じ", []))


class VcRaidSpareRegularsTests(_SecurityCase):
    """S4: VC の荒らしは「入って間もない人」で見る。数に入った全員に措置し、常連は巻き込まない。"""

    def test_fresh_joiners_are_new_members_of_a_day_or_new_accounts(self):
        """入って 24 時間未満か、アカウントを作って 7 日未満。joined_at が無ければ数えない。"""
        self.assertTrue(sec.is_fresh_joiner(_member(joined_days_ago=0.9)))
        self.assertFalse(sec.is_fresh_joiner(_member(joined_days_ago=1.1)))
        self.assertTrue(sec.is_fresh_joiner(_member(uid=_snowflake(3), joined_days_ago=30)))
        self.assertFalse(sec.is_fresh_joiner(_member(uid=_snowflake(8), joined_days_ago=30)))
        self.assertFalse(sec.is_fresh_joiner(_member(uid=_snowflake(1), joined_days_ago=None)))

    def test_everyone_counted_is_timed_out_in_join_order(self):
        """5 人目で、数に入った全員を最初に入った順に 24 時間のタイムアウトし、1 人ずつ報告する。"""
        members = [_member(uid=10 + i, joined_days_ago=0.01) for i in range(5)]
        for member in members:
            self._join_vc(member)
        for member in members:
            member.timeout.assert_awaited_once_with(datetime.timedelta(seconds=86400), reason="セキュリティ違反")
        reports = [entry for entry in self.logged if entry.message == "VCレイド検出"]
        self.assertEqual([entry.user.id for entry in reports], [10, 11, 12, 13, 14])
        self.assertEqual(reports[0].fields, {"チャンネル": "<#777>", "タイムアウト": "24 時間"})

    def test_a_later_joiner_is_acted_on_and_nobody_twice(self):
        """同じ窓の中で後から入った人にも措置する。同じ人に二度は措置しない。"""
        members = [_member(uid=10 + i, joined_days_ago=0.01) for i in range(6)]
        for member in members:
            self._join_vc(member)
        self._join_vc(members[0])
        for member in members:
            member.timeout.assert_awaited_once()

    def test_old_members_are_not_counted_or_recorded(self):
        """入って間もなくない人は数えない（記録にも入れない）。"""
        for i in range(5):
            self._join_vc(_member(uid=10 + i, joined_days_ago=30))
        self.assertEqual(raid_detection._vc_join_history.get(777, []), [])
        self.assertEqual(self.logged, [])

    def test_a_failed_bypass_check_withholds_only_that_person(self):
        """バイパスの判定に失敗した人への措置は見送り（要確認のログ）、ほかの人への措置は止めない。"""

        def bypass(member):
            """ID 12 の人だけ判定に失敗する。"""
            return sec.BypassResult(False, "check_failed", True) if member.id == 12 else sec.BypassResult(False)

        members = [_member(uid=10 + i, joined_days_ago=0.01) for i in range(5)]
        for member in members:
            self._join_vc(member, bypass=bypass)
        members[2].timeout.assert_not_awaited()
        for member in members[:2] + members[3:]:
            member.timeout.assert_awaited_once()
        withheld = [entry for entry in self.logged if "要確認" in entry.message]
        self.assertEqual([entry.user.id for entry in withheld], [12])

    def test_a_regular_in_a_raided_vc_is_not_flagged(self):
        """荒らしの形の VC で発言しても、その人自身が数に入っていなければ VC_RAID にしない（常連を巻き込まない）。"""
        for i in range(5):
            raid_detection.check_vc_raid(SimpleNamespace(id=10 + i), 777)
        member = _member(voice_channel=777)
        message = _message(member)
        self._check(message)
        self.assertNotIn("VC_RAID", self._final().fields["理由"])
        message.delete.assert_not_awaited()
        member.timeout.assert_not_awaited()

    def test_a_counted_raider_is_flagged_but_not_acted_on_twice(self):
        """数に入った人の発言は VC_RAID。VC の経路で措置済みなので、投稿は消すがタイムアウトは二重にしない。"""
        for uid in (10, 11, 12, 13, 5):
            raid_detection.check_vc_raid(SimpleNamespace(id=uid), 777)
        member = _member(voice_channel=777)
        message = _message(member)
        self._check(message)
        final = self._final()
        self.assertIn("VC_RAID", final.fields["理由"])
        message.delete.assert_awaited_once()
        member.timeout.assert_not_awaited()
        self.assertEqual(final.fields["措置"], "消した（VC の荒らしで措置済み）")
        self.assertEqual(final.level, "ERROR")


class NewAccountTests(_SecurityCase):
    """S5: アカウントの作成日（ID から）も見る。新しいアカウントには NEW_ACCOUNT を付け、AI にも伝える。"""

    def test_the_account_age_comes_from_the_id(self):
        """作成から 7 日未満が新しいアカウント（ID の snowflake から。参加日時とは別）。"""
        self.assertTrue(sec.is_new_account(_member(uid=_snowflake(2))))
        self.assertTrue(sec.is_new_account(_member(uid=_snowflake(6.9))))
        self.assertFalse(sec.is_new_account(_member(uid=_snowflake(7.1))))
        self.assertFalse(sec.is_new_account(_member(uid=5)))

    def test_a_new_account_is_flagged_and_told_to_the_ai(self):
        """NEW_ACCOUNT の印・ログの行・AI に渡す材料（is_new_account）。新規メンバーの印は別のまま。"""
        member = _member(uid=_snowflake(2))
        assess = AsyncMock(return_value="SAFE")
        with (
            patch.object(sec, "gpt_assess", assess),
            patch.object(sec, "check_spam", lambda *args: spam_detection.SpamCheck()),
        ):
            logs: list = []
            findings = asyncio.run(sec._collect_findings(Mock(), 1, member, "はじめまして", [], [], logs))
        self.assertIn("NEW_ACCOUNT", findings.reason_flags)
        self.assertNotIn("NEW_MEMBER", findings.reason_flags)
        self.assertIn("新しいアカウント", logs)
        self.assertTrue(assess.await_args.kwargs["is_new_account"])
        self.assertEqual(sec.reason_icon("NEW_ACCOUNT"), "[ACCOUNT]")

    def test_the_ai_line_names_the_threshold(self):
        """AI に渡す文の「【新しいアカウント】…」の 1 行（日数は設定から）。"""
        lines = content_moderation._context_lines(spam_detection.SpamCheck(), False, True)
        self.assertEqual(lines, ["【新しいアカウント】このユーザーのアカウントは作成から7日未満です。"])


class LinkExtractionTests(unittest.TestCase):
    """S6: Discord の書き方（隠しリンク・括弧・飾りの記号・招待）を読み解いて URL を抜き出す。"""

    def test_a_masked_link_gives_only_the_url_inside(self):
        """隠しリンク [文](https://例) は括弧の中の URL だけ（以前は ) まで拾っていた。文の中の URL も拾わない）。"""
        links = sec.extract_links
        self.assertEqual(links("見て [公式](https://masked.example/p) だよ"), ["https://masked.example/p"])
        self.assertEqual(links("[https://shown.example](https://hidden.example/x)"), ["https://hidden.example/x"])
        self.assertEqual(links("[t](<https://angle.example/a>)"), ["https://angle.example/a"])
        wiki = "https://ja.wikipedia.org/wiki/Y_(Z)"
        self.assertEqual(links(f"[w]({wiki})"), [wiki])

    def test_closing_parens_and_brackets_are_dropped_only_when_unpaired(self):
        """末尾の ) ] は、URL の中の ( [ と対にならない分だけ落とす。"""
        wiki = "https://ja.wikipedia.org/wiki/X_(曖昧さ回避)"
        self.assertEqual(sec.normalize_url(wiki), wiki)
        self.assertEqual(sec.normalize_url("https://paren.example/a)"), "https://paren.example/a")
        self.assertEqual(sec.normalize_url("https://a.example/(x))"), "https://a.example/(x)")
        self.assertEqual(sec.normalize_url("https://bracket.example/b]"), "https://bracket.example/b")

    def test_discord_decorations_are_dropped_even_with_punctuation(self):
        """末尾の || ** __ ~~ * _ ` を落とす。句読点と組み合わさっても落ちきる。"""
        for raw in (
            "https://a.example/x||",
            "https://a.example/x**",
            "https://a.example/x__",
            "https://a.example/x~~",
            "https://a.example/x*",
            "https://a.example/x`",
            "https://a.example/x||.",
            "https://a.example/x**!?",
            "https://a.example/x).",
            "https://a.example/x>.",
        ):
            self.assertEqual(sec.normalize_url(raw), "https://a.example/x", raw)
        self.assertEqual(sec.normalize_url("https://a.example/x~"), "https://a.example/x~", "1 文字の ~ は飾りではない")
        self.assertEqual(sec.extract_links("||https://spoiler.example/a||"), ["https://spoiler.example/a"])

    def test_invites_without_a_scheme_are_picked_once(self):
        """招待は https:// が無くても拾い、https:// を付けた形にする。https:// 付きと重なったら 1 つ。"""
        text = "discord.gg/AbC123 と DISCORD.COM/invite/xyz と discordapp.com/INVITE/q-1 と https://discord.gg/AbC123"
        self.assertEqual(
            sec.extract_links(text),
            ["https://discord.gg/AbC123", "https://DISCORD.COM/invite/xyz", "https://discordapp.com/INVITE/q-1"],
        )
        self.assertEqual(sec.extract_links("http://discord.gg/abc"), ["http://discord.gg/abc"])
        self.assertEqual(sec.extract_links("[discord.gg/fake](https://real.example/x)"), ["https://real.example/x"])

    def test_other_names_and_bare_domains_are_not_picked(self):
        """別のドメインの一部の招待・www.・ドメインらしい文字列は拾わない（本人の決定）。日本語の直後の招待は拾う。"""
        text = "evil-discord.gg/abc mydiscord.gg/x www.example.com example.com/path 見てdiscord.gg/ok"
        self.assertEqual(sec.extract_links(text), ["https://discord.gg/ok"])

    def test_fullwidth_and_order_stay_as_before(self):
        """全角の https は拾わない。全角の句読点は URL の一部のまま。重複は 1 回、並びは出た順（いまの作法）。"""
        text = (
            "ｈｔｔｐｓ：／／ｆｕｌｌ．ｅｘａｍｐｌｅ と https://日本語.example/パス。 と "
            "[m](https://a.example) https://a.example."
        )
        self.assertEqual(sec.extract_links(text), ["https://日本語.example/パス。", "https://a.example"])


class BypassTests(_SecurityCase):
    """S7: 管理者は設定を読む前に飛ばす。飛ばしたことはログファイルにだけ書く。"""

    def test_an_administrator_is_skipped_without_reading_settings(self):
        """管理者は理由 administrator で飛ばす。設定は読まない（読めなくても飛ばす）。"""
        trusted = Mock(side_effect=RuntimeError("設定が読めない"))
        with patch.object(sec, "get_trusted_user_ids", trusted):
            result = sec.is_security_bypassed(_member(admin=True))
        self.assertEqual(result, sec.BypassResult(True, "administrator"))
        trusted.assert_not_called()

    def test_manage_guild_and_manage_messages_are_not_enough(self):
        """MANAGE_GUILD・MANAGE_MESSAGES の人は飛ばさない（_member は両方を持っている）。"""
        with (
            patch.object(sec, "get_trusted_user_ids", lambda g: []),
            patch.object(sec, "get_bypass_role_ids", lambda g: []),
        ):
            self.assertFalse(sec.is_security_bypassed(_member(admin=False)).bypassed)

    def test_a_skip_is_written_to_the_log_file_only(self):
        """飛ばしたら、ログチャンネルには何も出さず、ログファイルに理由つきで 1 行書く。"""
        message = _message(_member(admin=True), "https://a.example")
        with self.assertLogs(sec.logger, level="INFO") as captured:
            self._check(message, gpt="DANGEROUS")
        self.assertEqual(self.logged, [])
        self.assertEqual(self.sent, [])
        self.assertTrue(any("administrator" in line and "INFO" in line for line in captured.output), captured.output)

    def test_a_vc_skip_is_written_to_the_log_file_too(self):
        """VC の経路も同じ（数えず、ログファイルに 1 行）。"""
        member = _member(admin=True, joined_days_ago=0.01)
        with self.assertLogs(sec.logger, level="INFO") as captured:
            self._join_vc(member)
        self.assertEqual(raid_detection._vc_join_history.get(777, []), [])
        self.assertTrue(any("administrator" in line and "VC" in line for line in captured.output), captured.output)


class OutcomeHeadingTests(_SecurityCase):
    """S8: 結果の表示の見出しと色を、実際に取った措置から決める。"""

    def test_the_table(self):
        """決めた表のとおり（色は discord.py の Color の値）。"""
        day = sec.TimeoutResult(True, "timed_out", 86400)
        ten = sec.TimeoutResult(True, "timed_out", 600)
        removed = sec.StripResult(True, "removed")
        rows = [
            (sec.Enforcement("danger", 1, timeout=day), False, "消して 24 時間のタイムアウト", RED),
            (sec.Enforcement("danger", 1, stripped=removed), False, "消してロールを外した", RED),
            (sec.Enforcement("spam", 3, timeout=ten), False, "消して 10 分のタイムアウト", ORANGE),
            (sec.Enforcement("spam", 3), False, "消した", ORANGE),
            (sec.Enforcement("withheld"), True, "措置を見送った（要確認）", ORANGE),
            (sec.Enforcement(), True, "記録だけ（注意の材料あり）", GOLD),
            (sec.Enforcement(), False, "記録だけ（問題なし）", GREEN),
        ]
        for enforcement, caution, title, color in rows:
            self.assertEqual(sec.outcome_heading(enforcement, caution), (title, color), title)
        self.assertEqual(GOLD.value, 0xF1C40F)

    def test_a_partial_failure_is_marked_in_the_heading(self):
        """措置の一部が失敗したら（消せなかった・タイムアウトが断られた・外せないロール）「（一部失敗）」を足す。"""
        refused = sec.TimeoutResult(False, "forbidden", 86400)
        kept = sec.StripResult(False, "forbidden", (), (SimpleNamespace(id=11),))
        heading = sec.outcome_heading
        self.assertTrue(heading(sec.Enforcement("danger", 1, timeout=refused), False)[0].endswith("（一部失敗）"))
        self.assertTrue(heading(sec.Enforcement("danger", 1, stripped=kept), False)[0].endswith("（一部失敗）"))
        self.assertEqual(sec.outcome_heading(sec.Enforcement("spam", 2, 1), False)[0], "消した（一部失敗）")

    def test_the_caution_materials(self):
        """注意の材料は VirusTotal の疑わしい・AI の SUSPICIOUS/UNKNOWN・リンク過多・ユニコードトリック。"""
        for reasons, gpt in (
            (["VT_SUSPICIOUS"], "SAFE"),
            (["TOO_MANY_LINKS"], "SAFE"),
            (["UNICODE_TRICK"], "SAFE"),
            ([], "SUSPICIOUS"),
            ([], "UNKNOWN"),
        ):
            self.assertTrue(sec.has_caution(reasons, gpt), (reasons, gpt))
        self.assertFalse(sec.has_caution(["NEW_MEMBER", "NEW_ACCOUNT", "GPT:SAFE"], "SAFE"))

    def test_the_final_embed_follows_the_enforcement(self):
        """結果の Embed の題と色は措置から。判定の材料は、これまでどおり項目に並ぶ。"""
        enforcement = sec.Enforcement("danger", 1, timeout=sec.TimeoutResult(True, "timed_out", 86400))
        embed = sec.build_final_embed([], "DANGEROUS", ["GPT:DANGEROUS", "NEW_ACCOUNT"], ["ログ"], enforcement)
        self.assertEqual((embed.title, embed.color), ("消して 24 時間のタイムアウト", RED))
        self.assertEqual(embed.fields[-1].value, "[GPT]GPT:DANGEROUS / [ACCOUNT]NEW_ACCOUNT")
        plain = sec.build_final_embed([], "SAFE", ["VT_DANGEROUS"], ["ログ"])
        self.assertEqual((plain.title, plain.color), ("記録だけ（問題なし）", GREEN), "措置なしなら材料では赤にしない")

    def test_the_log_level_and_colour_follow_the_enforcement(self):
        """「メッセージセキュリティ検査」の水準と色も措置から（措置したら ERROR）。"""
        self._check(_message(_member()), gpt="SUSPICIOUS")
        self.assertEqual((self._final().level, self._final().color), ("INFO", GOLD))
        self.logged.clear()
        self._check(_message(_member(uid=6)), gpt="SAFE")
        self.assertEqual((self._final().level, self._final().color), ("INFO", GREEN))
        self.logged.clear()
        self._check(_message(_member(uid=7)), gpt="DANGEROUS")
        self.assertEqual((self._final().level, self._final().color), ("ERROR", RED))


if __name__ == "__main__":
    unittest.main()
