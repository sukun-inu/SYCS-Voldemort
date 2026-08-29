import discord
from discord.ext import commands
from discord.ext.commands import Bot

from events import background_tasks, members, messages, reactions, ready, voice
from events.state import EventState


def create_bot() -> Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    intents.voice_states = True
    intents.moderation = True
    intents.reactions = True
    return commands.Bot(command_prefix="!", intents=intents)


def setup_events(bot: Bot) -> None:
    """イベントハンドラ・背景タスクをまとめて bot へ登録する。

    以前はここが 1,210 行の単一クロージャだった。ヘルパー・背景タスク・
    12個のイベントハンドラが全部ローカル変数を nonlocal で共有しており、
    分割もテストも無いまま積み上がっていた。実体は events/ 以下へ
    関心ごとに切り出し（詳細は events/__init__.py）、ここでは
    モジュールをまたいで共有する状態を1つ作って各 register() へ順に
    渡すだけにしてある。
    """
    state = EventState()
    loops = background_tasks.register(bot, state)
    ready.register(bot, state, loops)
    messages.register(bot)
    voice.register(bot)
    members.register(bot)
    reactions.register(bot)
