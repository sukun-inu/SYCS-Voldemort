from collections.abc import Callable
from dataclasses import dataclass

from discord.ext.commands import Bot

from commands.djaudio_commands import register_djaudio_commands
from commands.logging_commands import register_logging_commands
from commands.metal_commands import register_metal_commands
from commands.server_commands import register_server_commands
from commands.tts_commands import register_tts_commands

CommandRegistrar = Callable[[Bot], None]


@dataclass(frozen=True)
class CommandModule:
    name: str
    register: CommandRegistrar


COMMAND_MODULES: tuple[CommandModule, ...] = (
    CommandModule("metal", register_metal_commands),
    CommandModule("logging", register_logging_commands),
    CommandModule("server", register_server_commands),
    CommandModule("djaudio", register_djaudio_commands),
    CommandModule("tts", register_tts_commands),
)


def register_all_commands(bot: Bot) -> list[str]:
    loaded: list[str] = []
    for module in COMMAND_MODULES:
        module.register(bot)
        loaded.append(module.name)
    return loaded
