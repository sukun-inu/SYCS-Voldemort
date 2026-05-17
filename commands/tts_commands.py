import logging
from typing import Optional

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin
from commands.interaction_utils import send_ephemeral, send_interaction
from services import tts_service
from services.tts_store import (
    add_tts_dictionary_entry,
    get_tts_dictionary,
    get_tts_settings,
    get_user_tts_settings,
    remove_tts_dictionary_entry,
    reset_user_tts_settings,
    set_tts_channels,
    set_tts_default_rate,
    set_tts_default_voice,
    set_tts_enabled,
    set_tts_read_name,
    set_user_tts_settings,
)

logger = logging.getLogger(__name__)

_DEFAULT_VOICE = "Kyoko"
_DEFAULT_RATE = 200


# ============================================================
# /tts グループ（管理者専用）
# ============================================================
tts_group = app_commands.Group(name="tts", description="TTS読み上げ設定（管理者専用）")


@tts_group.command(name="enable", description="TTS読み上げを有効にする")
async def tts_enable(interaction: discord.Interaction) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    set_tts_enabled(interaction.guild.id, True)
    await send_ephemeral(interaction, "✅ TTS読み上げを有効にした。")


@tts_group.command(name="disable", description="TTS読み上げを無効にする")
async def tts_disable(interaction: discord.Interaction) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    set_tts_enabled(interaction.guild.id, False)
    await send_ephemeral(interaction, "❌ TTS読み上げを無効にした。")


@tts_group.command(name="add_watch", description="読み上げ対象のテキストチャンネルを追加する")
@app_commands.describe(channel="読み上げるテキストチャンネル")
async def tts_add_watch(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    settings = get_tts_settings(interaction.guild.id)
    watch_ids: list[int] = [int(cid) for cid in settings.get("watch_channel_ids", [])]
    if channel.id not in watch_ids:
        watch_ids.append(channel.id)
    set_tts_channels(interaction.guild.id, watch_ids, settings.get("vc_channel_id"))
    await send_ephemeral(interaction, f"✅ {channel.mention} を読み上げ対象に追加した。")


@tts_group.command(name="remove_watch", description="読み上げ対象からテキストチャンネルを削除する")
@app_commands.describe(channel="削除するテキストチャンネル")
async def tts_remove_watch(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    settings = get_tts_settings(interaction.guild.id)
    watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", []) if int(cid) != channel.id]
    set_tts_channels(interaction.guild.id, watch_ids, settings.get("vc_channel_id"))
    await send_ephemeral(interaction, f"✅ {channel.mention} を読み上げ対象から削除した。")


@tts_group.command(name="vc", description="ボットが参加するVCチャンネルを設定する")
@app_commands.describe(channel="ボットが参加するVCチャンネル")
async def tts_vc(
    interaction: discord.Interaction,
    channel: discord.VoiceChannel,
) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    settings = get_tts_settings(interaction.guild.id)
    watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
    set_tts_channels(interaction.guild.id, watch_ids, channel.id)
    await send_ephemeral(interaction, f"✅ VCチャンネルを {channel.mention} に設定した。")


@tts_group.command(name="status", description="TTS設定の現在状況を表示する")
async def tts_status(interaction: discord.Interaction) -> None:
    assert interaction.guild
    guild = interaction.guild
    settings = get_tts_settings(guild.id)

    enabled = settings.get("enabled", False)
    watch_ids = settings.get("watch_channel_ids", [])
    vc_id = settings.get("vc_channel_id")
    default_voice = settings.get("default_voice", _DEFAULT_VOICE)
    default_rate = settings.get("default_rate", _DEFAULT_RATE)
    dict_count = len(get_tts_dictionary(guild.id))

    watch_mentions = []
    for cid in watch_ids:
        ch = guild.get_channel(int(cid))
        watch_mentions.append(ch.mention if ch else f"（不明: {cid}）")

    vc_ch = guild.get_channel(int(vc_id)) if vc_id else None
    vc_mention = vc_ch.mention if vc_ch else "未設定"

    embed = discord.Embed(
        title="TTS 設定状況",
        color=discord.Color.green() if enabled else discord.Color.red(),
    )
    embed.add_field(name="状態", value="✅ 有効" if enabled else "❌ 無効", inline=False)
    embed.add_field(
        name="読み上げチャンネル",
        value="\n".join(watch_mentions) if watch_mentions else "未設定",
        inline=False,
    )
    read_name = settings.get("read_name", True)
    embed.add_field(name="VCチャンネル", value=vc_mention, inline=True)
    embed.add_field(name="デフォルト声", value=str(default_voice), inline=True)
    embed.add_field(name="デフォルト速度", value=str(default_rate), inline=True)
    embed.add_field(name="名前読み上げ", value="✅ あり" if read_name else "❌ なし", inline=True)
    embed.add_field(name="辞書登録数", value=str(dict_count), inline=True)
    await send_interaction(interaction, embed=embed, ephemeral=True)


@tts_group.command(name="join", description="指定したVCに参加し、そのVCのコメント欄を優先読み上げ対象にする")
@app_commands.describe(channel="参加するVCチャンネル")
async def tts_join(
    interaction: discord.Interaction,
    channel: discord.VoiceChannel,
) -> None:
    assert interaction.guild
    settings = get_tts_settings(interaction.guild.id)
    if not settings.get("enabled"):
        await send_ephemeral(interaction, "❌ TTS が無効。先に `/tts enable` で有効にせよ。")
        return
    await tts_service.temp_join(interaction.client, interaction.guild, channel.id)
    await send_ephemeral(
        interaction,
        f"✅ {channel.mention} に参加した。このVCのコメント欄を優先読み上げ中。\n`/tts leave` で退出・元の設定に戻る。",
    )


@tts_group.command(name="leave", description="ボットをVCから退出させキューをクリアする（temp join 中なら元の設定に戻る）")
async def tts_leave(interaction: discord.Interaction) -> None:
    assert interaction.guild
    await tts_service.disconnect(interaction.guild.id)
    await send_ephemeral(interaction, "✅ VCから退出した。")


@tts_group.command(name="default_voice", description="サーバーのデフォルト声を設定する")
@app_commands.describe(voice="声の名前（例: Kyoko）")
async def tts_default_voice_cmd(
    interaction: discord.Interaction,
    voice: str,
) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    set_tts_default_voice(interaction.guild.id, voice.strip())
    await send_ephemeral(interaction, f"✅ デフォルト声を `{voice}` に設定した。")


@tts_default_voice_cmd.autocomplete("voice")
async def _voice_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[app_commands.Choice[str]]:
    voices = await tts_service.fetch_voices()
    return [
        app_commands.Choice(name=v, value=v)
        for v in voices
        if current.lower() in v.lower()
    ][:25]


@tts_group.command(name="read_name", description="メッセージ読み上げ時に発言者名を読み上げるか設定する")
@app_commands.describe(enabled="on で名前あり、off で名前なし")
@app_commands.choices(enabled=[
    app_commands.Choice(name="on（名前を読み上げる）", value="on"),
    app_commands.Choice(name="off（名前を読み上げない）", value="off"),
])
async def tts_read_name_cmd(
    interaction: discord.Interaction,
    enabled: str,
) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    read_name = enabled == "on"
    set_tts_read_name(interaction.guild.id, read_name)
    if read_name:
        await send_ephemeral(interaction, "✅ 発言者名を読み上げるようにした。")
    else:
        await send_ephemeral(interaction, "✅ 発言者名を読み上げないようにした。")


@tts_group.command(name="default_rate", description="サーバーのデフォルト読み上げ速度を設定する（100〜400）")
@app_commands.describe(rate="速度（100〜400語/分）")
async def tts_default_rate_cmd(
    interaction: discord.Interaction,
    rate: int,
) -> None:
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    if not (100 <= rate <= 400):
        await send_ephemeral(interaction, "❌ 速度は100〜400の範囲で指定せよ。")
        return
    set_tts_default_rate(interaction.guild.id, rate)
    await send_ephemeral(interaction, f"✅ デフォルト速度を `{rate}` に設定した。")


# ============================================================
# /voice グループ（全ユーザー）
# ============================================================
voice_group = app_commands.Group(name="voice", description="自分のTTS声設定")


@voice_group.command(name="set", description="自分の読み上げ声と速度を設定する")
@app_commands.describe(
    voice="声の名前（例: Kyoko）",
    rate="読み上げ速度（100〜400語/分）",
)
async def voice_set(
    interaction: discord.Interaction,
    voice: Optional[str] = None,
    rate: Optional[int] = None,
) -> None:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    if voice is None and rate is None:
        await send_ephemeral(interaction, "❌ voice か rate のどちらかを指定せよ。")
        return
    if rate is not None and not (100 <= rate <= 400):
        await send_ephemeral(interaction, "❌ 速度は100〜400の範囲で指定せよ。")
        return
    set_user_tts_settings(interaction.guild.id, interaction.user.id, voice=voice, rate=rate)
    parts = []
    if voice:
        parts.append(f"声: `{voice}`")
    if rate:
        parts.append(f"速度: `{rate}`")
    await send_ephemeral(interaction, f"✅ 声設定を更新した（{', '.join(parts)}）。")


@voice_set.autocomplete("voice")
async def _voice_set_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[app_commands.Choice[str]]:
    voices = await tts_service.fetch_voices()
    return [
        app_commands.Choice(name=v, value=v)
        for v in voices
        if current.lower() in v.lower()
    ][:25]


@voice_group.command(name="reset", description="自分の読み上げ設定をデフォルトに戻す")
async def voice_reset(interaction: discord.Interaction) -> None:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    reset_user_tts_settings(interaction.guild.id, interaction.user.id)
    await send_ephemeral(interaction, "✅ 声設定をリセットした。")


@voice_group.command(name="info", description="自分の現在の読み上げ設定を表示する")
async def voice_info(interaction: discord.Interaction) -> None:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    server_settings = get_tts_settings(interaction.guild.id)
    user_cfg = get_user_tts_settings(interaction.guild.id, interaction.user.id)

    voice = user_cfg.get("voice") or server_settings.get("default_voice") or _DEFAULT_VOICE
    rate = user_cfg.get("rate") or server_settings.get("default_rate") or _DEFAULT_RATE
    has_custom = bool(user_cfg)

    embed = discord.Embed(title="貴様の声設定", color=discord.Color.blurple())
    embed.add_field(name="声", value=str(voice), inline=True)
    embed.add_field(name="速度", value=str(rate), inline=True)
    embed.add_field(
        name="カスタム設定",
        value="✅ あり（個別設定）" if has_custom else "❌ なし（サーバーデフォルト）",
        inline=False,
    )
    await send_interaction(interaction, embed=embed, ephemeral=True)


# ============================================================
# /dict グループ（全ユーザー）
# ============================================================
dict_group = app_commands.Group(name="dict", description="TTS読み上げ辞書")


@dict_group.command(name="add", description="辞書にエントリを追加する（単語を別の読みに置き換え）")
@app_commands.describe(word="置換する単語（最大50文字）", reading="読み替え後のテキスト（最大100文字）")
async def dict_add(
    interaction: discord.Interaction,
    word: str,
    reading: str,
) -> None:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    if len(word) > 50 or len(reading) > 100:
        await send_ephemeral(interaction, "❌ 単語は50文字以内、読みは100文字以内にせよ。")
        return
    add_tts_dictionary_entry(interaction.guild.id, word.strip(), reading.strip())
    await send_ephemeral(interaction, f"✅ `{word}` → `{reading}` を辞書に登録した。")


@dict_group.command(name="remove", description="辞書からエントリを削除する")
@app_commands.describe(word="削除する単語")
async def dict_remove(
    interaction: discord.Interaction,
    word: str,
) -> None:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    removed = remove_tts_dictionary_entry(interaction.guild.id, word.strip())
    if removed:
        await send_ephemeral(interaction, f"✅ `{word}` を辞書から削除した。")
    else:
        await send_ephemeral(interaction, f"❌ `{word}` は辞書に存在しない。")


@dict_group.command(name="list", description="辞書の一覧を表示する")
async def dict_list(interaction: discord.Interaction) -> None:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    d = get_tts_dictionary(interaction.guild.id)
    if not d:
        await send_ephemeral(interaction, "辞書は空だ。")
        return
    items = list(d.items())
    lines = [f"`{w}` → `{r}`" for w, r in items[:50]]
    if len(items) > 50:
        lines.append(f"... 他 {len(items) - 50} 件")
    embed = discord.Embed(
        title="TTS 辞書",
        description="\n".join(lines),
        color=discord.Color.blue(),
    )
    await send_interaction(interaction, embed=embed, ephemeral=True)


def register_tts_commands(bot: Bot) -> None:
    bot.tree.add_command(tts_group)
    bot.tree.add_command(voice_group)
    bot.tree.add_command(dict_group)
