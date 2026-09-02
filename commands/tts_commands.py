import logging
from typing import Optional, cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin, is_admin
from commands.interaction_utils import (
    EMBED_DESCRIPTION_BUDGET,
    cap_list_for_message,
    send_ephemeral,
    send_interaction,
)
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
    """TTSを有効化するだけ。実際に読み上げが動くには watch チャンネルと
    VCチャンネルの設定（tts_add_watch/tts_vc）も別途要る。
    """
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    set_tts_enabled(interaction.guild.id, True)
    await send_ephemeral(interaction, "✅ TTS読み上げを有効にした。")


@tts_group.command(name="disable", description="TTS読み上げを無効にする")
async def tts_disable(interaction: discord.Interaction) -> None:
    """無効化するだけで、watch_channel_ids/vc_channel_id 等の設定は消さない。
    残しておくことで、再度 enable すれば同じ構成のまま復帰できる。
    """
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
    """set_tts_channels は watch_channel_ids と vc_channel_id を同時に丸ごと
    書き換える（services/tts_store.py参照）。ここで現在の vc_channel_id を
    読み戻してから渡さないと、watch を1件足しただけのつもりでVC設定が
    消えてしまう。
    """
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
    """tts_add_watch と同じ理由で vc_channel_id を読み戻してから渡す。
    watch_channel_ids に無い channel.id を指定してもリストは変わらず、
    エラーにもしない。
    """
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
    """tts_add_watch と同じ理由で watch_channel_ids を読み戻してから渡す
    （vc側だけを差し替えて、読み上げ対象チャンネルの設定を消さないため）。
    """
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    settings = get_tts_settings(interaction.guild.id)
    watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
    set_tts_channels(interaction.guild.id, watch_ids, channel.id)
    await send_ephemeral(interaction, f"✅ VCチャンネルを {channel.mention} に設定した。")


@tts_group.command(name="status", description="TTS設定の現在状況を表示する")
async def tts_status(interaction: discord.Interaction) -> None:
    """設定を変えない読み取り専用だが、ギルド全体の構成（監視チャンネル・
    VC・デフォルト声等）をそのまま出すため、一般ユーザーには見せず
    /tts の他コマンド同様に管理者限定にしている。自分個人の設定だけを
    見たい場合は /voice info を使わせる想定。
    """
    # /tts の他のコマンドと同じく管理者向け（ドキュメントにもそう書いてある）。
    if not await ensure_admin(interaction):
        return
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
    """VC参加自体は誰でも使える。管理者以外に録音の自動開始を許さない
    ガードの理由、defer の位置付けは本文コメント参照。
    """
    assert interaction.guild
    # VC接続（temp_join）、さらに管理者なら録音の自動開始判定も続けて行う。
    # どちらもDiscordとの往復を伴い、3秒の持ち時間を超えうるので先にdeferする
    # （/record start や /tts leave の録音締め処理と同じ考え方）。
    await interaction.response.defer(ephemeral=True, thinking=True)
    settings = get_tts_settings(interaction.guild.id)
    if not settings.get("enabled"):
        await send_ephemeral(interaction, "❌ TTS が無効。先に `/tts enable` で有効にせよ。")
        return
    # このアプリでは interaction.client は常に commands.Bot のインスタンス。
    bot = cast(Bot, interaction.client)
    await tts_service.temp_join(bot, interaction.guild, channel.id)

    # 読み上げと録音は独立したスイッチ。両方オンなら、こちらの入口から入っても
    # 録音が始まるようにする（人の入室イベントだけを入口にしていると、既に人が
    # いる VC へ手動で参加させたときに録音が始まらない）。
    #
    # ただし録音は管理者専用の機能（/record start も管理者限定）なので、
    # 誰でも打てるこのコマンドから始められるようにはしない。このガードが無いと、
    # 一般利用者が /tts join で録音を開始できてしまう。
    extra = ""
    if is_admin(interaction):
        from services import recording_service as recording

        await recording.maybe_start_for_channel(
            interaction.client,
            interaction.guild,
            channel,
            trigger="/tts join",
        )
        if recording.is_recording(interaction.guild.id):
            extra = "録音も始めた。"

    await send_ephemeral(
        interaction,
        f"✅ {channel.mention} に参加した。このVCのコメント欄を優先読み上げ中。{extra}"
        f"\n`/tts leave` で退出・元の設定に戻る。",
    )


@tts_group.command(name="leave", description="ボットをVCから退出させキューをクリアする（録音中なら締めてから退出）")
async def tts_leave(interaction: discord.Interaction) -> None:
    """録音停止の権限（/record stop は管理者限定）を、このコマンド経由で
    迂回させない分岐の理由は本文コメント参照。管理者以外は読み上げだけを
    切り、録音は続けさせる。
    """
    assert interaction.guild
    from services import recording_service as recording

    # 録音を止められるのは管理者だけ。誰でも打てるこのコマンドで録音を
    # 打ち切れると、/record stop の管理者限定を迂回できてしまう。
    # 管理者以外は読み上げだけ抜ける（接続は録音側が掴んでいるので切れない）。
    if not recording.is_recording(interaction.guild.id) or not is_admin(interaction):
        await tts_service.disconnect(interaction.guild.id)
        note = ""
        if recording.is_recording(interaction.guild.id):
            note = "\n※ 録音は続いている。止めるには管理者に `/record stop` を頼め。"
        await send_ephemeral(interaction, f"✅ 読み上げを止めた。{note}")
        return

    # 録音中に黙って抜けると、そこまで録った分が宙に浮く。締めてリンクを出す。
    # 書き出し（ffmpeg と ZIP 化）に時間がかかるので defer しておく。
    await interaction.response.defer(thinking=True)
    try:
        result = await recording.stop_recording(
            interaction.client,
            interaction.guild.id,
            reason="/tts leave で退出",
        )
    except recording.RecordingError as e:
        await tts_service.disconnect(interaction.guild.id)
        await interaction.followup.send(f"✅ VCから退出した。ただし録音の書き出しに失敗した（{e}）")
        return

    await tts_service.disconnect(interaction.guild.id)
    await interaction.followup.send(
        content="✅ VCから退出した。録音も締めた。",
        embed=recording.build_result_embed(interaction.guild.id, result),
    )


@tts_group.command(name="default_voice", description="サーバーのデフォルト声を設定する")
@app_commands.describe(voice="声の名前（例: Kyoko）")
async def tts_default_voice_cmd(
    interaction: discord.Interaction,
    voice: str,
) -> None:
    """空白のみの入力を弾く理由は本文コメント参照（空文字が保存されると
    settings.get("default_voice", ...) の既定値フォールバックが効かなく
    なり、空の声設定のまま残ってしまう）。
    """
    if not await ensure_admin(interaction):
        return
    assert interaction.guild
    voice = voice.strip()
    # 空白のみだと空文字が保存され、以後 settings.get("default_voice", ...) は
    # キーが存在する扱いになって既定値へフォールバックせず、空の声設定のまま残る。
    if not voice:
        await send_ephemeral(interaction, "❌ 声の名前は空白のみでは指定できぬ。")
        return
    set_tts_default_voice(interaction.guild.id, voice)
    await send_ephemeral(interaction, f"✅ デフォルト声を `{voice}` に設定した。")


@tts_default_voice_cmd.autocomplete("voice")
async def _voice_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[app_commands.Choice[str]]:
    """入力中の文字列に対し、前方一致ではなく部分一致で候補を絞り込む
    （声の名前は先頭が揃っていないことが多いため）。Discordのautocomplete
    表示上限が25件なので、絞り込み後さらに先頭25件で打ち切る。
    """
    voices = await tts_service.fetch_voices()
    return [app_commands.Choice(name=v, value=v) for v in voices if current.lower() in v.lower()][:25]


@tts_group.command(name="read_name", description="メッセージ読み上げ時に発言者名を読み上げるか設定する")
@app_commands.describe(enabled="on で名前あり、off で名前なし")
@app_commands.choices(
    enabled=[
        app_commands.Choice(name="on（名前を読み上げる）", value="on"),
        app_commands.Choice(name="off（名前を読み上げない）", value="off"),
    ]
)
async def tts_read_name_cmd(
    interaction: discord.Interaction,
    enabled: str,
) -> None:
    """bool ではなく on/off の choice にしているのは、Discord UI 上で
    bool 引数は "True"/"False" としか表示されず分かりにくいため
    （record/config.py の auto コマンドは同じ用途に bool を直接使っており、
    ここはUI表示を優先して意図的に choice にしている）。
    """
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
    """範囲チェック(100〜400)は voice_set 側にも同じものが別途あり、
    共有はしていない（デフォルト速度用とユーザー個別速度用で別のバリデーション
    箇所を持つ）。
    """
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
    """voice・rate はどちらか一方だけの指定も許す（両方 None のときだけ拒否）。
    stripする理由は本文コメント参照。
    """
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    # 他のvoice系コマンド（tts default_voice等）と同じくstripする。ここだけ
    # stripしないと、空白だけの入力がそのまま声設定として保存されてしまう。
    if voice is not None:
        voice = voice.strip() or None
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
    """_voice_autocomplete と全く同じ絞り込みロジック。discord.py の
    autocomplete はコマンドごとに紐付ける必要があり、voice_set 用として
    別関数にしているためコードは重複している（機能上の問題は無い）。
    """
    voices = await tts_service.fetch_voices()
    return [app_commands.Choice(name=v, value=v) for v in voices if current.lower() in v.lower()][:25]


@voice_group.command(name="reset", description="自分の読み上げ設定をデフォルトに戻す")
async def voice_reset(interaction: discord.Interaction) -> None:
    """個別設定を消すだけで、以後はサーバーの default_voice/default_rate へ
    自動的にフォールバックする（voice_info の優先順位参照）。
    """
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    reset_user_tts_settings(interaction.guild.id, interaction.user.id)
    await send_ephemeral(interaction, "✅ 声設定をリセットした。")


@voice_group.command(name="info", description="自分の現在の読み上げ設定を表示する")
async def voice_info(interaction: discord.Interaction) -> None:
    """声・速度の優先順位はユーザー個別設定 → サーバーのデフォルト →
    ハードコードの既定値(_DEFAULT_VOICE/_DEFAULT_RATE)。has_custom は
    user_cfg の有無だけで判定するため、voice/rateのどちらか一方しか
    個別設定していなくても「カスタム設定あり」と表示される。
    """
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
    """空白のみの単語・読みを弾く理由、strip前の長さで判定してはいけない
    理由は本文コメント参照。
    """
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    word = word.strip()
    reading = reading.strip()
    # strip前の長さで判定すると、空白だけの入力("　"等)が長さチェックを通り抜けて
    # 空文字キーとして登録されてしまう（読み上げ時に何にでもマッチしてしまう）。
    if not word or not reading:
        await send_ephemeral(interaction, "❌ 単語・読みのいずれも空白のみは指定できぬ。")
        return
    if len(word) > 50 or len(reading) > 100:
        await send_ephemeral(interaction, "❌ 単語は50文字以内、読みは100文字以内にせよ。")
        return
    add_tts_dictionary_entry(interaction.guild.id, word, reading)
    await send_ephemeral(interaction, f"✅ `{word}` → `{reading}` を辞書に登録した。")


@dict_group.command(name="remove", description="辞書からエントリを削除する")
@app_commands.describe(word="削除する単語")
async def dict_remove(
    interaction: discord.Interaction,
    word: str,
) -> None:
    """remove_tts_dictionary_entry の bool 戻り値で存在有無を判定し、
    無かった場合と削除できた場合とでメッセージを分ける。
    """
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
    """辞書をembedで一覧表示する。文字数予算ベースで打ち切る理由（件数だけ
    で打ち切ると embed の description 上限を超えうる）は本文コメント参照。
    """
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return
    d = get_tts_dictionary(interaction.guild.id)
    if not d:
        await send_ephemeral(interaction, "辞書は空だ。")
        return
    items = list(d.items())
    lines = [f"`{w}` → `{r}`" for w, r in items]
    # word は最大50文字・readingは最大100文字まで許容している（dict_add参照）ため、
    # 単純に件数だけで打ち切ると1行が最大約160文字になり、embedのdescription
    # 上限(4096文字)を超えて送信自体が失敗しうる。文字数予算ベースで打ち切る
    # （一覧の打ち切りはcap_list_for_messageに一本化しており、ここだけ別実装を
    # 持たない）。
    description = cap_list_for_message(lines, budget=EMBED_DESCRIPTION_BUDGET, omitted_unit="件")
    embed = discord.Embed(
        title="TTS 辞書",
        description=description,
        color=discord.Color.blue(),
    )
    await send_interaction(interaction, embed=embed, ephemeral=True)


def register_tts_commands(bot: Bot) -> None:
    """/tts・/voice・/dict の3グループを bot.tree に登録する。各サブコマンドは
    モジュールレベルで @tts_group.command 等として既に定義済みなので、ここ
    ではグループそのものを足すだけでよい。
    """
    bot.tree.add_command(tts_group)
    bot.tree.add_command(voice_group)
    bot.tree.add_command(dict_group)
