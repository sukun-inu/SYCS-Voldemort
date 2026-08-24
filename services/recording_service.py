"""VC録音（Craig の代わり）。ユーザーごとに別トラックで録る。

仕組み:
  discord.py 本体に音声受信は無いので、discord-ext-voice-recv の
  VoiceRecvClient を使う。これは discord.VoiceClient のサブクラスで送信
  （読み上げ）と受信（録音）を同時に持てるため、接続は services/voice_session.py
  で TTS と共有する。録音中は voice_session の hold を立て、TTS 側の
  「VCが空になったら切る」で接続ごと落とされないようにする。

トラックの作り方:
  受信できるのは「誰かが喋っているあいだの音声パケット」だけで、黙っている
  あいだは何も来ない。素直に繋ぐと無音が詰まってトラック同士がずれるため、
  録音開始からの経過時間を基準に、足りない分を無音で埋めてから書く。結果、
  全トラックが同じ長さ・同じ時間軸に揃い、そのまま重ねて編集できる。

  PCM をそのままディスクに置くと 1人あたり毎時 約690MB になるので、
  ユーザーごとに ffmpeg を1つ立ち上げ、パイプへ流しながら mp3 にする。
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import discord

from config import DJAUDIO_FFMPEG_PATH, JST as _JST
from services import voice_session
from services.djaudio_cache import register_file

logger = logging.getLogger(__name__)

# Discord の音声は 48kHz / 2ch / 16bit 固定
SAMPLE_RATE = 48000
CHANNELS = 2
SAMPLE_WIDTH = 2
BYTES_PER_SECOND = SAMPLE_RATE * CHANNELS * SAMPLE_WIDTH
FRAME_BYTES = 3840  # 20ms
_SILENCE_CHUNK = b"\x00" * (BYTES_PER_SECOND // 10)  # 100ms

_MAX_PAD_SECONDS = 3600 * 8  # これを超える穴埋めは異常値として切り捨てる

# max_minutes に 0 を指定すると「時間では止めない」。VC が無人になるまで録り続ける。
UNLIMITED = 0
_GUARD_INTERVAL_SEC = 15.0
_EMPTY_GRACE_SEC = 20.0   # 開始直後は参加者のキャッシュが揃っていないことがある

# guild_id -> RecordingSession
_sessions: dict[int, "RecordingSession"] = {}


class RecordingError(RuntimeError):
    """利用者にそのまま見せてよいエラー。"""


# ── トラック1本 ───────────────────────────────────────────────

class _TrackWriter:
    """1ユーザー分の音声を、無音で位置合わせしながら mp3 へ書く。"""

    def __init__(self, user_id: int, display_name: str, out_path: Path, started_at: float):
        self.user_id = user_id
        self.display_name = display_name
        self.out_path = out_path
        self.started_at = started_at
        self.written_bytes = 0
        self.voiced_bytes = 0          # 実際に声が入っていた分（無音埋めを除く）
        self.failed = False
        self._process = subprocess.Popen(
            [
                DJAUDIO_FFMPEG_PATH, "-hide_banner", "-loglevel", "error",
                "-f", "s16le", "-ar", str(SAMPLE_RATE), "-ac", str(CHANNELS),
                "-i", "pipe:0",
                "-c:a", "libmp3lame", "-q:a", "5",
                str(out_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def _raw(self, payload: bytes) -> None:
        if self.failed or self._process.stdin is None:
            return
        try:
            self._process.stdin.write(payload)
            self.written_bytes += len(payload)
        except (BrokenPipeError, OSError) as e:
            self.failed = True
            logger.warning("[recording] トラック書き込み失敗 user=%s: %s", self.user_id, e)

    def pad_until(self, elapsed: float) -> None:
        """録音開始から elapsed 秒の位置まで無音で埋める。"""
        target = int(elapsed * BYTES_PER_SECOND)
        target -= target % FRAME_BYTES
        gap = target - self.written_bytes
        if gap <= 0:
            return
        if gap > _MAX_PAD_SECONDS * BYTES_PER_SECOND:
            logger.warning("[recording] 異常な無音幅を切り詰めます user=%s gap=%s", self.user_id, gap)
            gap = _MAX_PAD_SECONDS * BYTES_PER_SECOND
        while gap > 0 and not self.failed:
            chunk = _SILENCE_CHUNK if gap >= len(_SILENCE_CHUNK) else b"\x00" * gap
            self._raw(chunk)
            gap -= len(chunk)

    def write(self, pcm: bytes, elapsed: float) -> None:
        self.pad_until(elapsed)
        self._raw(pcm)
        self.voiced_bytes += len(pcm)

    def close(self, total_elapsed: float, timeout: float = 60.0) -> None:
        """末尾まで無音で埋めてから ffmpeg を終わらせる。"""
        self.pad_until(total_elapsed)
        if self._process.stdin is not None:
            try:
                self._process.stdin.close()
            except OSError:
                pass
        try:
            _, stderr = self._process.communicate(timeout=timeout)
            if self._process.returncode not in (0, None) and stderr:
                logger.warning(
                    "[recording] ffmpeg 終了コード %s user=%s: %s",
                    self._process.returncode, self.user_id, stderr.decode("utf-8", "replace")[:300],
                )
        except subprocess.TimeoutExpired:
            logger.warning("[recording] ffmpeg が終了しないため強制終了 user=%s", self.user_id)
            self._process.kill()

    @property
    def voiced_seconds(self) -> float:
        return self.voiced_bytes / BYTES_PER_SECOND


# ── Sink ─────────────────────────────────────────────────────

def _make_sink_class():
    """AudioSink の実装を返す。受信拡張が無い環境では import 自体ができない。"""
    from discord.ext import voice_recv

    class _RecordingSink(voice_recv.AudioSink):
        """Opus のまま受け取り、自前でデコードする。

        wants_opus() を False にするとライブラリ側がデコードするが、そこで
        1つでも壊れたパケットに当たると OpusError が上がり、受信スレッドごと
        落ちて stop_listening() まで呼ばれる（router.py の run/finally）。
        つまり壊れたパケット1個で録音が黙って止まる。

        こちらでデコードすれば、そのパケットを捨てて先へ進める。取りこぼしは
        無音として扱われるが、トラックの位置合わせは経過時間を基準にしている
        ので、ずれではなく短い欠落になるだけで済む。
        """

        def __init__(self, session: "RecordingSession"):
            super().__init__()
            self.session = session
            self._decoders: dict[int, "discord.opus.Decoder"] = {}

        def wants_opus(self) -> bool:
            return True

        def _decoder_for(self, user_id: int):
            decoder = self._decoders.get(user_id)
            if decoder is None:
                from discord.opus import Decoder
                decoder = Decoder()
                self._decoders[user_id] = decoder
            return decoder

        def write(self, user, data) -> None:
            # voice_recv の受信スレッドから呼ばれる。ここでイベントループには触らない。
            if user is None:
                return
            encoded = data.opus
            if not encoded:
                return

            user_id = int(getattr(user, "id", 0) or 0)
            if not user_id or user_id in self.session.excluded_user_ids:
                return

            try:
                pcm = self._decoder_for(user_id).decode(encoded, fec=False)
            except Exception:
                # 壊れたパケットは捨てて続ける。毎回ログを出すと洪水になるので
                # 数だけ数え、停止時にまとめて残す。
                self.session.dropped_packets += 1
                return

            self.session.feed(user, pcm)

        def cleanup(self) -> None:
            self._decoders.clear()

    return _RecordingSink


# ── セッション ────────────────────────────────────────────────

@dataclass
class RecordingSession:
    guild_id: int
    channel_id: int
    channel_name: str
    started_by_id: int
    started_by_name: str
    started_at: float
    max_seconds: int
    retention_days: int
    excluded_user_ids: set[int] = field(default_factory=set)
    workdir: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="rec-")))
    tracks: dict[int, _TrackWriter] = field(default_factory=dict)
    stopping: bool = False
    dropped_packets: int = 0     # デコードできず捨てたパケット数
    announce_message: discord.Message | None = None
    _guard_task: asyncio.Task | None = None

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def is_unlimited(self) -> bool:
        """時間では止めない設定か（VC が無人になるまで録り続ける）。"""
        return self.max_seconds <= 0

    @property
    def output_bytes(self) -> int:
        total = 0
        for track in self.tracks.values():
            try:
                total += track.out_path.stat().st_size
            except OSError:
                continue
        return total

    def feed(self, user, pcm: bytes) -> None:
        if self.stopping or not pcm:
            return
        user_id = int(getattr(user, "id", 0) or 0)
        if not user_id or user_id in self.excluded_user_ids:
            return

        track = self.tracks.get(user_id)
        if track is None:
            display = getattr(user, "display_name", None) or getattr(user, "name", None) or str(user_id)
            index = len(self.tracks) + 1
            safe = "".join(c for c in str(display) if c.isalnum() or c in " ._-()").strip()[:40]
            out = self.workdir / f"{index:02d}-{safe or user_id}.mp3"
            try:
                track = _TrackWriter(user_id, str(display), out, self.started_at)
            except Exception as e:
                logger.exception("[recording] トラックを開始できません user=%s: %s", user_id, e)
                return
            self.tracks[user_id] = track
            logger.info("[recording] guild=%s トラック追加: %s", self.guild_id, display)

        track.write(pcm, self.elapsed)

    def status(self) -> dict:
        return {
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "channel_name": self.channel_name,
            "started_by": self.started_by_name,
            "started_at": self.started_at,
            "elapsed_seconds": int(self.elapsed),
            "max_seconds": self.max_seconds,
            "unlimited": self.is_unlimited,
            "speakers": [
                {"user_id": t.user_id, "name": t.display_name,
                 "voiced_seconds": round(t.voiced_seconds, 1)}
                for t in self.tracks.values()
            ],
            "output_bytes": self.output_bytes,
            "dropped_packets": self.dropped_packets,
            "excluded": sorted(self.excluded_user_ids),
        }


# ── 開始 / 停止 ───────────────────────────────────────────────

# 管理画面は Bot とは別プロセスなので、メモリ上の状態が見えない。
# 開始・停止のたびに共有ディレクトリへ書き出して、そちらから読めるようにする
# （開発者パネルのシグナルと同じ考え方）。
def _state_file() -> Path:
    import os
    base = Path(os.getenv("SETTINGS_DIR", str(Path(__file__).resolve().parent.parent / "data")))
    return base / "_recording_state.json"


def _write_state() -> None:
    try:
        path = _state_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": time.time(),
            "sessions": {str(s.guild_id): s.status() for s in _sessions.values()},
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as e:
        logger.warning("[recording] 状態ファイルを書けませんでした: %s", e)


def read_state() -> dict:
    """管理画面から読む用。Bot 側が書いた状態をそのまま返す。"""
    try:
        return json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"updated_at": 0, "sessions": {}}


def get_session(guild_id: int) -> RecordingSession | None:
    return _sessions.get(guild_id)


def is_recording(guild_id: int) -> bool:
    return guild_id in _sessions


def active_sessions() -> list[dict]:
    return [s.status() for s in _sessions.values()]


async def start_recording(
    bot,
    guild: discord.Guild,
    channel: discord.VoiceChannel,
    *,
    started_by: discord.abc.User,
    announce_to: discord.abc.Messageable | None = None,
) -> RecordingSession:
    """録音を開始する。既に録音中なら RecordingError。"""
    from services.settings_store import get_recording_settings

    if not voice_session.RECEIVE_AVAILABLE:
        raise RecordingError(
            "この環境では音声を受信できないため録音できません"
            f"（{voice_session.receive_unavailable_reason() or 'discord-ext-voice-recv が未導入'}）。"
        )
    if guild.id in _sessions:
        raise RecordingError("このサーバーでは既に録音中です。先に停止してください。")

    settings = get_recording_settings(guild.id)
    if not settings.get("enabled", True):
        raise RecordingError("録音機能が無効になっています。管理画面で有効にしてください。")

    client = await voice_session.acquire(guild, channel.id, purpose="recording")
    if client is None:
        raise RecordingError("VC に接続できませんでした。")
    if not voice_session.can_receive(client):
        raise RecordingError(
            "今の接続では音声を受信できません。読み上げが先に接続している場合は、"
            "一度 VC から退出させてからもう一度お試しください。"
        )

    session = RecordingSession(
        guild_id=guild.id,
        channel_id=channel.id,
        channel_name=channel.name,
        started_by_id=int(getattr(started_by, "id", 0) or 0),
        started_by_name=str(getattr(started_by, "display_name", None) or started_by),
        started_at=time.monotonic(),
        max_seconds=max(0, int(settings.get("max_minutes", 360))) * 60,
        retention_days=int(settings.get("retention_days", 7)),
        excluded_user_ids={int(u) for u in settings.get("excluded_user_ids", [])},
    )

    sink_cls = _make_sink_class()
    try:
        client.listen(sink_cls(session))
    except Exception as e:
        shutil.rmtree(session.workdir, ignore_errors=True)
        raise RecordingError(f"録音を開始できませんでした（{e}）。") from e

    _sessions[guild.id] = session
    voice_session.hold(guild.id, "recording")
    _write_state()

    # 録音していることは必ず知らせる。黙って録るための機能ではない。
    session.announce_message = await _announce_start(channel, session, announce_to)
    session._guard_task = asyncio.create_task(_guard(bot, guild.id))
    logger.info(
        "[recording] guild=%s ch=%s 開始（上限 %d 分 / %s）",
        guild.id, channel.id, session.max_seconds // 60, session.started_by_name,
    )
    return session


def preferred_vc_channel_id(guild_id: int) -> int | None:
    """このギルドで「録るのが自然な VC」。

    設定していなければ読み上げの対象VCに従う。読み上げと録音は同じ音声接続を
    共有するので、既定では同じ VC を見る（「両方オンなら両方使う」という状態を、
    設定を2箇所書かずに作れるように）。録音だけ別の VC を狙いたいときだけ
    vc_channel_id を明示する。

    自動録音のスイッチとは無関係に返す。手動で始めるときの初期値としても使う
    （毎回ゼロから選び直させないため）。
    """
    from services.settings_store import get_recording_settings

    explicit = get_recording_settings(guild_id).get("vc_channel_id")
    if explicit:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            return None

    # TTS 側の対象VCに合わせる。TTS が無効でも「どのVCか」の設定は読める。
    try:
        from services.tts_service import get_effective_vc_watch
        from services.tts_store import get_tts_settings

        watched, _ = get_effective_vc_watch(guild_id, get_tts_settings(guild_id))
        return int(watched) if watched else None
    except Exception as e:
        logger.debug("[recording] TTS の対象VCを読めませんでした guild=%s: %s", guild_id, e)
        return None


def auto_start_channel_id(guild_id: int) -> int | None:
    """自動録音の対象VC。スイッチが両方オンのときだけ返す。"""
    from services.settings_store import get_recording_settings

    settings = get_recording_settings(guild_id)
    if not settings.get("enabled", True) or not settings.get("auto_start"):
        return None
    return preferred_vc_channel_id(guild_id)


async def maybe_auto_start(bot, member, channel) -> None:
    """人が VC に入ったときに、自動録音の条件が揃っていれば録り始める。

    条件が揃わない場合は静かに何もしない（入室のたびに警告を出さない）。
    """
    guild = getattr(member, "guild", None)
    if guild is None or getattr(member, "bot", False) or channel is None:
        return
    if guild.id in _sessions:
        return                       # すでに録音中
    if not voice_session.RECEIVE_AVAILABLE:
        return
    if auto_start_channel_id(guild.id) != channel.id:
        return

    try:
        await start_recording(bot, guild, channel, started_by=guild.me or bot.user)
        logger.info("[recording] guild=%s ch=%s 自動録音を開始しました", guild.id, channel.id)
    except RecordingError as e:
        # 自動で走る経路なので、失敗しても入室そのものは妨げない。
        logger.warning("[recording] guild=%s 自動録音を開始できませんでした: %s", guild.id, e)


async def _announce_start(
    channel: discord.VoiceChannel,
    session: RecordingSession,
    announce_to: discord.abc.Messageable | None,
) -> discord.Message | None:
    embed = discord.Embed(
        title="🔴 このボイスチャンネルの録音を開始しました",
        description=(
            f"**{channel.name}** の音声を録音しています。参加者ごとに別トラックで記録されます。\n"
            "録音されたくない場合は、VC から退出するか、管理者に除外を依頼してください。"
        ),
        color=discord.Color.red(),
    )
    embed.add_field(name="開始した人", value=session.started_by_name, inline=True)
    embed.add_field(
        name="自動停止",
        value="全員が退出したとき" if session.is_unlimited else f"{session.max_seconds // 60} 分後",
        inline=True,
    )
    embed.set_footer(text="停止すると、ダウンロード用のリンクが投稿されます。")

    targets = [t for t in (announce_to, channel) if t is not None]
    for target in targets:
        try:
            return await target.send(embed=embed)
        except Exception as e:
            logger.debug("[recording] 開始通知を送れませんでした: %s", e)
    logger.warning("[recording] guild=%s 開始を知らせる先がありませんでした", session.guild_id)
    return None


def _is_receiving(guild_id: int) -> bool:
    """まだ音声を受信できている状態か。

    voice_recv は受信スレッドで例外が起きると stop_listening() を呼んで
    黙って受信をやめる（デコードできないパケット1つでも起きうる）。
    接続そのものは生きているので、listening かどうかで見分ける。
    """
    client = voice_session.get(guild_id)
    if client is None:
        return False
    is_listening = getattr(client, "is_listening", None)
    if is_listening is None:
        return True          # 判断できないなら止めない
    try:
        return bool(is_listening())
    except Exception:
        return True


def _vc_is_empty(bot, session: "RecordingSession") -> bool:
    """録音中の VC から人間が居なくなったか。判断できないときは False。"""
    guild = bot.get_guild(session.guild_id)
    if guild is None:
        return False
    channel = guild.get_channel(session.channel_id)
    members = getattr(channel, "members", None)
    if members is None:
        return False
    return not any(m for m in members if not m.bot)


async def _guard(bot, guild_id: int) -> None:
    """上限時間に達したら自動で停止する。あわせて VC の無人化も見張る。

    無人化は on_voice_state_update でも拾っているが、イベントを取り逃す
    （bot の再接続中に全員が抜けた等）と誰も止める人がいなくなる。上限時間なし
    で録っているときはそれが「無音を録り続ける」ではなく「永久に止まらない」に
    なるため、ここでも定期的に確かめる。
    """
    session = _sessions.get(guild_id)
    if session is None:
        return
    try:
        while guild_id in _sessions and not session.stopping:
            if not session.is_unlimited:
                remaining = session.max_seconds - session.elapsed
                if remaining <= 0:
                    logger.info("[recording] guild=%s 上限時間に達したので停止します", guild_id)
                    await stop_recording(bot, guild_id, reason="上限時間に達しました")
                    return
                interval = min(_GUARD_INTERVAL_SEC, max(1.0, remaining))
            else:
                interval = _GUARD_INTERVAL_SEC

            # 受信スレッドが落ちていないか。voice_recv は内部でエラーが起きると
            # stop_listening() を呼んで受信をやめるが、こちらのセッションは
            # 「録音中」のまま残る。放っておくと、途中で切れた録音が最後まで
            # 録れたように見えてしまうので、気づいた時点で書き出す。
            if not _is_receiving(guild_id):
                logger.warning(
                    "[recording] guild=%s 音声の受信が止まっていたので書き出します", guild_id,
                )
                await stop_recording(bot, guild_id, reason="音声の受信が止まりました")
                return

            # 開始直後は参加者のキャッシュが揃っていないことがあるので少し待つ
            if session.elapsed > _EMPTY_GRACE_SEC and _vc_is_empty(bot, session):
                logger.info("[recording] guild=%s VC が無人になったので停止します", guild_id)
                await stop_recording(bot, guild_id, reason="VC が空になりました")
                return

            _write_state()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.exception("[recording] guard error guild=%s: %s", guild_id, e)


async def stop_recording(bot, guild_id: int, *, reason: str = "") -> dict:
    """録音を止めて ZIP にまとめ、ダウンロード用のトークンを返す。"""
    session = _sessions.get(guild_id)
    if session is None:
        raise RecordingError("このサーバーでは録音していません。")
    if session.stopping:
        raise RecordingError("停止処理中です。")

    session.stopping = True
    total_elapsed = session.elapsed
    _sessions.pop(guild_id, None)
    _write_state()

    if session._guard_task and not session._guard_task.done():
        session._guard_task.cancel()

    client = voice_session.get(guild_id)
    if client is not None and hasattr(client, "stop_listening"):
        try:
            client.stop_listening()
        except Exception as e:
            logger.debug("[recording] stop_listening: %s", e)

    voice_session.unhold(guild_id, "recording")

    # ffmpeg の終了とアーカイブ作成はブロッキングなので別スレッドで行う。
    try:
        result = await asyncio.to_thread(_finalize, session, total_elapsed, reason)
    except Exception as e:
        shutil.rmtree(session.workdir, ignore_errors=True)
        logger.exception("[recording] guild=%s 書き出しに失敗: %s", guild_id, e)
        raise RecordingError(f"録音の書き出しに失敗しました（{e}）。") from e

    logger.info(
        "[recording] guild=%s 停止（%s / %d トラック / %.1f 分 / 取りこぼし %d パケット）",
        guild_id, result["token"], result["track_count"], total_elapsed / 60,
        session.dropped_packets,
    )
    return result


def _finalize(session: RecordingSession, total_elapsed: float, reason: str) -> dict:
    for track in session.tracks.values():
        track.close(total_elapsed)

    started_jst = datetime.now(_JST)
    stamp = started_jst.strftime("%Y%m%d_%H%M")
    title = f"録音 {session.channel_name} {stamp}"

    info = {
        "サーバーID": str(session.guild_id),
        "チャンネル": session.channel_name,
        "開始した人": session.started_by_name,
        "書き出し日時": started_jst.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "長さ": f"{int(total_elapsed // 60)}分{int(total_elapsed % 60)}秒",
        "停止理由": reason or "手動停止",
        "取りこぼしたパケット": session.dropped_packets,
        "トラック": [
            {"ファイル": t.out_path.name, "名前": t.display_name,
             "発話時間(秒)": round(t.voiced_seconds, 1)}
            for t in session.tracks.values()
        ],
    }

    zip_path = session.workdir / "archive.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for track in session.tracks.values():
            if track.out_path.exists() and track.out_path.stat().st_size > 0:
                archive.write(track.out_path, arcname=track.out_path.name)
        archive.writestr("info.json", json.dumps(info, ensure_ascii=False, indent=2))
        archive.writestr(
            "info.txt",
            "\n".join([
                f"チャンネル: {session.channel_name}",
                f"開始した人: {session.started_by_name}",
                f"書き出し: {info['書き出し日時']}",
                f"長さ: {info['長さ']}",
                f"停止理由: {info['停止理由']}",
                "",
                "各トラックは同じ時間軸に揃えてあります（そのまま重ねれば同期します）。",
                "",
                *[f"  {t['ファイル']}  {t['名前']}  発話 {t['発話時間(秒)']}秒"
                  for t in info["トラック"]],
            ]),
        )

    size_bytes = zip_path.stat().st_size
    token = register_file(
        zip_path,
        source_url=f"voice://{session.guild_id}/{session.channel_id}",
        title=title,
        guild_id=session.guild_id,
        ttl=session.retention_days * 24 * 3600,
        kind="recording",
    )
    shutil.rmtree(session.workdir, ignore_errors=True)

    return {
        "token": token,
        "title": title,
        "track_count": len(session.tracks),
        "duration_seconds": int(total_elapsed),
        "size_bytes": size_bytes,
        "retention_days": session.retention_days,
        "channel_id": session.channel_id,
        "channel_name": session.channel_name,
        "reason": reason or "手動停止",
        "dropped_packets": session.dropped_packets,
        "speakers": [t.display_name for t in session.tracks.values()],
    }


def download_url(guild_id: int, token: str) -> str:
    from config import DJAUDIO_BASE_URL
    return f"{DJAUDIO_BASE_URL}/dlaudio/files/{guild_id}/{token}"


def build_result_embed(guild_id: int, result: dict) -> discord.Embed:
    minutes, seconds = divmod(result["duration_seconds"], 60)
    embed = discord.Embed(
        title="⏹️ 録音を保存しました",
        description=f"**{result['channel_name']}** / {minutes}分{seconds}秒",
        color=discord.Color.green(),
    )
    embed.add_field(name="トラック数", value=f"{result['track_count']} 人", inline=True)
    embed.add_field(name="サイズ", value=f"{result['size_bytes'] / 1024 / 1024:.1f} MB", inline=True)
    embed.add_field(name="保存期間", value=f"{result['retention_days']} 日", inline=True)
    if result["speakers"]:
        embed.add_field(name="参加者", value="、".join(result["speakers"][:20]), inline=False)
    # 取りこぼしがあったなら黙っていない。音が欠けている可能性を伝える。
    dropped = result.get("dropped_packets", 0)
    if dropped:
        embed.add_field(
            name="⚠️ 取りこぼし",
            value=f"{dropped} パケットを復元できませんでした（その分だけ音が欠けています）。",
            inline=False,
        )
    url = download_url(guild_id, result["token"])
    embed.add_field(name="ダウンロード", value=f"[ZIP をダウンロード]({url})\n`{url}`", inline=False)
    embed.set_footer(text=f"停止理由: {result['reason']}")
    return embed


async def stop_all(bot, reason: str = "bot 停止") -> None:
    """全ギルドの録音を止める（終了処理用）。録り逃しを残さないため。"""
    for guild_id in list(_sessions):
        try:
            await stop_recording(bot, guild_id, reason=reason)
        except Exception as e:
            logger.exception("[recording] guild=%s の停止に失敗: %s", guild_id, e)
