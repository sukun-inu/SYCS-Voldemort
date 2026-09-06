"""
DJAudio-DL CDN 配信ルーター。
- /dlaudio/files/<guild_id>/<token>  → MP3 配信
- /dlaudio/info/<guild_id>/<token>   → ファイル情報 JSON
- /dlaudio/health                    → ヘルスチェック

webapp_admin にも cdn_main にも依存せず、どちらからでも import できる。
"""

import asyncio
import gzip
import html
import json
import logging
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from starlette.background import BackgroundTask
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from datetime import datetime, timezone

from config import DJAUDIO_FFMPEG_PATH
from services.djaudio_cache import content_type_for, get_meta, payload_path

logger = logging.getLogger(__name__)

dlaudio_router = APIRouter()


def _validate_token(token: str) -> bool:
    """トークンの形（uuid4.hex と同じ32文字の英数字）だけを見る。
    実在の照合は get_meta() 側で行うため、ここでは明らかに不正な値を
    ファイルシステムへ渡す前に弾くだけでよい。
    """
    return token.isalnum() and len(token) == 32


def _validate_guild_id(guild_id: str) -> bool:
    """URLの guild_id が数字だけか。不正な値をそのまま比較・ログへ通さない
    ための最低限の検査。
    """
    return guild_id.isdigit()


@dlaudio_router.get("/health")
async def dlaudio_health():
    """CDNプロセスが生きているかだけを返す。認証も状態確認もしない。"""
    return JSONResponse({"status": "ok"})


_LINK_INVALID = "リンクが正しくありません。Discordに投稿されたリンクをそのまま開いてください。"
_LINK_EXPIRED = "このリンクの有効期限が切れました。Discordでもう一度URLを投稿して、新しいリンクを取得してください。"
_LINK_WRONG_GUILD = "このリンクは別のサーバー向けに発行されたものです。"


@dlaudio_router.get("/files/{guild_id}/{token}")
async def serve_file(guild_id: str, token: str):
    """MP3等を配信するDJAudio-DLの本体。

    404/410/403 をエラー内容ごとに使い分けているのは、利用者に見せる文面
    （_LINK_INVALID/_LINK_EXPIRED/_LINK_WRONG_GUILD）を状態ごとに変える
    ため。guild_id の不一致は、リンクを他サーバーへ転送された場合の
    アクセス制御なので、期限切れとは別に検知してログへ残す。
    """
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    if meta.get("guild_id") != guild_id:
        logger.warning("guild_id 不一致: URL=%s meta=%s token=%s", guild_id, meta.get("guild_id"), token)
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)

    # 録音は ZIP でまとめて渡すため、拡張子はメタから決める（旧エントリは .mp3）。
    extension = str(meta.get("extension") or ".mp3")
    path = payload_path(token, meta)
    if path is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    raw_name = meta.get("filename", f"{token}{extension}")
    safe_name = "".join(c for c in raw_name if c.isalnum() or c in " ._-").strip() or f"{token}{extension}"
    if not safe_name.endswith(extension):
        safe_name += extension

    logger.info("配信: guild=%s token=%s → %s", guild_id, token, safe_name)
    return FileResponse(str(path), media_type=content_type_for(extension), filename=safe_name)


@dlaudio_router.get("/info/{guild_id}/{token}")
async def file_info(guild_id: str, token: str):
    """ファイル本体は落とさず、残り時間などのメタ情報だけを返す。
    ダウンロード前に「あと何分で切れるか」をUIへ出すためのエンドポイント。
    """
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    if meta.get("guild_id") != guild_id:
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)

    now = datetime.now(timezone.utc).timestamp()
    remaining = max(0, int(meta["expires_at"] - now))
    return JSONResponse(
        {
            "token": token,
            "title": meta.get("title", ""),
            "filename": meta.get("filename", ""),
            "expires_at": meta.get("expires_at"),
            "remaining_seconds": remaining,
            "remaining_minutes": remaining // 60,
        }
    )


# ── 録音ミキサー用 ───────────────────────────────────────────
#
# 管理画面のミキサーは、ZIP を丸ごと落とさずに「索引」と「トラック1本」を
# 個別に取りに来る。配信の入口は既存の serve_file と同じ（トークン＋ギルド照合）。


def _recording_zip(guild_id: str, token: str) -> Path:
    """録音の ZIP を返す。合わないものは 404/410 で弾く。"""
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)
    if meta.get("guild_id") != guild_id:
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)
    if meta.get("kind") != "recording" or meta.get("extension") != ".zip":
        raise HTTPException(status_code=404, detail="これは録音ではありません。")

    path = payload_path(token, meta)
    if path is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)
    return path


def _stored_member_range(zip_path: Path, name: str) -> tuple[int, int] | None:
    """ZIP 内の無圧縮メンバーの (開始位置, 長さ)。無圧縮でなければ None。

    ローカルヘッダの長さは可変（ファイル名と拡張フィールド）なので、実際に
    読んで足す。ここが分かると、ZIP を展開せずにその範囲だけ配れる。
    """
    try:
        with zipfile.ZipFile(zip_path) as archive:
            info = archive.getinfo(name)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    if info.compress_type != zipfile.ZIP_STORED:
        return None

    try:
        with open(zip_path, "rb") as handle:
            handle.seek(info.header_offset)
            header = handle.read(30)
    except OSError:
        return None
    if len(header) < 30 or header[:4] != b"PK\x03\x04":
        return None

    name_len = int.from_bytes(header[26:28], "little")
    extra_len = int.from_bytes(header[28:30], "little")
    return info.header_offset + 30 + name_len + extra_len, info.file_size


def _read_manifest(zip_path: Path) -> dict:
    """録音ZIP内の索引を読む。索引が無い古いアーカイブでも、mp3ファイル名
    から並び・stemだけを推測して同じ形の辞書に仕立てる（"legacy": True で
    区別できるようにする）ので、呼び出し側は世代を意識しなくてよい。
    """
    from services.recording_service import MANIFEST_NAME

    try:
        with zipfile.ZipFile(zip_path) as archive:
            manifest: dict = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
            return manifest
    except KeyError:
        # 索引を入れる前に録った古いアーカイブ。中身から最低限を組み立てる。
        try:
            with zipfile.ZipFile(zip_path) as archive:
                names = [n for n in archive.namelist() if n.lower().endswith(".mp3")]
        except (OSError, zipfile.BadZipFile):
            names = []
        return {
            "version": 0,
            "duration_seconds": 0,
            "bucket_seconds": 0.25,
            "legacy": True,
            "stems": [{"index": i, "file": n, "name": Path(n).stem, "peaks": []} for i, n in enumerate(sorted(names))],
        }
    except (OSError, zipfile.BadZipFile, ValueError, UnicodeDecodeError) as e:
        logger.warning("録音の索引を読めませんでした token=%s: %s", zip_path.stem, e)
        raise HTTPException(status_code=500, detail="録音の索引を読めませんでした。")


def _json_maybe_gzipped(payload: dict, request: Request) -> Response:
    """JSON を返す。相手が gzip を受け付けるなら圧縮して返す。

    受け付けない相手（curl の既定など）には素のまま返す。ここで無条件に
    圧縮すると、ヘッダを見ない道具から**読めない中身**が返ることになる。
    """
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if "gzip" not in request.headers.get("accept-encoding", "").lower():
        return Response(content=body, media_type="application/json")
    return Response(
        content=gzip.compress(body, 6),
        media_type="application/json",
        headers={"Content-Encoding": "gzip", "Vary": "Accept-Encoding"},
    )


@dlaudio_router.get("/files/{guild_id}/{token}/mixer")
async def recording_manifest(guild_id: str, token: str, request: Request):
    """ミキサーが読む索引（トラックの並び・波形・長さ）。

    波形を 0.05 秒刻みで持つので、2時間×5トラックだと素の JSON で 2MB 近く
    なる。中身は base64 の1バイト列で、無音がそのまま 'A' の連なりになるため
    **圧縮がよく効く**（実測で 1.98MB → 1.16MB）。ここだけ手で gzip する。

    アプリ全体に GZipMiddleware を挟まないのは、トラック配信が Range に
    対応しているため。途中から返すレスポンスを圧縮しなおすと、
    Content-Range とバイト数が食い違って頭出しが壊れる。
    """
    zip_path = _recording_zip(guild_id, token)
    manifest = _read_manifest(zip_path)
    stems = manifest.get("stems", [])
    for stem in stems:
        stem["url"] = f"/dlaudio/files/{guild_id}/{token}/stem/{stem['index']}"

    # 再生用の区切り配信が使えるか。使えるなら全トラックを1つの音源として
    # 鳴らせる（時計が1つなので、トラック同士がずれようがない）。
    # 圧縮された古いアーカイブは subfile で読めないので使えない。
    usable = 0 < len(stems) <= SEGMENT_MAX_TRACKS and all(
        _stored_member_range(zip_path, str(s.get("file", ""))) is not None for s in stems
    )
    if usable:
        manifest["segment_url"] = f"/dlaudio/files/{guild_id}/{token}/segment"
        # 生の PCM を組み立てるのに要る情報。チャンネルの並びは stems の並びと同じ。
        manifest["segment_format"] = {
            "encoding": "s16le",
            "sample_rate": SEGMENT_RATE,
            "channels": len(stems),
        }
    return _json_maybe_gzipped(manifest, request)


@dlaudio_router.get("/files/{guild_id}/{token}/stem/{index}")
async def recording_stem(guild_id: str, token: str, index: int, request: Request):
    """トラック1本を配信する。頭出しのため Range に対応する。"""
    zip_path = _recording_zip(guild_id, token)
    stems = _read_manifest(zip_path).get("stems", [])
    stem = next((s for s in stems if int(s.get("index", -1)) == index), None)
    if stem is None:
        raise HTTPException(status_code=404, detail="そのトラックはありません。")

    name = str(stem.get("file", ""))
    found = _stored_member_range(zip_path, name)

    if found is None:
        # 圧縮して入っている古いアーカイブ。範囲指定はできないので通しで返す。
        try:
            with zipfile.ZipFile(zip_path) as archive:
                data = archive.read(name)
        except (KeyError, OSError, zipfile.BadZipFile):
            raise HTTPException(status_code=404, detail="そのトラックを読めませんでした。")
        return Response(content=data, media_type="audio/mpeg")

    start, size = found
    begin, end = 0, size - 1
    range_header = request.headers.get("range", "")
    partial = False
    match = re.match(r"bytes=(\d*)-(\d*)$", range_header.strip())
    if match:
        raw_begin, raw_end = match.group(1), match.group(2)
        if raw_begin:
            begin = int(raw_begin)
            end = int(raw_end) if raw_end else size - 1
        elif raw_end:  # bytes=-N（末尾から N バイト）
            begin = max(0, size - int(raw_end))
        else:
            # "bytes=-" は数字がどちらも無く、範囲として成立しない。
            # RFC 9110 では壊れた Range は無視して全体を返す。
            raw_begin = raw_end = ""
        if raw_begin or raw_end:
            end = min(end, size - 1)
            # 終わりが始まりより手前（"bytes=500-100" など）は満たせない。
            # 弾かずに進むと length が負になり、Content-Length: -399 という
            # 壊れたヘッダを 206 で返していた。
            if begin >= size or begin > end:
                return Response(status_code=416, headers={"Content-Range": f"bytes */{size}"})
            partial = True

    length = end - begin + 1

    def stream():
        """[begin, end] の範囲だけをチャンクで読んで返す。ZIP内の当該
        メンバーがファイル先頭からの絶対オフセット(start)に無圧縮で
        入っている前提（_stored_member_range で確認済み）なので、
        zipfile を介さず直接 seek して読める。
        """
        remaining = length
        with open(zip_path, "rb") as handle:
            handle.seek(start + begin)
            while remaining > 0:
                chunk = handle.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    headers = {
        "Content-Length": str(length),
        "Accept-Ranges": "bytes",
        "Cache-Control": "private, max-age=600",
    }
    if partial:
        headers["Content-Range"] = f"bytes {begin}-{end}/{size}"
    return StreamingResponse(
        stream(),
        status_code=206 if partial else 200,
        media_type="audio/mpeg",
        headers=headers,
    )


# 区間の切り出し。ミキサーで決めたループ区間を、そのまま ZIP で落とせるようにする。
# 全部落として自分で切るより速く、必要な部分だけを渡せる。
_CLIP_MAX_SECONDS = 3600 * 2  # 切り出しでも 2 時間を超えたら通しで落としてもらう
_CLIP_MIN_SECONDS = 0.1


def _clip_stem(zip_path: Path, member: str, start: float, length: float, source: Path | None = None) -> bytes | None:
    """mp3 の一部だけを切り出して返す。

    再エンコードはせず（-c copy）フレーム境界で切る。中身に手を触れないので
    速く、音も劣化しない。

    source に取り出し済みのファイルを渡すとそれを使う。渡さなければ ZIP から
    一時ファイルへ取り出す。以前はメンバー全体をメモリへ読んで ffmpeg の
    標準入力へ渡していたので、1リクエストで最大 86MB（6時間のトラック）を
    抱えていた。
    """
    with tempfile.TemporaryDirectory(prefix="clip-") as work:
        if source is None:
            source = Path(work) / "stem.mp3"
            if not _extract_member(zip_path, member, source):
                return None
        try:
            result = subprocess.run(
                [
                    DJAUDIO_FFMPEG_PATH,
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-ss",
                    f"{start:.3f}",
                    "-t",
                    f"{length:.3f}",
                    "-i",
                    str(source),
                    "-c",
                    "copy",
                    "-f",
                    "mp3",
                    "pipe:1",
                ],
                capture_output=True,
                timeout=180,
            )
        except (subprocess.SubprocessError, OSError) as e:
            logger.warning("切り出しに失敗 %s: %s", member, e)
            return None
    if result.returncode != 0 or not result.stdout:
        logger.warning("切り出しに失敗 %s: %s", member, result.stderr.decode("utf-8", "replace")[:200])
        return None
    return result.stdout


# ── ミキサーの再生（多チャンネルの区切り配信）────────────────
#
# トラックごとに <audio> を1本ずつ持つと、時計が人数ぶん並ぶ。<audio> は
# それぞれ独立に進むので、揃え続けるには常に補正が要る。
#
# そこで、再生に使うぶんだけを「1トラック＝1チャンネル」の WAV にまとめて
# 渡す。ブラウザ側は decodeAudioData で1つの AudioBuffer にし、
# ChannelSplitter で分ける。音源が1つなので、時計も1つしかない
# ＝ずれようがない。音量・パン・ミュートは分けたあとに掛ける。
#
# 送るのは**生の PCM**（16bit little-endian のインターリーブ）。コンテナに
# 入れない理由は実測から。
#
#   - Opus(WebM) は再生できるが、ブラウザ側でチャンネル順が入れ替わる
#     （ffmpeg で読み直すと正しい順なので、並べ替えているのは復号側）
#   - WAV は 8ch では順序も保たれて復号できたが、3ch だと
#     EncodingError: Unable to decode audio data で落ちた。ffmpeg が
#     WAVE_FORMAT_EXTENSIBLE に channelMask=0xb（FL/FR/LFE の 2.1）を
#     書くためで、人数によって通ったり通らなかったりする
#
# 生の PCM なら、並びは書いた順そのもので、復号器の解釈が入らない。
# 標本化周波数とチャンネル数は索引で伝える。
#
# ffmpeg の subfile プロトコルで ZIP 内の範囲を直接読めるので、トラックを
# 取り出して置いておく必要はない。
#
# 音は 1トラック＝モノラルにする。Discord の音声はもともとモノラルで、
# 録音時にステレオへ複製されているだけなので、情報は失われない。
_SEGMENT_MAX_SECONDS = 30.0
_SEGMENT_MIN_SECONDS = 0.1
# ChannelSplitterNode の上限が 32。これを超える人数の録音では、
# 従来どおりトラックごとに配信する（クライアントが判断する）。
SEGMENT_MAX_TRACKS = 32
# 送る PCM の標本化周波数。録音がこの値で書かれている。
SEGMENT_RATE = 48000
# 入力側で粗く飛んだあと、出力側で捨てる長さ（→ _segment_pcm）
_SEGMENT_PREROLL = 2.0


def _gzip_file(src: Path, dst: Path) -> None:
    """gzip で固める。水準は1で足りる（→ recording_segment のコメント）。"""
    with open(src, "rb") as fin, gzip.open(dst, "wb", compresslevel=1) as fout:
        shutil.copyfileobj(fin, fout, 1024 * 1024)


def _segment_pcm(zip_path: Path, stems: list[dict], start: float, length: float, destination: Path) -> bool:
    """全トラックの同じ区間を、1トラック＝1チャンネルの生 PCM にまとめる。

    ZIP からの取り出しはしない。無圧縮で入っているので、subfile プロトコルで
    その範囲だけを直接読ませる。
    """
    # 位置合わせは「粗く入力側で飛んでから、出力側で正確に切る」。
    #
    # 入力側の -ss だけで切ると、区切りの先頭に無音が入る。subfile 越しの mp3 は
    # 索引を使った正確なシークができないためで、実測では要求位置によって
    # 110〜195ms とばらついた。区切りの継ぎ目ごとに音が欠け、しかも欠ける量が
    # 位置によって違う、という一番たちの悪い形になる。
    #
    #   10.0 秒を要求: 入力シークのみ 110.8ms ずれ / 粗+出力シーク 0.0ms
    #   20.0 秒を要求: 入力シークのみ 194.6ms ずれ / 粗+出力シーク 0.0ms
    #
    # 入力側は少し手前まで飛ぶだけにして、そこからの端数を出力側で捨てる。
    preroll = min(_SEGMENT_PREROLL, start)
    inputs: list[str] = []
    for stem in stems:
        found = _stored_member_range(zip_path, str(stem.get("file", "")))
        if found is None:
            return False  # 圧縮された古いアーカイブ。この経路は使えない
        offset, size = found
        inputs += [
            "-ss",
            f"{start - preroll:.3f}",
            "-i",
            f"subfile,,start,{offset},end,{offset + size},,:{zip_path}",
        ]

    count = len(stems)
    chain = "".join(f"[{i}:a]pan=mono|c0=0.5*c0+0.5*c1[m{i}];" for i in range(count))
    if count == 1:
        chain += "[m0]anull[out]"
    else:
        chain += "".join(f"[m{i}]" for i in range(count)) + f"amerge=inputs={count}[out]"

    try:
        result = subprocess.run(
            [
                DJAUDIO_FFMPEG_PATH,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                *inputs,
                "-filter_complex",
                chain,
                "-map",
                "[out]",
                "-ss",
                f"{preroll:.3f}",
                "-t",
                f"{length:.3f}",
                "-f",
                "s16le",
                "-acodec",
                "pcm_s16le",
                "-ar",
                str(SEGMENT_RATE),
                str(destination),
            ],
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("区切りの書き出しに失敗: %s", e)
        return False
    if result.returncode != 0 or not destination.exists() or destination.stat().st_size == 0:
        logger.warning("区切りの書き出しに失敗: %s", result.stderr.decode("utf-8", "replace")[:200])
        return False
    return True


@dlaudio_router.get("/files/{guild_id}/{token}/segment")
async def recording_segment(guild_id: str, token: str, request: Request, start: float = 0.0, length: float = 10.0):
    """再生用の区切り。全トラックを1トラック1チャンネルの生 PCM にまとめて返す。

    ■ なぜ gzip で返すか

    生の PCM は**中身に関係なく帯域を食う**。1トラック 48kHz/16bit なので、
    5トラックで 3.84Mbps、32トラックなら 24.6Mbps。再生に間に合わせるには
    これを常時流し続ける必要がある。

    ところが中身はほとんど無音で、gzip が極端に効く。実際の録音（5時間・
    5トラック）の20秒ぶんで実測すると:

        10分地点  9.16MB → 1.86MB (20.3%)   実効 0.78Mbps
        2時間     9.16MB → 1.45MB (15.9%)   実効 0.61Mbps
        4時間     9.16MB → 0.11MB ( 1.2%)   実効 0.04Mbps

    水準は1にしてある。実測 0.03〜0.10秒で、水準6は4倍かかって数%しか
    縮まない。区切りの生成そのものが 0.7〜1.6秒かかるので、そちらに対して
    無視できる大きさに抑える。

    受け取る側は何も変えなくてよい。ブラウザが透過的に解くので、
    arrayBuffer() には生の PCM が入る。
    """
    zip_path = _recording_zip(guild_id, token)
    stems = _read_manifest(zip_path).get("stems", [])
    if not stems:
        raise HTTPException(status_code=404, detail="トラックがありません。")
    if len(stems) > SEGMENT_MAX_TRACKS:
        raise HTTPException(status_code=409, detail=f"トラックが多すぎます（{SEGMENT_MAX_TRACKS} まで）。")

    begin = max(0.0, float(start))
    span = float(length)
    if not (_SEGMENT_MIN_SECONDS <= span <= _SEGMENT_MAX_SECONDS):
        raise HTTPException(
            status_code=400, detail=f"区切りの長さは {_SEGMENT_MIN_SECONDS}〜{_SEGMENT_MAX_SECONDS} 秒です。"
        )

    work = Path(tempfile.mkdtemp(prefix="segment-"))
    out_path = work / "segment.pcm"
    # ffmpeg はブロッキング。直接呼ぶとこのワーカーの他のリクエストまで止まる。
    ok = await asyncio.to_thread(_segment_pcm, zip_path, stems, begin, span, out_path)
    if not ok:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=500, detail="区切りを作れませんでした。")

    headers = {"Cache-Control": "private, max-age=600"}
    body = out_path
    # 受け取れない相手には生のまま返す。ブラウザは必ず gzip を受け取れるが、
    # curl などで直に叩かれたときに壊れた中身を渡さない。
    if "gzip" in request.headers.get("accept-encoding", "").lower():
        body = work / "segment.pcm.gz"
        await asyncio.to_thread(_gzip_file, out_path, body)
        headers["Content-Encoding"] = "gzip"
    return FileResponse(
        body,
        media_type="application/octet-stream",
        headers=headers,
        background=BackgroundTask(shutil.rmtree, work, ignore_errors=True),
    )


@dlaudio_router.get("/files/{guild_id}/{token}/clip")
async def recording_clip(guild_id: str, token: str, start: float = 0.0, end: float = 0.0):
    """指定した区間だけを切り出した ZIP を返す。

    ミキサーで決めたループ区間をそのまま落とせるようにするための入口。
    全トラックを同じ位置で切るので、落としたあとも時間軸は揃っている。
    """
    zip_path = _recording_zip(guild_id, token)
    manifest = _read_manifest(zip_path)
    stems = manifest.get("stems", [])
    if not stems:
        raise HTTPException(status_code=404, detail="トラックがありません。")

    begin = max(0.0, float(start))
    finish = float(end)
    length = finish - begin
    if length < _CLIP_MIN_SECONDS:
        raise HTTPException(status_code=400, detail="切り出す区間が短すぎます。")
    if length > _CLIP_MAX_SECONDS:
        raise HTTPException(
            status_code=400,
            detail=f"切り出せるのは {_CLIP_MAX_SECONDS // 3600} 時間までです。"
            "これより長い場合は ZIP を丸ごと落としてください。",
        )

    # 出力はディスクへ組み立てて、そのまま流す。BytesIO に作っていたときは、
    # 切り出しの元を全部メモリへ読んだうえ（6時間×8人で 689MB）、完成した ZIP
    # まで丸ごと抱えていた。同時に2人が押せば軽く GB を超える。
    work = Path(tempfile.mkdtemp(prefix="clip-out-"))
    out_path = work / "clip.zip"
    written = 0
    try:
        _build = zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED)
    except OSError as e:
        shutil.rmtree(work, ignore_errors=True)
        logger.warning("切り出しの出力を作れませんでした: %s", e)
        raise HTTPException(status_code=500, detail="切り出しに失敗しました。")
    with _build as archive:
        for stem in stems:
            member = str(stem.get("file", ""))
            # ffmpeg の subprocess.run はブロッキング（最大180秒）。ここで直接
            # 呼ぶと FastAPI のイベントループごと止まり、同じワーカーが受けている
            # 他のリクエスト（配信・ヘルスチェック含む）まで巻き添えで固まる。
            piece = await asyncio.to_thread(_clip_stem, zip_path, member, begin, length)
            if piece is None:
                continue
            archive.writestr(member, piece)
            written += 1
        if not written:
            shutil.rmtree(work, ignore_errors=True)
            raise HTTPException(status_code=500, detail="切り出しに失敗しました。")
        archive.writestr(
            "info.txt",
            "\n".join(
                [
                    f"元の録音: {manifest.get('channel_name', '')}",
                    f"切り出した区間: {begin:.2f} 秒 〜 {finish:.2f} 秒（{length:.2f} 秒）",
                    f"トラック数: {written}",
                    "",
                    "全トラックを同じ位置で切っているので、重ねれば時間軸は揃います。",
                ]
            ),
        )

    stamp = f"{int(begin)}-{int(finish)}"
    return FileResponse(
        out_path,
        media_type="application/zip",
        filename=f"clip_{stamp}.zip",
        # 送り終えてから消す。ここで消さないと一時ファイルが残り続ける。
        background=BackgroundTask(shutil.rmtree, work, ignore_errors=True),
    )


def wants_json(request) -> bool:
    """エラーを JSON で返すべき相手か。

    /dlaudio/files/ の下には2種類が同居している。ブラウザが直接開く配信リンクと、
    ミキサーが fetch する索引・解析・切り出し。パスの接頭辞では区別できないので
    Accept で見る。ブラウザの遷移は text/html を要求し、fetch する側は
    application/json を指定する。

    ここを1箇所に置いて、管理画面（webapp_admin/app.py）と単体の配信プロセス
    （cdn_main.py）の両方から使う。別々に書いていたころは、同じ URL でも
    どちらのプロセスが応答したかで JSON と HTML が入れ替わり、ミキサーは
    理由を読めずに「Unexpected token '<'」としか言えなかった。
    """
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


# 配信リンクのエラーページに出す見出し。status ごとの一言で、detail はこの下に添える。
_LINK_ERROR_TITLES = {
    400: "リクエストが正しくありません",
    403: "アクセスできません",
    404: "リンクが見つかりません",
    405: "この URL では受け付けていない操作です",
    409: "この録音では作れません",
    410: "リンクの有効期限切れ",
    416: "要求された範囲を返せません",
    429: "アクセスが集中しています",
    500: "処理に失敗しました",
}


def render_link_error_page(status_code: int, detail: object) -> str:
    """配信リンクをブラウザで直接開いた人に見せる案内ページ。

    ページを**外部の資材へ一切頼らない形**にしてあるのは、返す先が配信の
    ホストだからだ。そこへ通っているのは /dlaudio/ だけで、管理画面の
    /static/ は届かない。管理画面のテンプレート（error.html）を返していた
    ころは、そこが読む CSS 4本・aero.js・アイコンのスプライトが揃って 404
    になり、素の HTML が縦に並ぶだけの画面が出ていた。しかも「管理画面へ」
    のリンクつきで——Discord のリンクを踏んだ人に見せる先ではない。

    wants_json と同じく、置き場所はここ1箇所だけにする。管理画面
    （webapp_admin/app.py）と単体の配信プロセス（cdn_main.py）の両方が
    これを呼ぶ。別々に持っていたころは、同じ URL でもどちらのプロセスが
    応答したかで見た目も案内も変わっていた。

    detail が空でも「この操作を完了できませんでした」に倒し、白紙を返さない。
    """
    title = _LINK_ERROR_TITLES.get(status_code, "エラーが発生しました")
    message = detail if isinstance(detail, str) and detail else "この操作を完了できませんでした。"
    # detail は今のところ全部このモジュール内の定数だが、埋め込む側で
    # 逃がしておく。ここへ外から来た文字列を渡す変更が入っても、
    # そのままタグとして解釈されることはない。
    title_html = html.escape(title)
    message_html = html.escape(message)
    return f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_html} - DJAudio-DL</title>
<style>
  :root {{ color-scheme: dark light; }}
  body {{
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #10120f; color: #e9ece4;
    font-family: "Hiragino Sans", "Yu Gothic UI", "Noto Sans JP", "Meiryo", system-ui, sans-serif;
    padding: 24px;
  }}
  .card {{
    max-width: 420px; width: 100%; background: #181c15; border: 1px solid #2c3126;
    border-radius: 16px; padding: 32px 28px; text-align: center;
  }}
  h1 {{ font-size: 20px; margin: 0 0 12px; }}
  /* 番号は見出しと同じ行に置く。別の行に「DJAudio-DL ・ 410」と出していた
     ころは、区切りの中黒だけが浮いて見えた。
     番号と見出しの間隔は h1 の中の空白1つぶんだけで、ここでは足さない。 */
  h1 .code {{ font-family: ui-monospace, "SF Mono", Consolas, monospace;
              letter-spacing: .08em; color: #7fbf8f; }}
  p {{ font-size: 14.5px; line-height: 1.7; color: #b7bfae; margin: 0; }}
</style>
</head>
<body>
  <div class="card">
    <h1><span class="code">{status_code}</span> {title_html}</h1>
    <p>{message_html}</p>
  </div>
</body>
</html>"""


# ZIP からトラックを取り出すときの読み取り単位。
# 6時間の録音は1トラックで 86MB、8人ぶんで 689MB になる。丸ごとメモリへ
# 載せると、切り出しのリクエストが2つ重なっただけで GB 単位になる。
_MEMBER_CHUNK = 256 * 1024


def _iter_member(zip_path: Path, member: str):
    """ZIP 内のメンバーを少しずつ読む。全体をメモリに載せない。

    無圧縮（録音は ZIP_STORED）なら展開せずに範囲を直接読み、圧縮されている
    古いアーカイブは zipfile の展開ストリームから読む。
    """
    found = _stored_member_range(zip_path, member)
    if found is None:
        with zipfile.ZipFile(zip_path) as archive:
            with archive.open(member) as stream:
                while True:
                    chunk = stream.read(_MEMBER_CHUNK)
                    if not chunk:
                        return
                    yield chunk
        return

    offset, size = found
    with open(zip_path, "rb") as handle:
        handle.seek(offset)
        remaining = size
        while remaining > 0:
            chunk = handle.read(min(_MEMBER_CHUNK, remaining))
            if not chunk:
                return
            remaining -= len(chunk)
            yield chunk


def _extract_member(zip_path: Path, member: str, destination: Path) -> bool:
    """ZIP 内のメンバーをファイルへ書き出す。メモリには載せない。

    ffmpeg に「途中から少しだけ」を読ませたいときは、パイプではなく実体の
    ファイルを渡す。パイプだと先頭から読み捨てる必要があり、6時間の録音の
    終盤を見るために毎回 86MB を流し込むことになる。
    """
    try:
        with open(destination, "wb") as out:
            for chunk in _iter_member(zip_path, member):
                out.write(chunk)
        return True
    except (KeyError, OSError, zipfile.BadZipFile) as e:
        logger.warning("トラックを取り出せませんでした %s: %s", member, e)
        return False
