import asyncio
import json
import logging
from http import HTTPStatus
from pathlib import Path

from envutil import env_bool, env_float
from services.log_setup import install_file_logging
from webapp_admin.core.config import resolve_session_secret, settings_dir

install_file_logging(settings_dir() / "logs", "admin.log")

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from webapp_admin.extensions import limiter
from webapp_admin.metrics import (
    record_error_response,
    record_exception,
    record_request,
    start_background_monitor,
)
from webapp_admin.security import _NeedsGuild, _NeedsLogin
from webapp_admin.templating import render

logger = logging.getLogger(__name__)


def _flatten_exception_group(exc: BaseException) -> list[BaseException]:
    """入れ子になった ExceptionGroup を再帰的にほどき、末端の例外だけを並べる。

    FastAPI のミドルウェア層は複数の内部タスクをまとめて実行するため、1つの
    ルートハンドラが投げた例外でも ExceptionGroup に包まれて（しかも何重にも
    ネストして）上がってくることがある。ログにグループそのものを出しても
    「ExceptionGroup」としか分からず、原因の例外の型・メッセージが埋もれる。
    """
    if isinstance(exc, BaseExceptionGroup):
        leaves: list[BaseException] = []
        for child in exc.exceptions:
            leaves.extend(_flatten_exception_group(child))
        return leaves
    return [exc]


def _unwrap_exception_group(exc: BaseException) -> BaseException:
    """ハンドリングの分岐に使う代表例外を1つ選ぶ（先頭の末端例外）。

    _NeedsLogin / _NeedsGuild / HTTPException かどうかで分岐したいだけなので、
    グループの中身を全部見る必要はない。空グループという通常ありえない形は
    exc 自身へフォールバックし、呼び出し側を壊さない。
    """
    leaves = _flatten_exception_group(exc)
    return leaves[0] if leaves else exc


def _compact_admin_guilds(value):
    """セッションへ書く前にギルド一覧を必要最小限のフィールドへ削る。

    Discord のギルドオブジェクトは大きく、丸ごとセッションへ入れると
    Cookie ベースのセッション（starlette SessionMiddleware は署名するだけで
    サイズ制限は Cookie 側にかかる）が肥大化する。id/name/icon 以外は捨てる。
    形が壊れている要素（dict でない、id が int にできない）は黙って除く。
    """
    if not isinstance(value, list):
        return []
    compact: list[dict[str, str | None]] = []
    for guild in value:
        if not isinstance(guild, dict):
            continue
        try:
            guild_id = str(int(guild.get("id")))
        except (TypeError, ValueError):
            continue
        icon = guild.get("icon")
        compact.append(
            {
                "id": guild_id,
                "name": str(guild.get("name") or "Unknown"),
                "icon": icon if isinstance(icon, str) else None,
            }
        )
    return compact


def _make_json_safe(value):
    """json.dumps に通らない値を、通る形（文字列化）へ強制的に変換する。

    _sanitize_session_payload の最終手段。ここに来る時点で「何が JSON 化
    できないか」を個別に特定してはいない（特定できるなら _compact_admin_guilds
    のように専用の削り方をする）。str(value) で潰すので中身の構造は失われる
    ── 表示できなくても、セッション全体が壊れて 500 になるよりまし、という
    最後の砦。
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _make_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_make_json_safe(v) for v in value]
    return str(value)


def _sanitize_session_payload(session: dict) -> None:
    """レスポンスを返す直前に、セッションが Cookie へ書き出せる形かを保証する。

    starlette の SessionMiddleware は最後に session を JSON へ dumps して
    署名・Cookie 化する。ここで弾かず json.dumps に任せると、どこかのハンドラが
    JSON化できない値（datetime など）を session に置いた瞬間、無関係に見える
    リクエストまで例外で 500 になる。admin_guilds は専用の削り方
    （_compact_admin_guilds）で先に軽くし、それでも通らなければ全体を
    _make_json_safe で強制変換する。in-place で書き換えるので戻り値は無い。
    """
    if "admin_guilds" in session:
        session["admin_guilds"] = _compact_admin_guilds(session.get("admin_guilds"))

    try:
        json.dumps(session)
        return
    except (TypeError, ValueError):
        pass

    safe = _make_json_safe(session)
    if isinstance(safe, dict):
        session.clear()
        session.update(safe)


def _register_legacy_redirects(app: FastAPI) -> None:
    """旧URL（/admin/settings/... 等）へブックマークやリンクが残っている前提で301ではなく303を返す。

    パネルは今はデスクトップUI内のウィンドウであり、単独の画面URLを持たない。
    旧URLを404にせず、対応するパネルのオーバービュー内アンカーへ流す。
    check_guild を通すのは、認証前に旧URLがどのパネルの存在を示すかを
    外部へ漏らさないため（未ログインならログイン画面へ落ちる）。
    """
    from webapp_admin.schema.registry import PANELS
    from webapp_admin.security import check_guild

    def _make_handler(app_id: str):
        """ルート登録用にクロージャでパネルIDを1つずつ束縛する。

        ループ変数をそのままハンドラ内で参照すると、全ハンドラが最後に代入
        された app_id を共有してしまう（Python のクロージャは変数を後から
        評価するため）。関数を挟んで呼び出し時点の値を束縛し直している。
        """

        async def handler(request: Request, _=Depends(check_guild)):
            """このパネルのオーバービュー内アンカーへ303リダイレクトする。"""
            return RedirectResponse(f"/admin/overview#{app_id}", status_code=303)

        return handler

    for panel in PANELS:
        if panel.path:
            app.add_api_route(panel.path, _make_handler(panel.id), methods=["GET"], include_in_schema=False)


def _is_api(request: Request) -> bool:
    """JSON で返すべき相手か。

    画面から fetch する先は /admin/api/ だけではない（配信の /dlaudio/ も
    ミキサーが読む）。HTML のエラーページを返すと、fetch する側は本文を
    読めず「HTTP 400」としか言えない。Accept を見て使い分ける。
    ブラウザの遷移は text/html を要求するので、これまでどおり画面が出る。
    """
    from services.djaudio_cdn import wants_json

    if request.url.path.startswith("/admin/api/"):
        return True
    return wants_json(request)


def _is_delivery_link(request: Request) -> bool:
    """ブラウザが直接開く配信リンクか。

    このプロセスは管理画面と配信の両方を持つ。配信は別ホスト（mcdn.*）から
    /dlaudio/ だけが通されているため、管理画面の /static/ を参照するページを
    返しても資材が全部 404 になる。返すページを分ける判定はここ1箇所。
    JSON か HTML かの判定（_is_api）とは別軸なので、関数も分けてある。
    """
    return request.url.path.startswith("/dlaudio/")


def _error_response(
    request: Request,
    status_code: int,
    message: str,
    *,
    detail: str | None = None,
    description: str | None = None,
    headers: dict | None = None,
):
    """エラーを、相手に応じて JSON か HTML で返す。

    3箇所（レート制限・HTTPException・想定外の例外）が同じ振り分けを必要と
    する。別々に書くと、片方だけ JSON を返さなくなっても気づけない。
    """
    if _is_api(request):
        return JSONResponse({"detail": detail or message}, status_code=status_code, headers=headers)
    if _is_delivery_link(request):
        # 配信リンクは mcdn.* のホストで踏まれる。そこへ通っているのは
        # /dlaudio/ だけなので、error.html が読む /static/ は届かない。
        # 単体で立つページを services 側から借りる（理由はそちらの docstring）。
        from services.djaudio_cdn import render_link_error_page

        return HTMLResponse(
            render_link_error_page(status_code, detail or description or message),
            status_code=status_code,
            headers=headers,
        )
    return render(
        request,
        "error.html",
        status_code=status_code,
        code=status_code,
        message=message,
        description=description,
    )


def _default_reason_phrase(status_code: int) -> str:
    """そのコードの英語の既定フレーズ（"Not Found" 等）。無いコードは空文字。"""
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return ""


def _http_exception_response(request: Request, exc: StarletteHTTPException):
    """HTTPException を、コードごとの日本語メッセージ + detail の補足にする。

    exc.detail をそのまま補足文として画面に出す。ただし detail を渡さずに
    `HTTPException(status_code=400)` とだけ書くと、starlette が既定で
    detail へ "Bad Request" 等の英語フレーズを入れる。それを見せると日本語の
    ページに英語が併記されるので、既定フレーズと一致する detail は落とす
    （下の _default_reason_phrase）。日本語の msg と重複する detail も同様に
    落とす（二重表示を避ける）。

    ExceptionGroup 経由の経路（_exception_group_response）からも呼ぶので、
    ハンドラのクロージャではなく、ここに関数として置いてある。
    """
    # ここに無いコードは「エラーが発生しました。」に落ちる。配信リンクが
    # 実際に投げる 409/410/416 と、レート制限の 429 が漏れていたため、
    # 理由が detail に入っているのに見出しだけ何も言っていない状態だった
    # （期限切れのリンクを踏むと「エラーが発生しました。」と出ていた）。
    msgs = {
        400: "不正なリクエストです。",
        403: "アクセス権限がありません。",
        404: "ページが見つかりません。",
        405: "このURLでは受け付けていない操作です。",
        409: "この内容では処理できません。",
        410: "リンクの有効期限が切れています。",
        416: "要求された範囲を返せません。",
        429: "リクエストが多すぎます。",
        500: "サーバーエラーが発生しました。",
    }
    msg = msgs.get(exc.status_code, "エラーが発生しました。")
    # 断った理由が書いてあるなら、そのまま見せる。「不正なリクエストです」
    # だけでは、何を直せばいいのか分からない。
    detail = exc.detail if isinstance(exc.detail, str) and exc.detail else ""
    # ただし detail を渡さずに投げられた HTTPException には、starlette が
    # 既定でそのコードの英語フレーズ（"Not Found" など）を入れてくる。
    # それは「断った理由」ではないので、無かったことにして日本語の msg
    # だけを見せる。放っておくと日本語のページに "Not Found" が併記される。
    if detail == _default_reason_phrase(exc.status_code):
        detail = ""
    description = detail if detail and detail != msg else None
    # API は JSON で返す。HTML のエラーページを返すと、fetch する側は本文を
    # 読めず「HTTP 502」としか言えない。detail に入れた理由をそのまま渡す。
    return _error_response(
        request,
        exc.status_code,
        msg,
        detail=detail or None,
        description=description,
        headers=getattr(exc, "headers", None),
    )


def _exception_group_response(request: Request, exc: ExceptionGroup):
    """ExceptionGroup の中身を見て、他の応答へ振り分ける。

    _NeedsLogin/_NeedsGuild/HTTPException を包んだ ExceptionGroup は
    FastAPI が直接は拾わない（登録してあるのはそれぞれの生の型に対する
    ハンドラのため）ので、ここで unwrap して手動で同じ処理に回す。
    どれにも当たらない場合だけ、原因不明のバグとしてログへ残し 500 を返す。

    その最後の 500 も、他の経路と同じく _error_response を通す。以前はここ
    だけが error.html を直に描いており、fetch する側には本文を読めない HTML
    が、配信リンクには /static/ の届かないホストで管理画面のページが返って
    いた。**どちらも「500 が返る」ことは変わらない**ため、動かしてみるだけ
    では気づけない。UnhandledExceptionGroupTests が3種類の相手を固定している。
    """
    root = _unwrap_exception_group(exc)
    if isinstance(root, _NeedsLogin):
        return RedirectResponse("/admin/login", status_code=303)
    if isinstance(root, _NeedsGuild):
        return RedirectResponse("/admin/guilds", status_code=303)
    if isinstance(root, StarletteHTTPException):
        return _http_exception_response(request, root)

    leaves = _flatten_exception_group(exc)
    logger.error(
        "Unhandled ExceptionGroup path=%s method=%s root=%s leaves=%s",
        request.url.path,
        request.method,
        type(root).__name__,
        [f"{type(leaf).__name__}: {leaf}" for leaf in leaves],
        exc_info=exc,
    )
    return _error_response(request, 500, "サーバーエラーが発生しました。")


def _unhandled_request_response(request: Request, exc: Exception, snap: dict):
    """どのハンドラにも拾われなかった例外を、記録してから応答にする。

    ここに来るのは HTTPException / RateLimitExceeded / ExceptionGroup の
    どれにも拾われなかった、想定していない例外（実装バグ）。それらは
    内側の ExceptionMiddleware で先に Response へ変換されるため、
    ここへは来ない ＝ 監視・ログはこれまでどおり動く。
    """
    record_exception(exc, snap)
    root = _unwrap_exception_group(exc) if isinstance(exc, BaseExceptionGroup) else exc
    logger.exception(
        "Request failed method=%s path=%s root=%s detail=%s",
        request.method,
        request.url.path,
        type(root).__name__,
        root,
    )
    # raise すると Starlette の既定ハンドラがプレーンテキスト（デバッグ
    # 時は HTML）を返し、fetch する側は本文を読めず「HTTP 500」としか
    # 言えなくなる（実例: relkind が asyncpg で bytes として返り、
    # JSONResponse の json.dumps がそのまま TypeError で落ちていた）。
    return _error_response(request, 500, "サーバーエラーが発生しました。")


def _apply_security_headers(request: Request, response) -> None:
    """レスポンスへセキュリティヘッダを付ける。CSP はここが唯一の定義箇所。

    埋め込み表示（iframe）は廃止済みなので X-Frame-Options は問答無用で
    DENY にできる。CSP の許可リストを広げるときは、実際に読み込む外部
    オリジンをここへ足すこと（黙って動かない・コンソールにブロックの
    ログが出るだけで気付きにくい）。
    """
    secure = env_bool("FLASK_SECURE_COOKIES", False)
    if request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-cache, max-age=0, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # iframe を使わなくなったので、埋め込みは全面的に拒否できる。
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # CDN からのスクリプト/スタイル読み込みは廃止した（アイコンも同梱スプライト）。
    # 残る外部は Discord のアバター画像と、Cloudflare が注入する計測スクリプトのみ。
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://static.cloudflareinsights.com; "
        "style-src 'self'; "
        "img-src 'self' https://cdn.discordapp.com data:; "
        "font-src 'self'; "
        "connect-src 'self' https://static.cloudflareinsights.com; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )


def _include_routers(app: FastAPI) -> None:
    """画面と API のルーターを、それぞれの接頭辞の下へ入れる。

    接頭辞を付け間違えても起動はする。落ちるのはその API を呼ぶ画面だけで、
    しかも 404 が返るという形なので、開くまで分からない。並びごと
    tests の CreateAppShapeTests が固定している。
    """
    from services.djaudio_cdn import dlaudio_router
    from webapp_admin.api.apps import router as apps_api_router
    from webapp_admin.api.dev import router as dev_api_router
    from webapp_admin.api.recording import router as recording_api_router
    from webapp_admin.api.sql import router as sql_api_router
    from webapp_admin.api.users import router as users_api_router
    from webapp_admin.views.auth_views import router as auth_router
    from webapp_admin.views.dashboard_views import router as dashboard_router

    app.include_router(auth_router, prefix="/admin")
    app.include_router(dashboard_router, prefix="/admin")
    app.include_router(apps_api_router, prefix="/admin/api")
    app.include_router(users_api_router, prefix="/admin/api")
    app.include_router(recording_api_router, prefix="/admin/api")
    app.include_router(dev_api_router, prefix="/admin/api/dev")
    app.include_router(sql_api_router, prefix="/admin/api/sql")
    app.include_router(dlaudio_router, prefix="/dlaudio")


def _register_public_pages(app: FastAPI) -> None:
    """ログイン不要で見えるページと、旧URLからの恒久リダイレクト。"""
    from webapp_admin.auth import DISCORD_CLIENT_ID, get_bot_guild_count

    def _invite_url() -> str | None:
        """未ログインの訪問者向けページで使う招待リンク。DISCORD_CLIENT_ID 未設定なら None。

        auth_views._build_invite_url と同じ組み立てを別実装として持っている
        （ログイン後の画面から呼ぶものと、ログイン前の公開ページから呼ぶもので
        経路が分かれているため）。scope/permissions を変えるときは両方直すこと。
        """
        if not DISCORD_CLIENT_ID:
            return None
        return (
            "https://discord.com/api/oauth2/authorize"
            f"?client_id={DISCORD_CLIENT_ID}"
            "&permissions=8&scope=bot+applications.commands"
        )

    @app.get("/")
    async def landing(request: Request):
        """公開トップページ。guild_count は get_bot_guild_count() 経由で5分キャッシュされる。

        ここだけ他の公開ページと違い Discord への問い合わせ（キャッシュ切れ時）
        を await する。毎リクエストで叩きに行くわけではないので、通常このページ
        だけが遅くなることはない。
        """
        return render(request, "landing.html", invite_url=_invite_url(), guild_count=await get_bot_guild_count())

    @app.get("/guide")
    async def guide(request: Request):
        """使い方ページ。認証不要で誰でも見える。"""
        return render(request, "guide.html", invite_url=_invite_url())

    @app.get("/privacy")
    async def privacy(request: Request):
        """プライバシーポリシー。認証不要で誰でも見える。"""
        return render(request, "privacy.html", invite_url=_invite_url())

    @app.get("/terms")
    async def terms(request: Request):
        """利用規約。認証不要で誰でも見える。"""
        return render(request, "terms.html", invite_url=_invite_url())

    @app.get("/admin/guide")
    async def redirect_admin_guide():
        """旧 /admin/guide への外部リンク・ブックマーク向けの恒久リダイレクト。

        ページの実体は /admin 配下から独立済みなので 301（恒久）で新URLを
        覚えさせる。ログイン導線の 303（その場限り）とは意味が違うので混ぜない。
        """
        return RedirectResponse("/guide", status_code=301)

    @app.get("/admin/privacy")
    async def redirect_admin_privacy():
        """旧 /admin/privacy への恒久リダイレクト。理由は redirect_admin_guide と同じ。"""
        return RedirectResponse("/privacy", status_code=301)

    @app.get("/admin/terms")
    async def redirect_admin_terms():
        """旧 /admin/terms への恒久リダイレクト。理由は redirect_admin_guide と同じ。"""
        return RedirectResponse("/terms", status_code=301)


def _register_metrics_endpoint(app: FastAPI) -> None:
    """Netdata が読む /metrics を登録する。

    _register_public_pages の後・_register_middleware の前に呼ぶ。位置に意味が
    あるのは、SlowAPIMiddleware より後に足すと既定のレート制限（300/分）が
    掛かるため。10秒間隔のスクレイプなら足りるが、**Netdata 側の間隔を詰めた
    ときに黙って 429 になる**のは避けたい。認証の代わりに接続元で絞っている
    経路なので、回数で守る必要は無い。
    """
    from webapp_admin.prometheus_view import metrics_path, render_metrics

    @app.get(metrics_path(), include_in_schema=False)
    async def metrics_endpoint(request: Request):
        """Prometheus 形式のメトリクス。許可された接続元だけに返す。

        中身は webapp_admin/prometheus_view.py。ここに直接書かないのは、
        接続元の判定を単体でテストできる形にしておきたいため。
        """
        return await render_metrics(request)


def _register_metrics_reporter(app: FastAPI) -> None:
    """管理画面自身のメトリクスを Valkey へ流す背景タスクを起動する。

    ここで起動するのは管理画面のぶんだけ。bot と web はそれぞれの背景処理から
    同じ services/metrics_reporter.py を呼ぶ。

    停止時にきちんと cancel して待つ。待たずに落とすと "Task was destroyed but
    it is pending" が出るうえ、その回のぶんの計数が Valkey へ届かない。
    """
    from services.metrics_reporter import report_forever

    @app.on_event("startup")
    async def _start_metrics_reporter() -> None:
        """報告ループを Task として動かし、app.state に控える。"""
        app.state.metrics_reporter_task = asyncio.create_task(
            report_forever("admin", interval_seconds=env_float("METRICS_REPORT_INTERVAL_SECONDS", 30.0, minimum=1.0))
        )

    @app.on_event("shutdown")
    async def _stop_metrics_reporter() -> None:
        """報告ループを止める。CancelledError はここで受け止める。"""
        task = getattr(app.state, "metrics_reporter_task", None)
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


def _register_exception_handlers(app: FastAPI) -> None:
    """例外を、画面向け・API 向けの応答へ変換する係を登録する。

    中身は module 直下の `_*_response` に置いてある。ExceptionGroup 経由の
    経路が HTTPException の応答を呼び直すので、関数として取り出しておかないと
    ハンドラ同士が互いのクロージャを参照することになる。
    """

    @app.exception_handler(_NeedsLogin)
    async def needs_login_handler(request: Request, exc: _NeedsLogin):
        """check_login/check_guild が投げた _NeedsLogin を、ログイン画面への303へ変換する。

        anyio のタスクグループ経由で例外が ExceptionGroup に包まれて上がってくる
        経路もあり、その場合はここではなく _exception_group_response 側の同じ判定が
        効く。2箇所に同じ判定があるのはそのため（片方だけ直すとどちらか一方の
        経路だけ壊れたままになる）。
        """
        return RedirectResponse("/admin/login", status_code=303)

    @app.exception_handler(_NeedsGuild)
    async def needs_guild_handler(request: Request, exc: _NeedsGuild):
        """check_guild が投げた _NeedsGuild を、ギルド選択画面への303へ変換する。

        needs_login_handler と同じ理由で、ExceptionGroup に包まれた経路は
        _exception_group_response 側の同じ判定が担う。
        """
        return RedirectResponse("/admin/guilds", status_code=303)

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        """slowapi のレート制限超過を、他のエラーと同じ見た目（JSON/HTML）で返す。

        素通しすると slowapi の既定ハンドラがプレーンテキストを返し、fetch 側は
        本文を読めず「HTTP 429」としか分からない。_error_response で振り分けるのは
        他の例外ハンドラと同じ理由。
        """
        return _error_response(request, 429, "リクエストが多すぎます。しばらく待ってから再試行してください。")

    @app.exception_handler(StarletteHTTPException)
    async def admin_http_exception_handler(request: Request, exc: StarletteHTTPException):
        """HTTPException を日本語のメッセージつきで返す（中身は _http_exception_response）。

        登録先が **starlette 側の基底クラス** なのが要点。fastapi.HTTPException
        だけに登録していたころは、経路が見つからないときに starlette の
        ルーターが投げる素の HTTPException がここを素通りし、starlette 既定の
        {"detail":"Not Found"} が生で返っていた。エンドポイントの中から投げた
        410 は日本語のページになるのに、URL を打ち間違えただけだと英語の JSON
        が出る、という食い違いになる。基底クラスに登録すれば MRO をたどって
        fastapi.HTTPException も同じここへ来る。
        """
        return _http_exception_response(request, exc)

    @app.exception_handler(ExceptionGroup)
    async def exception_group_handler(request: Request, exc: ExceptionGroup):
        """anyio のタスクグループ経由で来た例外の受け皿（中身は _exception_group_response）。"""
        return _exception_group_response(request, exc)


def _register_middleware(app: FastAPI, secret: str) -> None:
    """ミドルウェアを積む。**並べ替えないこと。**

    ミドルウェアは `add_middleware` した順とは逆順（後で足したものが先に
    リクエストを受ける）に実行される。session_serialization_guard は
    SessionMiddleware より前に足してあるので、レスポンス側の処理では
    SessionMiddleware が Cookie を書き出すより前にセッションを浄化できる。
    ここを並べ替えると、この保証が崩れて未浄化のセッションがそのまま
    Cookie 化されようとし、_sanitize_session_payload が存在する意味が
    無くなる。**並べ替えても例外は出ず、画面も出る**ので、
    tests の CreateAppShapeTests が順序ごと固定している。
    """

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        """全リクエストの計測と、想定外の未捕捉例外の最終防波堤。

        ここでの except は HTTPException/RateLimitExceeded/ExceptionGroup の
        いずれでもない例外（＝上のハンドラが対応していない実装バグ）しか
        受け取らない（詳しくは _unhandled_request_response）。
        """
        # request.client.host は uvicorn の proxy_headers が X-Forwarded-For
        # から直したあとの値（admin_main.py で有効にしている）。信頼する
        # プロキシ以外から来たヘッダは uvicorn が捨てるので、ここでは
        # そのまま使ってよい。CF-Connecting-IP はそれより手前にある
        # Cloudflare が付けるもので、より確からしいので優先する。
        client_ip = request.headers.get("CF-Connecting-IP") or (request.client.host if request.client else "unknown")
        snap = {"method": request.method, "path": request.url.path, "endpoint": None, "remote_addr": client_ip}
        try:
            response = await call_next(request)
            if not request.url.path.startswith("/static"):
                record_request()
                record_error_response(response.status_code, snap)
        except Exception as exc:
            return _unhandled_request_response(request, exc, snap)
        return response

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        """全レスポンスへセキュリティヘッダを付ける（中身は _apply_security_headers）。"""
        response = await call_next(request)
        _apply_security_headers(request, response)
        return response

    @app.middleware("http")
    async def session_serialization_guard_middleware(request: Request, call_next):
        """レスポンスを作り終えた後、Cookie化される前にセッションを浄化する。

        この関数の登録順の理由は _register_middleware の docstring にある。
        順序が崩れると _sanitize_session_payload を呼んでも手遅れになる。
        """
        response = await call_next(request)
        session = getattr(request, "session", None)
        if isinstance(session, dict):
            _sanitize_session_payload(session)
        return response

    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie="admin_session",
        max_age=3600,
        same_site="lax",
        https_only=env_bool("FLASK_SECURE_COOKIES", False),
    )


def create_app() -> FastAPI:
    """FastAPI アプリ本体を組み立てる。

    **並べ替えないこと。** 登録の順序には意味がある。

      - ルーターと公開ページの順序は、経路が重なったときにどちらが勝つかを決める
      - ミドルウェアの順序は、セッションの浄化が Cookie の書き出しより先に
        走ることを保証している（理由は _register_middleware の docstring）

    どちらも**並べ替えても例外は出ず、画面も出る**。壊れるのは特定の経路だけ
    なので、動かしてみるだけでは気づけない。tests の CreateAppShapeTests が
    ここで組み上がる姿を丸ごと固定してある。
    """
    secret = resolve_session_secret()

    app = FastAPI(docs_url=None, redoc_url=None)
    app.state.limiter = limiter

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    _include_routers(app)
    # 旧ページのURL（/admin/settings/... など）はブックマークやリンクが残っているので、
    # デスクトップ上の該当ウィンドウを開く形へ寄せる。対応表はパネル定義から作る。
    _register_legacy_redirects(app)
    _register_public_pages(app)
    _register_metrics_endpoint(app)
    _register_exception_handlers(app)
    _register_middleware(app, secret)
    _register_metrics_reporter(app)

    @app.on_event("shutdown")
    async def _close_http_session() -> None:
        """使い回している HTTP セッションを、プロセス終了時に閉じる。

        Bot 側は main.py の finally で閉じている。管理画面には同じ契機が
        無く、閉じないまま落ちると "Unclosed client session" が出る。
        """
        from services.http_client import close_session

        await close_session()

    start_background_monitor(logger)

    return app


app = create_app()
