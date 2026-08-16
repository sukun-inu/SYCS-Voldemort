"""デスクトップUIの「アプリ」定義。

タスクバー/スタートメニューのタイル一覧と、直接URLアクセスをデスクトップへ
リダイレクトするためのパス対応表の、単一の情報源（single source of truth）。
両方が別々にハードコードされてズレるのを防ぐためにここへ集約する。
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AppEntry:
    id: str
    path: str
    title: str
    icon: str
    group: str


APP_REGISTRY: list[AppEntry] = [
    AppEntry("user-state", "/admin/users/state", "ユーザー状態監査", "bi-person-lines-fill", "概要"),
    AppEntry("logging", "/admin/settings/logging", "ログ設定", "bi-journal-text", "基本設定"),
    AppEntry("welcome", "/admin/settings/welcome", "ウェルカム/グッバイ", "bi-person-plus-fill", "基本設定"),
    AppEntry("vc-notify", "/admin/settings/vc-notify", "VC 通知", "bi-mic-fill", "基本設定"),
    AppEntry("earthquake", "/admin/settings/earthquake", "地震アラート", "bi-exclamation-triangle-fill", "自動通知"),
    AppEntry("news-feeds", "/admin/settings/news-feeds", "ニュースフィード", "bi-newspaper", "自動通知"),
    AppEntry("sticky", "/admin/settings/sticky", "スティッキー", "bi-pin-angle-fill", "チャンネル機能"),
    AppEntry("reaction-roles", "/admin/settings/reaction-roles", "リアクションロール", "bi-emoji-smile-fill", "チャンネル機能"),
    AppEntry("djaudio", "/admin/settings/djaudio", "DJAudio-DL", "bi-music-note-beamed", "メディア"),
    AppEntry("tts", "/admin/settings/tts", "TTS 読み上げ", "bi-soundwave", "メディア"),
    AppEntry("security", "/admin/settings/security", "セキュリティ設定", "bi-shield-fill-check", "セキュリティ"),
    # 開発者パネルは is_dev のユーザーにのみ表示（dashboard_views 側でフィルタする）
    AppEntry("dev", "/admin/dev", "開発者パネル", "bi-bug-fill", "開発者"),
]

# 直接URLアクセス（非埋め込み）をデスクトップ+ウィンドウへリダイレクトするための逆引き表
APP_PATH_TO_ID: dict[str, str] = {a.path: a.id for a in APP_REGISTRY}
