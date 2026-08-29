"""Discord Bot のイベントハンドラ・背景タスク一式。

以前は bot_setup.py の setup_events(bot) が 1,210 行の単一クロージャで、中に
ヘルパー・背景タスク・全イベントハンドラを抱えていた（テストも1行も無かった）。
関心ごとに以下へ分けている。

- state.py             モジュールをまたいで共有する実行時状態（EventState）
- _util.py              _safe() など、各モジュールが共通で使う小さな道具
- user_state_sync.py    監査ログ照会・メンバー/BAN取得・ユーザー状態同期
- background_tasks.py   @tasks.loop の4本（ステータス/ニュース/スティッキー/シグナル監視）
- ready.py              on_ready
- messages.py           on_message / on_message_delete / on_message_edit
- voice.py              on_voice_state_update とその内側のヘルパー
- members.py            on_member_join/remove/update/ban/unban
- reactions.py          on_raw_reaction_add / on_raw_reaction_remove

各モジュールは register(bot, ...) を公開し、bot_setup.setup_events(bot) が
それらを順に呼ぶだけになっている。分割の経緯・分け方の理由は
bot_setup.py の setup_events() docstring を参照。
"""
