"""サーバー設定系スラッシュコマンド一式（旧 register_server_commands の分割先）。

以前は commands/server_commands.py の register_server_commands(bot) が
584行・循環的複雑度75の単一クロージャで、ウェルカム/グッバイ・VC通知・
スティッキー・リアクションロール・ニュース・地震アラート・サーバー/ユーザー情報の
7トピック分のコマンドを1関数に抱えていた（71件のテストはあったが、
どれか1つを直すにも全体を読む必要があった）。events/ パッケージの分け方に
倣い、トピックごとに以下へ分けている。

- welcome_goodbye.py   ウェルカム / グッバイ（greeting グループ）
- vcnotify.py          VC入退室通知
- sticky.py            チャンネル最下部に貼り付けるスティッキーメッセージ
- reactionrole.py      リアクションロール
- news.py              ニュースフィード
- quake.py             地震アラート（通知タイプ切り替え用の View も含む）
- info.py              サーバー情報 / ユーザー情報

各モジュールは register(bot) を公開し、自分のグループを組み立てて
bot.tree.add_command() まで行う。events/ と違い、トピック間で共有する
状態やグループが無いため（greeting/welcome/goodbye の親子関係は
welcome_goodbye.py 内で閉じている）、戻り値の受け渡しは不要にしてある。
commands/server_commands.py の register_server_commands(bot) が
それぞれの register(bot) を順に呼ぶだけになっている。
"""
