"""Bot 設定系スラッシュコマンド一式（旧 register_logging_commands の分割先）。

以前は commands/logging_commands.py の register_logging_commands(bot) が
271行・循環的複雑度35の単一クロージャで、ログ送信先・AI応答チャンネル・
信頼済みユーザー・バイパスロール・設定一覧/ヘルプの5トピック分のコマンドを
1関数に抱えていた。commands/server/ の分け方に倣い、グループごとに以下へ
分けている。

- log.py       ログの送信先とレベル（/log）
- chat.py      AI応答チャンネルの設定（/chat）
- trusted.py   信頼済みユーザー（/trusted）
- bypass.py    バイパスロール（/bypass）
- overview.py  設定一覧とコマンドヘルプ（/bot）
- picker.py    trusted と bypass が共有する複数選択ビュー

commands/server/ と違い、グループの生成と bot.tree.add_command() は
commands/logging_commands.py 側に残してある。理由は2つある。

1. 元のコードが5つのグループをまとめて生成し、最後に1つのループで
   add_command していた。登録順（log → chat → trusted → bypass → bot）を
   1箇所で読める形を保ちたかった。
2. tests/test_commands.py が `patch.object(lc.app_commands, "Group", FakeGroup)`
   でグループ生成を差し替えている。生成箇所が register_logging_commands から
   消えると、この patch は app_commands モジュール属性への差し替えなので
   届きはするものの、「どこでグループが作られるか」がテストから見えなくなる。

trusted.py と bypass.py だけが状態（選択中のエンティティ）を持つビューを
共有するため、そこだけ picker.py へ切り出してある。
"""
