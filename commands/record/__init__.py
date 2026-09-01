"""VC録音のスラッシュコマンド一式（旧 register_recording_commands の分割先）。

以前は commands/recording_commands.py の register_recording_commands(bot) が
268行・循環的複雑度35の単一クロージャで、録音の開始/停止/状況・自動録音・
設定・本人の除外までを1関数に抱えていた。commands/server/ と
commands/settings/ の分け方に倣い、以下へ分けている。

- session.py  録音そのものの操作（/record start, stop, status）
- config.py   設定（/record auto, config）
- exclude.py  本人が自分を録音対象から外す（/record exclude）

commands/server/ と違い、これらは1つの /record グループを共有するため、
グループの生成と bot.tree.add_command() は commands/recording_commands.py 側に
残し、各モジュールの register() はグループを受け取る形にしてある。登録順
（start → stop → status → auto → config → exclude）は分割前と同じ。

session.py だけ bot を受け取る。start_recording / stop_recording が Bot を
必要とするためで、他の2つは設定の読み書きだけで完結する。
"""
