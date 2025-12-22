# Discord Voldemort Bot 仕様書

このリポジトリは、金属価格コマンド・ChatGPT会話・サーバーアクティビティログ・セキュリティ対策を統合した Discord ボット実装です。

---

## 1. 機能概要

1. **金属価格コマンド**  
   `/gold` `/silver` `/platinum` `/all` で JPY ベースのリアルタイム金属価格を取得し、Embed で表示。

2. **ChatGPT 会話 Bot**  
   - 日本語限定・ヴォルデモート人格
   - OpenAI の検索機能付きモデル（`gpt-4o-search-preview`）を使用
   - ユーザーごとに会話履歴を保持して文脈の続いた会話を実現

3. **サーバーアクティビティログ**  
   - メッセージ送信 / 削除 / 編集
   - ボイスチャンネル参加 / 退出 / 移動 / 状態変化
   - メンバー参加 / 退出 / ロール変更 / ニックネーム変更
   - チャンネル作成 / 削除
   を、指定したログチャンネルに **Embed 形式** で出力（日本時間付き）。

4. **設定の JSON 永続化**  
   - ログチャンネル
   - ログレベル（`NONE / ERROR / INFO / DEBUG`）
   - ChatGPT 応答チャンネル
   - 信頼済みユーザーリスト
   - セキュリティバイパスロールリスト

5. **セキュリティ対策**  
   - メッセージレート監視（1秒間に3件以上）
   - Unicode 異常（極端な長文・ゼロ幅/制御/Bidi 制御文字の大量使用）の検出
   - GPT による危険コンテンツ判定（フィッシング・マルウェア・荒らし・スパムなど）
   - VC レイド検知（短時間に似た名前のユーザーが多数参加）
   - 危険と判断したユーザーからロール剥奪＆テキストチャンネルで注意喚起
   - 「信頼済みユーザー」および「バイパスロール保持者」はセキュリティチェック対象外

---

## 2. プロジェクト構成

```text
discord_volchang/
├── main.py                    # エントリーポイント（Bot 起動）
├── config.py                  # 環境変数・定数管理（APIキー・金属設定・システムプロンプトなど）
├── bot_setup.py               # Bot 初期化・イベント登録（on_ready / ログ用イベントなど）
├── commands/
│   ├── __init__.py
│   ├── metal_commands.py      # 金属価格 Slash コマンド群 (/gold /silver /platinum /all)
│   ├── chat_commands.py       # ChatGPT メッセージハンドラー（on_message）
│   └── logging_commands.py    # ログ・設定・信頼済みユーザー・バイパスロールの Slash コマンド
├── services/
│   ├── __init__.py
│   ├── metal_service.py       # Metalprice API 連携
│   ├── chatgpt_service.py     # OpenAI Chat API 連携（会話履歴保持・検索機能付きモデル）
│   ├── discord_utils.py       # Discord 共通処理（Embed 作成・長文送信）
│   ├── logging_service.py     # Embed ベースのログ出力処理
│   ├── settings_store.py      # settings.json 読み書き（ギルドごとの設定）
│   └── security_service.py    # セキュリティ関連処理（レート監視/GPTモデレーション/Unicodeフィルタ/レイド検知）
└── requirements.txt           # 依存パッケージ
```

---

## 3. 環境変数

`.env` または環境変数として、最低限以下を設定します。

```bash
DISCORD_BOT_TOKEN=your_bot_token
METALPRICE_API_KEY=your_metalprice_api_key
OPENAI_API_KEY=your_openai_api_key
```

---

## 4. インストールと実行

```bash
pip install -r requirements.txt
python main.py
```

Bot 起動後、Discord 側で以下のような管理者用コマンドを使って初期設定を行うことを推奨します。

- `/set_log_channel` でログ出力用チャンネルを指定
- `/set_log_level` でログレベル（INFO か DEBUG など）を設定
- `/set_response_channel` で ChatGPT が応答するテキストチャンネルを指定
- `/add_trusted_members` や `/add_bypass_roles` で誤検知から守りたいユーザー/ロールを登録

---

## 5. Slash コマンド一覧

※ `/help` を実行すると、Bot が現在登録している全スラッシュコマンドと説明を Embed で一覧表示します。

主なコマンド:


### 5.1 コマンド一覧（アルファベット順）

- `/add_bypass_roles role1..role3`  
  指定したロールを「セキュリティチェックをバイパスするロール」に追加。
- `/add_trusted_members member1..member5`  
  指定したメンバーを「信頼済みユーザー」に追加（セキュリティチェック対象外）。
- `/all g:<グラム数>`  
  指定グラム数の金・銀・プラチナ価格をまとめて取得。
- `/clear_response_channel`  
  ChatGPT応答チャンネル設定を解除。
- `/gold g:<グラム数>`  
  指定グラム数の金の価格を取得。
- `/help`  
  登録されている全スラッシュコマンド名と description を Embed で一覧表示（ephemeral）。
- `/list_bypass_roles`  
  登録されているバイパスロールを一覧表示。
- `/list_trusted_members`  
  登録されている信頼済みユーザーを一覧表示。
- `/platinum g:<グラム数>`  
  指定グラム数のプラチナ価格を取得。
- `/remove_bypass_roles role1..role3`  
  バイパスロールから削除。
- `/remove_trusted_members member1..member5`  
  信頼済みユーザーから削除。
- `/set_log_channel channel:<#channel>`  
  ボットの動作ログを送信するチャンネルを設定。
- `/set_log_level level:<NONE|ERROR|INFO|DEBUG>`  
  ログレベルを設定。
- `/set_response_channel channel:<#channel>`  
  ChatGPT が応答するチャンネルを設定。
- `/silver g:<グラム数>`  
  指定グラム数の銀の価格を取得。

---

## 6. ChatGPT 会話仕様

- 指定された ChatGPT 応答チャンネル（ギルド設定 or `RESPONSE_CHANNEL_ID`）で、Bot 以外のメッセージに反応。
- ユーザー ID ごとに `ChatGPT` インスタンスと会話履歴を保持し、文脈の続いた応答を生成。
- OpenAI API:
  - エンドポイント: `https://api.openai.com/v1/chat/completions`
  - モデル: `gpt-4o-search-preview`
  - パラメータ: `messages`, `temperature=0.45`, `web_search_options={}`
- システムメッセージはヴォルデモート人格・日本語限定・威圧的なトーン・現在日時の付与などを含む。

---

## 7. ログ機能の詳細

- すべてのログは `logging_service.log_action` を通じて **Embed 形式** で出力。
- ユーザー関連ログでは、Embed の Author にユーザー名とアイコンを表示し、通常はユーザーのアイコン画像から代表色を抽出して Embed の色を決定（`colorthief` 使用）。
- セキュリティ関連のログ（危険ユーザー検出・ロール剥奪・ロール剥奪エラー など）は、Embed 色を必ず赤 (`discord.Color.red()`) に固定して強調表示。
- フッターには日本時間 (JST) の実行時刻を表示。

ログ対象イベントの例:

- メッセージ削除 / 編集
- ボイスチャンネル参加 / 退出 / 移動 / ミュート状態変更
- メンバー参加 / 退出 / ロール変更 / ニックネーム変更
- チャンネル作成 / 削除
- ChatGPT 入力 / 出力、金属コマンド実行 / エラー など

---

## 8. セキュリティ仕様

セキュリティ関連ロジックは `services/security_service.py` に集約されています。

### 8.1 チェック対象からの除外

- 次のいずれかに該当するメンバーは、すべてのセキュリティチェックをスキップ:
  - 信頼済みユーザー（`trusted_user_ids` に登録）
  - バイパスロールを1つ以上保持しているユーザー（`bypass_role_ids` に登録されたロール）

### 8.2 メッセージセキュリティ

非除外ユーザーのメッセージに対し:

1. **レート監視**: 1 秒間に 3 件以上の投稿でスパム判定フラグ
2. **Unicode 異常検出**:
   - 4000文字以上 & 同一文字 100連続以上
   - ゼロ幅 / Bidi 制御 / 制御文字カテゴリーが 16 文字以上かつ全体の 15% 以上
3. **GPT モデレーション**:
   - モデル `gpt-4o-mini` を使用
   - メッセージ内容とサーバー参加時刻を渡し、危険 (`danger=true`) かどうかと理由・カテゴリを JSON で受け取る

いずれかが危険と判定された場合:

- 対象ユーザーから `@everyone` 以外のロールを剥奪
- ログに詳細を記録
- そのテキストチャンネルで注意喚起メッセージを投稿（危険なリンク・コンテンツを開かないよう警告）

### 8.3 VC レイド検知

ボイスチャンネル参加時（`before.channel is None` → `after.channel is not None`）に:

- 同一 VC 内で、20 秒以内に「名前の頭が似ているユーザー」が 5 人以上参加した場合、レイドと判断。
- その参加メンバーに対してロール剥奪＆注意喚起を実行。

---

## 9. 運用のすすめ

1. Bot 起動後、まず管理者が以下を実行:
   - `/set_log_channel` でログチャンネルを設定
   - `/set_log_level` を INFO か DEBUG に設定
   - `/set_response_channel` で ChatGPT 応答チャンネルを設定
2. サーバー運営メンバー・信頼できる常連には:
   - `/add_trusted_members` または `/add_bypass_roles` で誤検出から保護
3. 必要に応じて:
   - `/list_trusted_members` `/list_bypass_roles` で設定状況を確認
   - `/help` で利用可能なコマンド一覧を確認

この仕様に沿って Bot を運用することで、会話・情報取得・ログ監査・荒らし対策までを一括して行うことができます。
