# Discord Voldemort Bot 仕様書

このリポジトリは、**金属価格コマンド・ChatGPT 会話 Bot・サーバーアクティビティログ・高度なセキュリティ対策**を  
**1 つに統合した Discord ボット実装**です。

単なる娯楽 Bot ではなく、  
> *「情報取得」「会話」「監査」「防衛」*  

を同時に担う **運用向け Bot** として設計されています。

---

## 1. 機能概要

### 1.1 金属価格コマンド
- `/gold` `/silver` `/platinum` `/all`
- JPY ベースのリアルタイム金属価格を取得
- グラム指定に対応
- Embed 形式で視認性の高い表示

---

### 1.2 ChatGPT 会話 Bot
- 日本語限定・ヴォルデモート人格
- ユーザーごとに会話履歴を保持し、文脈の続いた会話が可能
- OpenAI の検索機能付きモデルを使用

使用モデル:
- `gpt-4o-search-preview`（会話）
- `gpt-4o-mini`（セキュリティ補助判定）

---

### 1.3 サーバーアクティビティログ
以下のイベントを **指定ログチャンネルへ Embed 形式** で出力します（JST 時刻付き）。

- メッセージ送信 / 削除 / 編集
- ボイスチャンネル参加 / 退出 / 移動 / 状態変化
- メンバー参加 / 退出
- ロール変更 / ニックネーム変更
- チャンネル作成 / 削除
- Bot コマンド実行 / エラー

---

### 1.4 設定の JSON 永続化
ギルドごとに以下の設定を `settings.json` に保存します。

- ログチャンネル ID
- ログレベル（`NONE / ERROR / INFO / DEBUG`）
- ChatGPT 応答チャンネル
- 信頼済みユーザー ID リスト
- セキュリティバイパスロール ID リスト

すべて **Slash コマンド経由で安全に操作可能**です。

---

### 1.5 セキュリティ対策（中核機能）
- メッセージレート監視
- Unicode 異常検出
- GPT による危険コンテンツ判定
- VirusTotal 連携（URL / ファイル）
- VC レイド検知
- 危険時の自動ロール剥奪 + 注意喚起

---

## 2. プロジェクト構成

```text
/
├── main.py
├── config.py
├── bot_setup.py
├── commands/
│   ├── metal_commands.py
│   ├── chat_commands.py
│   └── logging_commands.py
├── services/
│   ├── metal_service.py
│   ├── chatgpt_service.py
│   ├── discord_utils.py
│   ├── logging_service.py
│   ├── settings_store.py
│   └── security_service.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## 3. 環境変数

```bash
DISCORD_BOT_TOKEN=your_bot_token
METALPRICE_API_KEY=your_metalprice_api_key
OPENAI_API_KEY=your_openai_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

※ VirusTotal を使用しない場合は未設定でも可。

---

## 4. インストールと実行

```bash
pip install -r requirements.txt
python main.py
```

起動後、Slash コマンドは自動同期されます。

---

## 5. Slash コマンド一覧

`/help` を実行すると、登録済みコマンドが Embed で表示されます。

### 管理・設定系
- `/set_log_channel`
- `/set_log_level`
- `/set_response_channel`
- `/clear_response_channel`

### セキュリティ管理
- `/add_trusted_members`
- `/remove_trusted_members`
- `/list_trusted_members`
- `/add_bypass_roles`
- `/remove_bypass_roles`
- `/list_bypass_roles`

### 金属価格
- `/gold g:<number>`
- `/silver g:<number>`
- `/platinum g:<number>`
- `/all g:<number>`

---

## 6. ChatGPT 会話仕様

- 指定された応答チャンネルでのみ反応
- ユーザー ID ごとに会話履歴を保持
- システムプロンプトに以下を含む:
  - ヴォルデモート人格
  - 日本語限定
  - 威圧的・尊大な口調
  - 現在日時（JST）

OpenAI API:
- Endpoint: `https://api.openai.com/v1/chat/completions`
- Model: `gpt-4.1-mini`
- Temperature: `0.45`

---

## 7. ログ機能の詳細

- すべて `logging_service.log_action` 経由
- Embed Author にユーザー名とアイコン表示
- 通常ログはアイコン色から Embed 色を自動抽出
- セキュリティ関連ログは **常に赤色で強調**
- フッターに JST 時刻を表示

---

## 8. セキュリティ仕様

### 8.1 チェック除外条件
以下に該当するユーザーは **全セキュリティチェックをスキップ**。

- 信頼済みユーザー
- バイパスロール保持者

---

### 8.2 メッセージセキュリティ

非除外ユーザーに対し、以下を順に評価します。

1. **レート監視**
   - 1 秒以内に 3 件以上でスパム判定

2. **Unicode 異常検出**
   - 極端な長文
   - 同一文字の連続
   - ゼロ幅 / Bidi / 制御文字の大量使用

3. **GPT モデレーション**
   - モデル: `gpt-5-mini`
   - 危険判定・理由・カテゴリを JSON で取得

4. **VirusTotal**
   - URL / 添付ファイルをスキャン
   - キャッシュによる API 節約

---

### 8.3 危険判定時の挙動

- メッセージ削除
- `@everyone` 以外のロール剥奪
- ログ出力
- チャンネルで注意喚起メッセージ送信

---

### 8.4 VC レイド検知

- 20 秒以内
- 同一 VC
- 名前の先頭が類似したユーザーが 5 人以上

→ レイドと判定しロール剥奪 + 警告

---

## 9. 運用のすすめ

1. 初期設定
   - `/set_log_channel`
   - `/set_log_level`
   - `/set_response_channel`

2. 信頼設定
   - `/add_trusted_members`
   - `/add_bypass_roles`

3. 定期確認
   - `/list_trusted_members`
   - `/list_bypass_roles`

---