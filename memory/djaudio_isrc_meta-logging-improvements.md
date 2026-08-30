---
name: djaudio_isrc_meta-logging-improvements
description: Deezer ISRC メタデータ取得時の HTTP エラーをログに出すように修正
metadata:
  type: project
  originSessionId: 4881cb30-3143-45d0-9b59-ddd2b4d69dcd
---

修正内容:
  - _fetch_by_isrc: HTTP ステータスが 200 でない場合に警告ログを出す。
  - _fetch_by_search: 同上。
  - _download_bytes: エラーメッセージに URL と例外詳細を追加。

Why: 以前は HTTP エラーが発生しても無言で失敗しており、設定やネットワークの問題に気づけなかった。
  user_state_service の修正と同様に、失敗理由をログに残すことでトラブルシューティングを容易にする。

How to apply: 同様の silent failure がないか他のモジュールも確認する。
Related: [[verify-before-claiming]] [[no-silent-noops]] [[settings-must-reach-consumer]]