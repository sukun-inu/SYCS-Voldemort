# Python の公式イメージ
FROM python:3.11-slim

# 作業ディレクトリ
WORKDIR /app

# 依存関係を先にインストール
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# アプリ本体をコピー
COPY . .

# 環境変数
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Tokyo

# コンテナ内で吐き出すポート（bot_status_server が使う可能性あり）
EXPOSE 8080

CMD ["python", "main.py"]