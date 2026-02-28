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


CMD ["python", "main.py"]
