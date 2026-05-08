# Python の公式イメージ
FROM python:3.11-slim

# 作業ディレクトリ
WORKDIR /app

# 依存関係を先にインストール
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

# アプリ本体をコピー
COPY . .

# 静的アセットをminify
RUN python scripts/minify_assets.py

# 環境変数
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Tokyo
ENV MINIFY_RESPONSES=true

CMD ["python", "main.py"]
