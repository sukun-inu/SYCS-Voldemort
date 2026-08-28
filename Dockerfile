# Python の公式イメージ
FROM python:3.11-slim

# 作業ディレクトリ
WORKDIR /app

# OS パッケージを先に入れる（requirements.txt より変更頻度が低いため、
# 依存を1つ足しただけで apt のレイヤーを作り直さずに済む）
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    fonts-noto-cjk \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python の依存関係
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# yt-dlp は PyPI より GitHub バイナリの方が更新が速いため上書き
RUN curl -fsSL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp \
    -o /usr/local/bin/yt-dlp && chmod a+rx /usr/local/bin/yt-dlp

# アプリ本体をコピー
COPY . .

# 静的アセットをminify
RUN python scripts/minify_assets.py

# 環境変数
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Tokyo
ENV MINIFY_RESPONSES=true

CMD ["python", "main.py"]
