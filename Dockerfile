# Python の公式イメージ
#
# **ここを変えるときは、同時に4箇所を揃えること。** ずれると、このリポジトリが
# 何度も踏んできた「手元では通るのに本番だけ壊れる」に戻る。
#
#   .python-version                       手元と Dependabot が読む
#   .github/workflows/tests.yml           setup-python と compileall の対象
#   pyproject.toml                        black / ruff の target-version、mypy の python_version
#   tools/check_requirements.py           ここの FROM を自分で読むので、変更は不要
#
# 3.11 → 3.13 にした（2026-09-04）。固定している31個すべてに 3.13 で使える配布物が
# あることを PyPI のメタデータで1つずつ確認してから上げた。
FROM python:3.13-slim

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
