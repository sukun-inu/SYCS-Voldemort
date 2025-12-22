import os

# 環境変数から定数を取得
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
METALPRICE_API_KEY = os.environ.get("METALPRICE_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

# API エンドポイント
METALPRICE_BASE_URL = 'https://api.metalpriceapi.com/v1/latest'

# 純度情報
CARAT_PURITY = {
    '24K': 1.0,
    '22K': 0.9167,
    '18K': 0.75,
    '14K': 0.5833
}

PLATINUM_PURITY = {
    'Pt1000': 1.0,
    'Pt950': 0.95,
    'Pt925': 0.925,
    'Pt900': 0.9,
    'Pt850': 0.85
}

SILVER_PURITY = {
    'Sv1000': 1.0,
    'Sv950': 0.95,
    'Sv925': 0.925,
    'Sv900': 0.9,
    'Sv850': 0.85,
    'Sv800': 0.8
}

# 金属コマンド設定
METAL_COMMANDS = {
    'gold': {
        'code': 'XAU',
        'purity': CARAT_PURITY,
        'name': '金',
        'description': 'これが金の力だ。リアルタイムの価格を見よ。',
        'color': 'gold'
    },
    'silver': {
        'code': 'XAG',
        'purity': SILVER_PURITY,
        'name': '銀',
        'description': '銀の輝きが示す価格だ。',
        'color': 'light_grey'
    },
    'platinum': {
        'code': 'XPT',
        'purity': PLATINUM_PURITY,
        'name': 'プラチナ',
        'description': 'プラチナの価値を知るがいい。',
        'color': 'blue'
    }
}

# ChatGPTシステムメッセージ
CHATGPT_SYSTEM_MESSAGE = "貴様はヴォルデモート卿である。すべての検索は **必ず日本語で行う** こと。日本語の情報のみを利用し、英語の情報は排除する。必要であれば最新情報を要約して提供せよ。尊厳と威厳を保ちつつ回答するのだ"
