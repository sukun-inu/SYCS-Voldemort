import json
import requests
from config import METALPRICE_BASE_URL, METALPRICE_API_KEY


def get_metal_price(metal_code: str) -> float:
    """金属の現在価格をAPIから取得"""
    try:
        if not METALPRICE_API_KEY:
            raise ValueError("METALPRICE_API_KEY が設定されていない。")
        url = f'{METALPRICE_BASE_URL}?api_key={METALPRICE_API_KEY}&base=JPY&currencies={metal_code}'
        response = requests.get(url, timeout=10)
        data = response.json()
        print("DEBUG: 金属API Response: " + json.dumps(data, ensure_ascii=False))
        
        if not data.get('success', True):
            raise ValueError(data.get('error', {}).get('message', '理解不能なエラーだ。'))
        
        return data.get('rates', {}).get(f'JPY{metal_code}', 0)
    except Exception as e:
        raise ValueError(f"{metal_code}の価格召喚に失敗したぞ。{e}")


def calculate_metal_value(grams: float, metal_code: str, purity_dict: dict = None) -> dict | int:
    """金属の価値を計算"""
    price_per_gram = get_metal_price(metal_code) / 31.1035
    
    if purity_dict:
        return {grade: int(price_per_gram * grams * purity) for grade, purity in purity_dict.items()}
    
    return int(price_per_gram * grams)
