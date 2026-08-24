"""期間（秒）の扱い。

保存はこれまでどおり「秒」で行う。既に保存されている値をそのまま読めるように
するためで、単位はあくまで入力と表示の都合として扱う。

30日を秒で書くと 2,592,000 になる。この桁を利用者に数えさせるのも、
ドキュメントに「60〜2592000」と載せるのも設計として無理があるので、
入力欄・検証のエラー文・生成ドキュメントの三箇所が同じ単位表記を使う。
"""

from __future__ import annotations

SECOND = 1
MINUTE = 60
HOUR = 3600
DAY = 86400

# 大きい順。値をどの単位で見せるかは「割り切れる一番大きい単位」で決める。
UNITS: tuple[tuple[str, int], ...] = (
    ("日", DAY),
    ("時間", HOUR),
    ("分", MINUTE),
    ("秒", SECOND),
)


def split(seconds: int) -> tuple[int, str]:
    """秒を (量, 単位名) にする。割り切れる一番大きい単位を選ぶ。

    600  -> (10, "分")
    3600 -> (1, "時間")
    2592000 -> (30, "日")
    90   -> (90, "秒")   割り切れないので秒のまま
    """
    value = int(seconds)
    if value <= 0:
        return value, "秒"
    for label, factor in UNITS:
        if value % factor == 0:
            return value // factor, label
    return value, "秒"


def humanize(seconds: int) -> str:
    """「30日」「10分」のように、人が読める1語にする。"""
    amount, label = split(seconds)
    return f"{amount}{label}"
