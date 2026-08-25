"""JavaScript が壊さずに読める JSON を返す。

Discord の ID（スノーフレーク）は 19 桁ある。JavaScript の数値は 2^53-1
（9,007,199,254,740,991）までしか正確に扱えないので、JSON に数値として
入れると読み込んだ時点で桁が落ちる。

    1342455482031542302  →  1342455482031542300

実際にこれで、実在するチャンネルを指定しているのに管理画面のプルダウンが
「一覧にありません」になった。値そのものが別物になっていたため、一覧と
突き合わせても一致しない。

安全な範囲を超える整数は文字列にして返す。ID は計算に使わないので、
文字列で困ることはない。書き込み側は元から文字列を受け付けている。
"""

from typing import Any

from starlette.responses import JSONResponse

# JavaScript の Number.MAX_SAFE_INTEGER
JS_SAFE_MAX = 2 ** 53 - 1


def stringify_big_ints(value: Any) -> Any:
    """JavaScript が正確に読めない整数だけを文字列に置き換える。

    真偽値は int の仲間なので、先に外す（True が "1" になると困る）。
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value) if abs(value) > JS_SAFE_MAX else value
    if isinstance(value, dict):
        return {k: stringify_big_ints(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [stringify_big_ints(v) for v in value]
    return value


class SafeJSONResponse(JSONResponse):
    """桁落ちしない JSON レスポンス。

    どの応答にも ID が混ざりうるので、個別に直すのではなく出口でまとめて
    변換する。書き漏らしで片方だけ壊れる、という形にしないため。
    """

    def render(self, content: Any) -> bytes:
        return super().render(stringify_big_ints(content))
