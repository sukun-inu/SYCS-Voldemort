"""Python の str.casefold() のうち、str.lower() と違う文字の表（rust/apps/bot/src/security_casefold.tsv）を作る。

スパムの「同じ内容」の比べ方（services/spam_detection.content_key）は、本文を NFKC にして casefold する。Rust には
casefold が無い。小文字の表（src/python_case.tsv。Python の str.lower()）はあるので、casefold が lower と違う文字
だけを、Python 3.13 の答えそのもので表にする（ß → ss、ς → σ、チェロキー文字、ギリシャ文字の下書きのイオタなど）。

1 行に 1 つ。f・元の文字・casefold した文字の並び（16 進、空白区切り）:

    python generate_casefold.py > ../../../src/security_casefold.tsv

CI の「基準」（tools/fixtures/regen.py の casefold）が、リポジトリの直下から回す。
"""


def main():
    """casefold が lower と違う文字を、符号位置の順に書き出す（Rust の文字列に入らないサロゲートは除く）。"""
    for code in range(0x110000):
        if 0xD800 <= code <= 0xDFFF:
            continue
        c = chr(code)
        folded = c.casefold()
        if folded != c.lower():
            print("f\t%X\t%s" % (code, " ".join("%X" % ord(x) for x in folded)))


if __name__ == "__main__":
    main()
