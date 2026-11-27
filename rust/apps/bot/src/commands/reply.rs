//! スラッシュコマンドの返事。Python の `commands/interaction_utils.py` と `commands/guards.py` の文言。

use serenity::all::CreateEmbed;

/// メッセージ本文の上限（文字数）。
pub const MESSAGE_BUDGET: usize = 2000;
/// Embed の説明の上限。
pub const EMBED_DESCRIPTION_BUDGET: usize = 4096;
/// Embed の 1 項目の値の上限。
pub const EMBED_FIELD_BUDGET: usize = 1024;

/// サーバーの外で打たれたとき（`ensure_admin`）。
pub const NOT_IN_GUILD: &str = "ギルド内でのみ使えるぞ。";
/// 管理者でない人が打ったとき（`ensure_admin`）。
pub const NOT_ADMIN: &str = "管理者のみが余のコマンドを扱えるのだ。貴様には権限がない。";
/// コマンドの中で失敗したとき（Python の `CommandInvokeError` の受け皿）。
pub const FAILED: &str = "❌ 余の力をもってしても処理できなかった。しばし待って試せ。";
/// まだ Rust に移していないコマンドが打たれたとき（切り替えの前には起きない）。
pub const NOT_PORTED: &str = "❌ このコマンドはまだ使えぬ。しばし待て。";

/// コマンドへの返事。
#[derive(Clone, Debug, Default)]
pub struct Reply {
    /// 本文。
    pub content: Option<String>,
    /// Embed。
    pub embed: Option<CreateEmbed>,
    /// 打った人にだけ見せるか。
    pub ephemeral: bool,
}

impl Reply {
    /// 打った人にだけ見える本文だけの返事。Python の `send_ephemeral`。
    pub fn ephemeral(content: impl Into<String>) -> Self {
        Self {
            content: Some(content.into()),
            embed: None,
            ephemeral: true,
        }
    }
}

/// 一覧を文字数の予算に収める。Python の `cap_list_for_message`。
///
/// 件数ではなく文字数を最後の保証にする（1 件の長さがばらばらな一覧で上限を超えないように）。
/// `header` は前置きで、その長さを先に差し引く。省略の行（`…他N件`）の長さも予算に入れる。
/// `limit` があれば件数でも打ち切る。文字数は Python の `len` と同じくコードポイントで数える。
pub fn cap_list_for_message(
    items: &[String],
    budget: usize,
    omitted_unit: &str,
    joiner: &str,
    limit: Option<usize>,
    header: &str,
) -> String {
    let len = |s: &str| s.chars().count() as i64;
    let remaining = budget as i64 - len(header);
    let total = items.len();
    let candidates = &items[..limit.map_or(total, |l| l.min(total))];
    let mut fitted: Vec<&str> = Vec::new();
    for item in candidates {
        let mut trial = fitted.clone();
        trial.push(item);
        if len(&trial.join(joiner)) > remaining {
            break;
        }
        fitted.push(item);
    }
    let mut omitted = total - fitted.len();
    loop {
        if omitted == 0 {
            return fitted.join(joiner);
        }
        let omission = format!("…他{omitted}{omitted_unit}");
        let text = fitted.join(joiner);
        let candidate = if text.is_empty() {
            omission
        } else {
            format!("{text}{joiner}{omission}")
        };
        // 1 件も入らないのに収まらないのは、予算が極端に小さい呼び方の誤り。止まらずに返す。
        if len(&candidate) <= remaining || fitted.is_empty() {
            return candidate;
        }
        fitted.pop();
        omitted += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(n: usize, text: &str) -> Vec<String> {
        (0..n).map(|i| format!("{text}{i}")).collect()
    }

    /// 収まるなら全部、収まらなければ省略の行を足して予算の内側に収めること。
    #[test]
    fn lists_fit_the_budget_including_the_omission_line() {
        assert_eq!(
            cap_list_for_message(&items(3, "a"), 100, "件", "\n", None, ""),
            "a0\na1\na2"
        );
        let long = items(50, "これは長い項目");
        let out = cap_list_for_message(&long, 60, "件", "\n", None, "見出し\n");
        assert!(
            out.chars().count() + "見出し\n".chars().count() <= 60,
            "{out}"
        );
        assert!(out.contains("…他") && out.ends_with('件'), "{out}");
        // 件数の上限でも打ち切る。
        let out = cap_list_for_message(&items(10, "a"), 1000, "名", ", ", Some(3), "");
        assert_eq!(out, "a0, a1, a2, …他7名");
        // 1 件も入らなくても止まらない。
        assert_eq!(
            cap_list_for_message(&items(2, "長い"), 1, "件", "\n", None, ""),
            "…他2件"
        );
        assert_eq!(cap_list_for_message(&[], 10, "件", "\n", None, ""), "");
    }
}
