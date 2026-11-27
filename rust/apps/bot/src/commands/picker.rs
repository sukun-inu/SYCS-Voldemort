//! 信頼済みユーザー・バイパスロールを、複数選んでから確定する画面。Python の `commands/settings/picker.py`
//! （`EntityPickerView`）と、それを開く `/trusted add|remove`・`/bypass add|remove`。
//!
//! スラッシュコマンドは人数の決まっていない引数を取れないので、コマンドを打つと選択の部品（ユーザーか
//! ロールを 25 件まで選べる）と「確定」のボタンを出す。選んだだけでは書かず、確定を押したときに書く。
//!
//! 選んだものは Bot が覚えておく（確定のボタンの知らせには、選んだ中身が付いてこない）。覚えるのは最後に
//! 触ってから 120 秒（Python の View の timeout と同じ。過ぎたら、押しても何も起きない）。

use std::sync::Mutex;
use std::time::Instant;

use serenity::all::{
    ButtonStyle, CreateActionRow, CreateButton, CreateSelectMenu, CreateSelectMenuKind,
};
use sycs_core::ttl_cache::TtlCache;

use super::settings::{BYPASS_KEY, TRUSTED_KEY, role_mention};

/// 触らずに置いておける秒数（Python の `EntityPickerView` の `timeout=120`）。
pub const TIMEOUT_SECONDS: f64 = 120.0;
/// 同時に覚えておく画面の数。
const MAX_OPEN: usize = 1024;
/// 部品の ID の先頭。
const PREFIX: &str = "picker";
/// 本人でない人が触ったときの文。
pub const NOT_YOURS: &str = "貴様にその操作の権限はない。";
/// 何も選ばずに確定を押したときの文。
pub const NOTHING_PICKED: &str = "何も選ばれておらぬ。";

/// 何を選ぶ画面か。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickerKind {
    /// `/trusted add`
    TrustedAdd,
    /// `/trusted remove`
    TrustedRemove,
    /// `/bypass add`
    BypassAdd,
    /// `/bypass remove`
    BypassRemove,
}

impl PickerKind {
    /// ロールを選ぶ画面か（そうでなければユーザー）。
    pub fn picks_roles(self) -> bool {
        matches!(self, Self::BypassAdd | Self::BypassRemove)
    }

    /// 足す画面か（そうでなければ外す）。
    pub fn adds(self) -> bool {
        matches!(self, Self::TrustedAdd | Self::BypassAdd)
    }

    /// 書き換える設定の鍵。
    pub fn settings_key(self) -> &'static str {
        if self.picks_roles() {
            BYPASS_KEY
        } else {
            TRUSTED_KEY
        }
    }

    /// 画面を開いたときの本文。
    pub fn prompt(self) -> &'static str {
        match self {
            Self::TrustedAdd => "信頼済みに追加するユーザーを選んでから「確定」を押すがよい。",
            Self::TrustedRemove => "信頼済みから削除するユーザーを選んでから「確定」を押すがよい。",
            Self::BypassAdd => "バイパスロールに追加するロールを選んでから「確定」を押すがよい。",
            Self::BypassRemove => {
                "バイパスロールから削除するロールを選んでから「確定」を押すがよい。"
            }
        }
    }

    /// 選択の部品に出す案内。
    pub fn placeholder(self) -> &'static str {
        match self {
            Self::TrustedAdd => "追加するユーザーを選択（複数選択可・最大25人）",
            Self::TrustedRemove => "削除するユーザーを選択（複数選択可・最大25人）",
            Self::BypassAdd => "追加するロールを選択（複数選択可・最大25個）",
            Self::BypassRemove => "削除するロールを選択（複数選択可・最大25個）",
        }
    }

    /// 確定したときの文の先頭。
    pub fn action_text(self) -> &'static str {
        match self {
            Self::TrustedAdd => "余の信頼を与えた",
            Self::TrustedRemove => "余の信頼を取り消した",
            Self::BypassAdd => "バイパスロールに加えた",
            Self::BypassRemove => "バイパスロールから除いた",
        }
    }

    /// 確定したときの文の、数の見出し。
    pub fn count_label(self) -> &'static str {
        if self.picks_roles() {
            "バイパスロール数"
        } else {
            "信頼済みユーザー数"
        }
    }
}

/// 部品のどちらが触られたか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// 選択の部品。
    Select,
    /// 「確定」のボタン。
    Confirm,
}

/// 部品の ID（`picker:<画面の印>:select` か `…:confirm`）。
pub fn custom_id(token: &str, part: Part) -> String {
    let part = match part {
        Part::Select => "select",
        Part::Confirm => "confirm",
    };
    format!("{PREFIX}:{token}:{part}")
}

/// 部品の ID から、画面の印とどちらの部品かを読む。この画面のものでなければ `None`。
pub fn parse_custom_id(id: &str) -> Option<(&str, Part)> {
    let mut parts = id.split(':');
    if parts.next()? != PREFIX {
        return None;
    }
    let token = parts.next()?;
    let part = match parts.next()? {
        "select" => Part::Select,
        "confirm" => Part::Confirm,
        _ => return None,
    };
    (parts.next().is_none() && !token.is_empty()).then_some((token, part))
}

/// 画面の部品（選択と「確定」のボタン）。`picked` は、いま選ばれている数（0 なら確定は押せない）。
pub fn components(token: &str, kind: PickerKind, picked: usize) -> Vec<CreateActionRow> {
    let select_kind = if kind.picks_roles() {
        CreateSelectMenuKind::Role {
            default_roles: None,
        }
    } else {
        CreateSelectMenuKind::User {
            default_users: None,
        }
    };
    let select = CreateSelectMenu::new(custom_id(token, Part::Select), select_kind)
        .placeholder(kind.placeholder())
        .min_values(1)
        .max_values(25);
    let label = if picked > 0 {
        format!("確定（{picked}件）")
    } else {
        "確定".to_string()
    };
    let confirm = CreateButton::new(custom_id(token, Part::Confirm))
        .label(label)
        .style(ButtonStyle::Primary)
        .disabled(picked == 0);
    vec![
        CreateActionRow::SelectMenu(select),
        CreateActionRow::Buttons(vec![confirm]),
    ]
}

/// 選んだもののメンション。ユーザーは `<@ID>`、ロールは `<@&ID>`（discord.py の `mention`）。
pub fn mention(kind: PickerKind, id: u64) -> String {
    if kind.picks_roles() {
        role_mention(i64::try_from(id).unwrap_or(-1))
    } else {
        format!("<@{id}>")
    }
}

/// 確定したときの文。Python の `update_entity_list`。`total` は書いたあとの件数。
pub fn confirmed_text(kind: PickerKind, picked: &[u64], total: usize) -> String {
    let mentions: Vec<String> = picked.iter().map(|id| mention(kind, *id)).collect();
    format!(
        "{}: {}\n（{}: {total}）",
        kind.action_text(),
        mentions.join(", "),
        kind.count_label()
    )
}

/// 開いている画面 1 つぶんの覚え。
#[derive(Clone, Debug, PartialEq, Eq)]
struct Open {
    author: u64,
    kind: PickerKind,
    picked: Vec<u64>,
}

/// 触られた結果、どうするか。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// 何もしない（この Bot が開いた画面でない・時間切れ）。Python の View も、時間切れのあとは応えない。
    Ignore,
    /// 本人でない人が触った。その人にだけ見える文を返す。
    NotYours,
    /// 選び直した。画面の部品を描き直す（確定のボタンに件数を出す）。
    Redraw {
        /// 何を選ぶ画面か。
        kind: PickerKind,
        /// 選ばれている数。
        picked: usize,
    },
    /// 何も選ばずに確定を押した。
    NothingPicked,
    /// 確定した。設定を書いて、画面を結果の文に置き換える。
    Confirm {
        /// 何を選ぶ画面か。
        kind: PickerKind,
        /// 選んだ ID（選択の部品が返した順）。
        picked: Vec<u64>,
    },
}

/// 開いている画面の覚え。1 つを使い回す。
pub struct Pickers {
    open: Mutex<TtlCache<String, Open>>,
    started: Instant,
}

impl Default for Pickers {
    fn default() -> Self {
        Self {
            open: Mutex::new(TtlCache::new(TIMEOUT_SECONDS, MAX_OPEN)),
            started: Instant::now(),
        }
    }
}

impl Pickers {
    fn now(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TtlCache<String, Open>> {
        self.open.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 画面を開く。部品の ID に入れる印を返す。
    pub fn open(&self, author: u64, kind: PickerKind) -> String {
        self.open_at(author, kind, self.now())
    }

    /// 選択の部品が触られた。
    pub fn select(&self, token: &str, user: u64, values: Vec<u64>) -> Step {
        self.select_at(token, user, values, self.now())
    }

    /// 「確定」が押された。
    pub fn confirm(&self, token: &str, user: u64) -> Step {
        self.confirm_at(token, user, self.now())
    }

    /// 画面を閉じる（確定して、設定を書けたあと。Python の `self.stop()`）。
    pub fn close(&self, token: &str) {
        self.lock().pop(&token.to_string());
    }

    fn open_at(&self, author: u64, kind: PickerKind, now: f64) -> String {
        let token = random_token();
        let state = Open {
            author,
            kind,
            picked: Vec::new(),
        };
        self.lock().set(token.clone(), state, now);
        token
    }

    /// 覚えを取り出し、触られた時刻を新しくする（本人でない人が触っても延びる。Python の View と同じ）。
    fn touch(&self, token: &str, now: f64) -> Option<Open> {
        let mut open = self.lock();
        let state = open.get(&token.to_string(), now)?;
        open.set(token.to_string(), state.clone(), now);
        Some(state)
    }

    fn select_at(&self, token: &str, user: u64, values: Vec<u64>, now: f64) -> Step {
        let Some(mut state) = self.touch(token, now) else {
            return Step::Ignore;
        };
        if state.author != user {
            return Step::NotYours;
        }
        state.picked = values;
        let step = Step::Redraw {
            kind: state.kind,
            picked: state.picked.len(),
        };
        self.lock().set(token.to_string(), state, now);
        step
    }

    fn confirm_at(&self, token: &str, user: u64, now: f64) -> Step {
        let Some(state) = self.touch(token, now) else {
            return Step::Ignore;
        };
        if state.author != user {
            return Step::NotYours;
        }
        // ボタンは未選択のあいだ押せないはずだが、古い画面から押されることはある。
        if state.picked.is_empty() {
            return Step::NothingPicked;
        }
        // 画面を閉じるのは、設定を書けてから（[`Pickers::close`]）。書けなかったときは、もう一度押せる。
        Step::Confirm {
            kind: state.kind,
            picked: state.picked,
        }
    }
}

/// 部品の ID に入れる印（当てずっぽうで他人の画面を触れないよう、乱数にする）。
fn random_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::with_capacity(32);
    for _ in 0..2 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        out.push_str(&format!("{:016x}", hasher.finish()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 部品の ID は行って戻れること。この画面のものでない ID は読まないこと。
    #[test]
    fn custom_ids_round_trip() {
        let id = custom_id("abc123", Part::Select);
        assert_eq!(id, "picker:abc123:select");
        assert_eq!(parse_custom_id(&id), Some(("abc123", Part::Select)));
        assert_eq!(
            parse_custom_id(&custom_id("t", Part::Confirm)),
            Some(("t", Part::Confirm))
        );
        for other in [
            "",
            "picker",
            "picker::select",
            "picker:t:other",
            "picker:t:select:x",
            "quake:t:select",
        ] {
            assert_eq!(parse_custom_id(other), None, "{other}");
        }
    }

    /// 印は毎回違い、32 文字の 16 進であること。
    #[test]
    fn tokens_are_random() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 選ぶ → 件数が出る → 確定で書く、の流れ。確定のあとは画面が終わること。
    #[test]
    fn select_then_confirm() {
        let p = Pickers::default();
        let token = p.open_at(7, PickerKind::TrustedAdd, 0.0);
        assert_eq!(p.confirm_at(&token, 7, 1.0), Step::NothingPicked);
        assert_eq!(
            p.select_at(&token, 7, vec![30, 10], 2.0),
            Step::Redraw {
                kind: PickerKind::TrustedAdd,
                picked: 2
            }
        );
        // 選び直すと、前に選んだものは残らない。
        assert_eq!(
            p.select_at(&token, 7, vec![20], 3.0),
            Step::Redraw {
                kind: PickerKind::TrustedAdd,
                picked: 1
            }
        );
        assert_eq!(
            p.confirm_at(&token, 7, 4.0),
            Step::Confirm {
                kind: PickerKind::TrustedAdd,
                picked: vec![20]
            }
        );
        // 書けるまでは閉じない（書けなかったら、もう一度押せる）。閉じたら終わり。
        assert!(matches!(p.confirm_at(&token, 7, 5.0), Step::Confirm { .. }));
        p.close(&token);
        assert_eq!(
            p.confirm_at(&token, 7, 6.0),
            Step::Ignore,
            "閉じたあとも残っている"
        );
    }

    /// 本人でない人は選べず、確定もできないこと。知らない印は無視すること。
    #[test]
    fn only_the_author_may_use_the_picker() {
        let p = Pickers::default();
        let token = p.open_at(7, PickerKind::BypassRemove, 0.0);
        assert_eq!(p.select_at(&token, 8, vec![1], 1.0), Step::NotYours);
        assert_eq!(p.confirm_at(&token, 8, 1.0), Step::NotYours);
        // 他人が触っても、本人の選んだものは変わらない。
        p.select_at(&token, 7, vec![5], 2.0);
        p.select_at(&token, 8, vec![9, 9], 3.0);
        assert_eq!(
            p.confirm_at(&token, 7, 4.0),
            Step::Confirm {
                kind: PickerKind::BypassRemove,
                picked: vec![5]
            }
        );
        assert_eq!(p.select_at("nope", 7, vec![1], 5.0), Step::Ignore);
    }

    /// 最後に触ってから 120 秒で終わること。触るたびに延びること。
    #[test]
    fn pickers_expire_120_seconds_after_the_last_touch() {
        let p = Pickers::default();
        let token = p.open_at(7, PickerKind::TrustedAdd, 0.0);
        assert!(matches!(
            p.select_at(&token, 7, vec![1], 119.0),
            Step::Redraw { .. }
        ));
        // 119 秒に触ったので、そこから 120 秒。
        assert!(matches!(p.confirm_at(&token, 8, 238.0), Step::NotYours));
        // 他人が触っても延びる（Python の View と同じ）。
        assert!(matches!(
            p.select_at(&token, 7, vec![2], 357.0),
            Step::Redraw { .. }
        ));
        assert_eq!(
            p.confirm_at(&token, 7, 477.0),
            Step::Ignore,
            "ちょうど 120 秒で終わる"
        );
        let token = p.open_at(7, PickerKind::TrustedAdd, 1000.0);
        assert_eq!(p.select_at(&token, 7, vec![1], 1120.5), Step::Ignore);
    }

    /// 確定の文: 選んだ順のメンションと、書いたあとの件数。
    #[test]
    fn the_confirmation_lists_mentions_and_the_new_total() {
        assert_eq!(
            confirmed_text(PickerKind::TrustedAdd, &[30, 10], 5),
            "余の信頼を与えた: <@30>, <@10>\n（信頼済みユーザー数: 5）"
        );
        assert_eq!(
            confirmed_text(PickerKind::BypassRemove, &[1, 22], 0),
            "バイパスロールから除いた: <@&1>, <@&22>\n（バイパスロール数: 0）"
        );
    }

    /// 足す・外す、ユーザー・ロールの組み合わせと、書き換える設定の鍵。
    #[test]
    fn kinds_map_to_keys() {
        assert_eq!(PickerKind::TrustedAdd.settings_key(), "trusted_user_ids");
        assert_eq!(PickerKind::BypassRemove.settings_key(), "bypass_role_ids");
        assert!(PickerKind::TrustedAdd.adds() && !PickerKind::TrustedRemove.adds());
        assert!(PickerKind::BypassAdd.adds() && !PickerKind::BypassRemove.adds());
        assert!(!PickerKind::TrustedRemove.picks_roles() && PickerKind::BypassAdd.picks_roles());
    }
}
