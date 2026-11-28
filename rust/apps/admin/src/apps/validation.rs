//! 設定パネルの入力の検証（rust-06 の A6）。Python の `webapp_admin/schema/validation.py`（`validate_field`・
//! `validate_values`・`validate_item` と `_validate_id`・`_validate_int`・`_validate_duration`・`_validate_select`・
//! `_validate_checklist`・`_validate_text`）、`types_def.py` の `Field.coerce`（真偽）、`duration.py` の `humanize`、
//! `webapp_admin/security.py` の `sanitize`。
//!
//! 規則は宣言（焼き込んだ `schema.json` の `wire`。入力欄の種類・`min`・`max`・`max_len`・`nullable`・`required`・
//! `free_text`・固定の選択肢・供給元・既定値）だけから引く（[`Rule`]。Python と同じく、画面ごとの分岐は持たない）。
//! 文字の上限（`MAX_STR_LEN`）と期間の単位も `schema.json` の `vocabulary` から読む。
//!
//! | 種類 | 受け付けるもの → 値 | 断る文 |
//! |---|---|---|
//! | ID（チャンネル・ボイス・ロール・スノーフレーク） | None・""・"0"・0（Python の `==`。`False`・`0.0` も）は未設定。ほかは `str(raw).strip()` が全部数字（`str.isdigit()`）で 0 より大きいもの → 整数。一覧が取れていれば、その中の値だけ | 選択してください。／Discord の ID（数字）を指定してください。／一覧にない項目です。選び直してください。 |
//! | 真偽 | 文字なら前後の空白を落として小文字にし、1・true・on・yes なら真。ほかは `bool()` | （断らない） |
//! | 数・期間 | None・"" で既定値があれば既定値（範囲は見ない）。ほかは `int()` して範囲 | 数値を入力してください。／期間を入力してください。／N 以上で…・N 以下で…（期間は「1分」「30日」の形） |
//! | 選択 | `str(raw).strip()`。空なら未設定。固定の選択肢・取れた一覧の中の値。一覧が取れなければ `free_text` だけ通す | 選択してください。／選べない値です。／利用できない選択肢です。／選択肢を取得できませんでした。… |
//! | チェックの一覧 | None は空。並びの要素を `str()` して、固定の選択肢の中だけ | 選択内容を解釈できませんでした。／不明な項目が含まれています。 |
//! | 文字 | `str(raw)` の長さ（文字の数）を見てから、NUL を落とし改行を `\n` にそろえる。1 行の文字は前後の空白を落とす。空なら未設定 | N 文字以内で入力してください。／入力してください。 |
//!
//! 検証の誤り（Python の `InvalidValue`）は利用者に見せる文（[`Refused::Invalid`]）。それ以外の例外は Python と同じく
//! 拾わない（[`Refused::Crash`]。`str.isdigit()` が真なのに `int()` が読めない上付きの数字〔²〕など。Python は 500 に
//! なる）。基準は `tests/fixtures/validation/`（入力欄 × 入力 × 選択肢 → 値か文か例外の表）。
//!
//! Python と違うところ: 一覧の入力欄に知らない鍵が 2 つ以上あるとき、誤りの並びは届いた順（Python は set の並びで、
//! 起動のたびに変わる。答えの中身は同じ）。

use std::cmp::Ordering;
use std::sync::OnceLock;

use serde_json::{Map, Value};

use crate::apps::schema::{self, ChoiceSource, Panel, Widget, int_value};
use crate::auth;
use crate::errors::Crash;
use crate::python;
use crate::users::store::DIGIT_ONLY;

/// 必須の選択が無い（`選択してください。`）。
pub const CHOOSE: &str = "選択してください。";
/// ID が数字でない（`_validate_id`）。
pub const NOT_AN_ID: &str = "Discord の ID（数字）を指定してください。";
/// ID が一覧に無い（`_validate_id`）。
pub const NOT_IN_LIST: &str = "一覧にない項目です。選び直してください。";
/// 数が読めない（`_validate_int`）。
pub const NOT_A_NUMBER: &str = "数値を入力してください。";
/// 期間が読めない（`_validate_duration`）。
pub const NOT_A_DURATION: &str = "期間を入力してください。";
/// 固定の選択肢に無い（`_validate_select`）。
pub const NOT_A_CHOICE: &str = "選べない値です。";
/// 取れた一覧に無い（`_validate_select`）。
pub const NOT_AVAILABLE: &str = "利用できない選択肢です。";
/// 一覧が取れず、手入力も許していない（`_validate_select`）。
pub const NO_CHOICES: &str = "選択肢を取得できませんでした。時間をおいて再試行してください。";
/// チェックの一覧が並びでない（`_validate_checklist`）。
pub const NOT_A_LIST: &str = "選択内容を解釈できませんでした。";
/// チェックの一覧に知らない値がある（`_validate_checklist`）。
pub const UNKNOWN_CHOICE: &str = "不明な項目が含まれています。";
/// 必須の文字が空（`_validate_text`・`validate_item`）。
pub const REQUIRED: &str = "入力してください。";
/// パネルに無い鍵（`validate_values`）。
pub const UNKNOWN_FIELD: &str = "不明な設定項目です。";
/// 書く関数の無い鍵（`validate_values`）。
pub const READ_ONLY: &str = "この項目は変更できません。";
/// 一覧の入力欄に無い鍵（`validate_item`）。
pub const UNKNOWN_ITEM_FIELD: &str = "不明な項目です。";
/// 真偽の入力欄で真と読む文字（`Field.coerce`。前後の空白を落として小文字にしたもの）。
pub const TRUE_WORDS: [&str; 4] = ["1", "true", "on", "yes"];
/// 0 以下の期間の単位（`duration.split` の `return value, "秒"`）。
pub const SECOND_LABEL: &str = "秒";

/// 検証が通った値（Python の `validate_field` の戻り値。書く関数へ渡す）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clean {
    /// `None`。
    Null,
    /// 真偽。
    Bool(bool),
    /// 整数（10 進の文字。Python の `int` は大きさに限りが無い）。
    Int(String),
    /// 文字。
    Text(String),
    /// 文字の並び（チェックの一覧）。
    List(Vec<String>),
}

impl Clean {
    /// JSON の値にする（整数は 64 ビットに収まれば数、収まらなければ 10 進の文字。[`int_value`]）。
    pub fn to_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(b) => Value::Bool(*b),
            Self::Int(text) => int_value(text),
            Self::Text(text) => Value::String(text.clone()),
            Self::List(items) => Value::Array(items.iter().cloned().map(Value::String).collect()),
        }
    }
}

/// 断った理由。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// 利用者に見せる文（Python の `InvalidValue`）。
    Invalid(String),
    /// Python で拾われない例外（500 になる）。
    Crash(Crash),
}

fn invalid(message: &str) -> Refused {
    Refused::Invalid(message.to_string())
}

/// 入力欄 1 つの規則（`Field` のうち、検証が読むもの。`wire` の入力欄から作る）。
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// 鍵。
    pub key: String,
    /// 種類。
    pub widget: Widget,
    /// 既定値（無ければ null）。
    pub default: Value,
    /// 下限（`min`）。
    pub min: Option<i64>,
    /// 上限（`max`）。
    pub max: Option<i64>,
    /// 文字の上限（`max_len`）。
    pub max_len: Option<usize>,
    /// 未設定を許すか（`nullable`）。
    pub nullable: bool,
    /// 必須か（`required`）。
    pub required: bool,
    /// 一覧が取れないとき手入力を許すか（`free_text`）。
    pub free_text: bool,
    /// 固定の選択肢の値（`static_choices`。無ければ `None`）。
    pub statics: Option<Vec<String>>,
    /// 実行時に解決する選択肢の供給元（`choice_source`）。
    pub source: Option<ChoiceSource>,
}

impl Rule {
    /// `wire` の入力欄 1 つ（`Field.to_json()`）から作る。
    pub fn from_wire(field: &Value) -> Result<Self, String> {
        let key = field["key"]
            .as_str()
            .ok_or("入力欄の key が文字ではない")?
            .to_string();
        let widget_text = field["widget"]
            .as_str()
            .ok_or_else(|| format!("{key}.widget が文字ではない"))?;
        let widget = Widget::parse(widget_text)
            .ok_or_else(|| format!("{key}: 知らない種類 {widget_text}"))?;
        let int = |name: &str| -> Result<Option<i64>, String> {
            match field.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value
                    .as_i64()
                    .map(Some)
                    .ok_or_else(|| format!("{key}.{name} が整数ではない")),
            }
        };
        let min = int("min")?;
        let max = int("max")?;
        let max_len = match int("max_len")? {
            None => None,
            Some(n) => Some(usize::try_from(n).map_err(|_| format!("{key}.max_len が負"))?),
        };
        let statics = match field.get("choices") {
            None => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|choice| {
                        choice["value"]
                            .as_str()
                            .map(str::to_string)
                            .ok_or_else(|| format!("{key}.choices[].value が文字ではない"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(_) => return Err(format!("{key}.choices が並びではない")),
        };
        let source = match field.get("choice_source") {
            None => widget.implied_source(),
            Some(Value::String(text)) => Some(
                ChoiceSource::parse(text).ok_or_else(|| format!("{key}: 知らない供給元 {text}"))?,
            ),
            Some(_) => return Err(format!("{key}.choice_source が文字ではない")),
        };
        let flag = |name: &str, default: bool| field[name].as_bool().unwrap_or(default);
        let nullable = flag("nullable", true);
        let required = flag("required", false);
        let free_text = flag("free_text", false);
        let default = field.get("default").cloned().unwrap_or(Value::Null);
        Ok(Self {
            key,
            widget,
            default,
            min,
            max,
            max_len,
            nullable,
            required,
            free_text,
            statics,
            source,
        })
    }
}

/// 一覧 1 つの規則（`Collection` のうち、追加・更新が読むもの）。
#[derive(Clone, Debug, PartialEq)]
pub struct CollectionRules {
    /// 鍵。
    pub key: String,
    /// 件数の上限（`max_items`）。
    pub max_items: Option<usize>,
    /// 入力欄（`item_fields` の順）。
    pub fields: Vec<Rule>,
}

impl CollectionRules {
    /// 鍵で入力欄を引く。
    pub fn field(&self, key: &str) -> Option<&Rule> {
        self.fields.iter().find(|rule| rule.key == key)
    }
}

/// パネル 1 枚の規則。
#[derive(Clone, Debug, PartialEq)]
pub struct PanelRules {
    /// パネルの ID。
    pub id: String,
    /// 直下の入力欄（セクションの順に平らにしたもの。`Panel.fields`）。
    pub fields: Vec<Rule>,
    /// 一覧（`Panel.collections`）。
    pub collections: Vec<CollectionRules>,
}

impl PanelRules {
    /// 鍵で直下の入力欄を引く（`Panel.field`。同じ鍵なら先のもの）。
    pub fn field(&self, key: &str) -> Option<&Rule> {
        self.fields.iter().find(|rule| rule.key == key)
    }

    /// 鍵で一覧を引く（`Panel.collection`）。
    pub fn collection(&self, key: &str) -> Option<&CollectionRules> {
        self.collections
            .iter()
            .find(|collection| collection.key == key)
    }
}

fn array<'a>(value: &'a Value, what: &str) -> Result<&'a [Value], String> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{what} が並びではない"))
}

static NULL: Value = Value::Null;

fn panel_rules_of(panel: &Panel) -> Result<PanelRules, String> {
    let id = panel.id.clone();
    let wire_sections = panel.wire.get("sections").unwrap_or(&NULL);
    let sections = array(wire_sections, &format!("{id}.sections"))?;
    let mut fields = Vec::new();
    let mut collections = Vec::new();
    for section in sections {
        for field in array(&section["fields"], &format!("{id} のセクションの fields"))? {
            fields.push(Rule::from_wire(field).map_err(|e| format!("{id}: {e}"))?);
        }
        for collection in array(
            &section["collections"],
            &format!("{id} のセクションの collections"),
        )? {
            let key = collection["key"]
                .as_str()
                .ok_or_else(|| format!("{id}: 一覧の key が文字ではない"))?
                .to_string();
            let max_items = match collection.get("max_items") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or_else(|| format!("{id}.{key}.max_items が数ではない"))?,
                ),
            };
            let mut item_fields = Vec::new();
            for field in array(&collection["fields"], &format!("{id}.{key}.fields"))? {
                item_fields.push(Rule::from_wire(field).map_err(|e| format!("{id}.{key}: {e}"))?);
            }
            collections.push(CollectionRules {
                key,
                max_items,
                fields: item_fields,
            });
        }
    }
    Ok(PanelRules {
        id,
        fields,
        collections,
    })
}

/// 宣言の全部のパネルの規則（最初に使うときに 1 回だけ作る。読めないのはビルドの誤りなので止まる。起動のときにも
/// 作るので、本番の要求の途中で初めて気づくことは無い。[`crate::apps::Panels::new`]）。
pub fn all_rules() -> &'static [PanelRules] {
    static RULES: OnceLock<Vec<PanelRules>> = OnceLock::new();
    RULES.get_or_init(|| {
        schema::schema()
            .panels
            .iter()
            .map(panel_rules_of)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| {
                panic!("焼き込んだ schema.json の入力欄を読めません（ビルドの誤り）: {e}")
            })
    })
}

/// パネルの規則（無いパネルは `None`）。
pub fn panel_rules(id: &str) -> Option<&'static PanelRules> {
    all_rules().iter().find(|rules| rules.id == id)
}

/// `schema.json` の `vocabulary`（文字の上限と期間の単位）。
struct Vocabulary {
    max_str_len: usize,
    units: Vec<(String, i64)>,
}

fn vocabulary() -> &'static Vocabulary {
    static VOCABULARY: OnceLock<Vocabulary> = OnceLock::new();
    VOCABULARY.get_or_init(|| {
        read_vocabulary().unwrap_or_else(|e| {
            panic!("焼き込んだ schema.json の vocabulary を読めません（ビルドの誤り）: {e}")
        })
    })
}

fn read_vocabulary() -> Result<Vocabulary, String> {
    let document: Value =
        serde_json::from_str(schema::SCHEMA_JSON).map_err(|e| format!("JSON ではない: {e}"))?;
    let vocabulary = &document["vocabulary"];
    let max_str_len = vocabulary["max_str_len"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or("max_str_len が数ではない")?;
    let mut units = Vec::new();
    for pair in array(&vocabulary["duration_units"], "duration_units")? {
        let label = pair[0].as_str().ok_or("単位の名前が文字ではない")?;
        let factor = pair[1].as_i64().ok_or("単位の秒が整数ではない")?;
        if factor <= 0 {
            return Err(format!("単位 {label} の秒が 0 以下"));
        }
        units.push((label.to_string(), factor));
    }
    Ok(Vocabulary { max_str_len, units })
}

/// `webapp_admin/security.py` の `MAX_STR_LEN`（`schema.json` の `vocabulary.max_str_len`）。
pub fn max_str_len() -> usize {
    vocabulary().max_str_len
}

/// `duration.humanize`（`split`: 0 以下は秒のまま、ほかは割り切れる一番大きい単位）。
pub fn humanize(seconds: i64) -> String {
    if seconds <= 0 {
        return format!("{seconds}{SECOND_LABEL}");
    }
    for (label, factor) in &vocabulary().units {
        if seconds % factor == 0 {
            return format!("{}{label}", seconds / factor);
        }
    }
    format!("{seconds}{SECOND_LABEL}")
}

/// `sanitize(s, max_len)`（NUL を落とし、`\r\n` と `\r` を `\n` にし、文字の数で切る）。
pub fn sanitize(text: &str, max_len: usize) -> String {
    let cleaned = text
        .replace('\u{0}', "")
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    cleaned.chars().take(max_len).collect()
}

/// Python の `str.isdigit()` の 1 文字（10 進の数字か、Numeric_Type=Digit の文字）。
fn is_digit_char(c: char) -> bool {
    let code = u32::from(c);
    python::decimal_value(c).is_some()
        || DIGIT_ONLY
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&code))
}

/// Python の `str.isdigit()`（空なら偽）。
pub fn is_digit_text(text: &str) -> bool {
    !text.is_empty() && text.chars().all(is_digit_char)
}

/// 全部が数字の文字の `int()`（10 進の文字。前の 0 は落とす）。10 進でない数字（² など）があれば `None`。
fn int_of_digits(text: &str) -> Option<String> {
    let mut digits = String::with_capacity(text.len());
    for c in text.chars() {
        digits.push(char::from_digit(python::decimal_value(c)?, 10)?);
    }
    let trimmed = digits.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    })
}

/// 10 進の整数の文字と数を比べる（桁の多い数は符号で決める）。
pub fn compare_int(text: &str, other: i64) -> Ordering {
    match text.parse::<i128>() {
        Ok(value) => value.cmp(&i128::from(other)),
        Err(_) if text.starts_with('-') => Ordering::Less,
        Err(_) => Ordering::Greater,
    }
}

/// `_options`（供給元の解決済みの一覧の `value`。供給元が無い・解決していなければ空）。
fn options(rule: &Rule, choices: &Map<String, Value>) -> Vec<Value> {
    let Some(source) = rule.source else {
        return Vec::new();
    };
    match choices.get(source.as_str()) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.get("value").cloned().unwrap_or(Value::Null))
            .collect(),
        _ => Vec::new(),
    }
}

/// `_validate_id`。
fn validate_id(rule: &Rule, raw: &Value, choices: &Map<String, Value>) -> Result<Clean, Refused> {
    if schema::is_unset_id(raw) {
        if !rule.nullable {
            return Err(invalid(CHOOSE));
        }
        return Ok(Clean::Null);
    }
    let text = python::strip(&python::str_of(raw)).to_string();
    if !is_digit_text(&text) {
        return Err(invalid(NOT_AN_ID));
    }
    // `int(text)`（`str.isdigit()` が真でも、上付きの数字などは int() が読めず ValueError。Python は拾わない）。
    let Some(number) = int_of_digits(&text) else {
        let shown = python::repr(&Value::String(text));
        let message = format!("invalid literal for int() with base 10: {shown}");
        return Err(Refused::Crash(Crash::new("ValueError", message)));
    };
    if number == "0" {
        return Err(invalid(NOT_AN_ID));
    }
    let options = options(rule, choices);
    if !options.is_empty() && !rule.free_text && !options.contains(&Value::String(text)) {
        return Err(invalid(NOT_IN_LIST));
    }
    Ok(Clean::Int(number))
}

/// `Field.coerce` の真偽（文字は前後の空白を落として小文字にし、[`TRUE_WORDS`] なら真。ほかは `bool()`）。
fn coerce_bool(raw: &Value) -> Clean {
    match raw {
        Value::String(text) => {
            let word = python::strip(text).to_lowercase();
            Clean::Bool(TRUE_WORDS.contains(&word.as_str()))
        }
        other => Clean::Bool(python::truthy(other)),
    }
}

/// `_validate_int`・`_validate_duration`（`unreadable` は読めないときの文、`shown` は範囲の数の書き方）。
fn validate_number(
    rule: &Rule,
    raw: &Value,
    unreadable: &str,
    shown: fn(i64) -> String,
) -> Result<Clean, Refused> {
    let empty = raw.is_null() || raw.as_str() == Some("");
    if empty && !rule.default.is_null() {
        // `int(field.default)`（範囲は見ない）。
        return auth::py_int(&rule.default)
            .map(Clean::Int)
            .map_err(Refused::Crash);
    }
    let Some(value) = python::int_text(raw) else {
        return Err(invalid(unreadable));
    };
    if let Some(min) = rule.min
        && compare_int(&value, min) == Ordering::Less
    {
        return Err(Refused::Invalid(format!("{} 以上で入力してください。", shown(min))));
    }
    if let Some(max) = rule.max
        && compare_int(&value, max) == Ordering::Greater
    {
        return Err(Refused::Invalid(format!("{} 以下で入力してください。", shown(max))));
    }
    Ok(Clean::Int(value))
}

fn plain(n: i64) -> String {
    n.to_string()
}

/// `_validate_select`。
fn validate_select(
    rule: &Rule,
    raw: &Value,
    choices: &Map<String, Value>,
) -> Result<Clean, Refused> {
    let text = if raw.is_null() {
        String::new()
    } else {
        python::strip(&python::str_of(raw)).to_string()
    };
    if text.is_empty() {
        if !rule.nullable {
            return Err(invalid(CHOOSE));
        }
        return Ok(Clean::Null);
    }
    if let Some(statics) = &rule.statics {
        if !statics.contains(&text) {
            return Err(invalid(NOT_A_CHOICE));
        }
        return Ok(Clean::Text(text));
    }
    let options = options(rule, choices);
    if !options.is_empty() {
        if !options.contains(&Value::String(text.clone())) {
            return Err(invalid(NOT_AVAILABLE));
        }
        return Ok(Clean::Text(text));
    }
    if !rule.free_text {
        return Err(invalid(NO_CHOICES));
    }
    Ok(Clean::Text(text))
}

/// `_validate_checklist`（固定の選択肢だけを正とする）。
fn validate_checklist(rule: &Rule, raw: &Value) -> Result<Clean, Refused> {
    let items = match raw {
        Value::Null => return Ok(Clean::List(Vec::new())),
        Value::Array(items) => items,
        _ => return Err(invalid(NOT_A_LIST)),
    };
    let values: Vec<String> = items.iter().map(python::str_of).collect();
    let allowed: &[String] = rule.statics.as_deref().unwrap_or_default();
    if values.iter().any(|value| !allowed.contains(value)) {
        return Err(invalid(UNKNOWN_CHOICE));
    }
    Ok(Clean::List(values))
}

/// `_validate_text`（長さは削る前の文字で見る。上限を超えたものは黙って切らずに断る）。
fn validate_text(rule: &Rule, raw: &Value) -> Result<Clean, Refused> {
    let text = if raw.is_null() {
        String::new()
    } else {
        python::str_of(raw)
    };
    if let Some(max_len) = rule.max_len
        && text.chars().count() > max_len
    {
        return Err(Refused::Invalid(format!("{max_len} 文字以内で入力してください。")));
    }
    // `sanitize(text, field.max_len or MAX_STR_LEN)`。
    let limit = rule.max_len.filter(|n| *n != 0).unwrap_or_else(max_str_len);
    let mut text = sanitize(&text, limit);
    if rule.widget != Widget::Textarea {
        text = python::strip(&text).to_string();
    }
    if text.is_empty() {
        if rule.required || !rule.nullable {
            return Err(invalid(REQUIRED));
        }
        return Ok(Clean::Null);
    }
    Ok(Clean::Text(text))
}

/// `validate_field`（1 項目を検証し、書く関数へ渡せる値にする）。`choices` は `choices.resolve` の答え。
pub fn validate_field(
    rule: &Rule,
    raw: &Value,
    choices: &Map<String, Value>,
) -> Result<Clean, Refused> {
    match rule.widget {
        Widget::Channel | Widget::VoiceChannel | Widget::Role | Widget::Snowflake => {
            validate_id(rule, raw, choices)
        }
        Widget::Bool => Ok(coerce_bool(raw)),
        Widget::Int => validate_number(rule, raw, NOT_A_NUMBER, plain),
        Widget::Duration => validate_number(rule, raw, NOT_A_DURATION, humanize),
        Widget::Select => validate_select(rule, raw, choices),
        Widget::Checklist => validate_checklist(rule, raw),
        Widget::Text | Widget::Textarea => validate_text(rule, raw),
    }
}

/// 検証が通った値（鍵と値。届いた順・入力欄の順）。
pub type Cleaned = Vec<(String, Clean)>;

/// `validate_values`（パネルへの変更〔変えた項目だけ〕を検証する）。誤りは鍵 → 文（届いた順）。拾われない例外は `Err`。
pub fn validate_values(
    panel: &Panel,
    incoming: &Map<String, Value>,
    choices: &Map<String, Value>,
) -> Result<(Cleaned, Map<String, Value>), Crash> {
    let rules = panel_rules(&panel.id);
    let mut clean = Vec::new();
    let mut errors = Map::new();
    for (key, raw) in incoming {
        let Some(field) = panel.fields.iter().find(|field| &field.key == key) else {
            errors.insert(key.clone(), Value::String(UNKNOWN_FIELD.to_string()));
            continue;
        };
        if field.set.is_none() {
            errors.insert(key.clone(), Value::String(READ_ONLY.to_string()));
            continue;
        }
        let Some(rule) = rules.and_then(|rules| rules.field(key)) else {
            let message = format!("{}.{key} の規則が宣言に無い", panel.id);
            return Err(Crash::new("KeyError", message));
        };
        match validate_field(rule, raw, choices) {
            Ok(value) => clean.push((key.clone(), value)),
            Err(Refused::Invalid(message)) => {
                errors.insert(key.clone(), Value::String(message));
            }
            Err(Refused::Crash(crash)) => return Err(crash),
        }
    }
    Ok((clean, errors))
}

/// `validate_item`（一覧へ足す・変える 1 件を検証する。`partial` は使われていないので無い）。
pub fn validate_item(
    rules: &CollectionRules,
    incoming: &Map<String, Value>,
    choices: &Map<String, Value>,
) -> Result<(Cleaned, Map<String, Value>), Crash> {
    let mut clean = Vec::new();
    let mut errors = Map::new();
    for rule in &rules.fields {
        if !incoming.contains_key(&rule.key) && rule.required {
            errors.insert(rule.key.clone(), Value::String(REQUIRED.to_string()));
            continue;
        }
        let raw = incoming.get(&rule.key).unwrap_or(&NULL);
        match validate_field(rule, raw, choices) {
            Ok(value) => clean.push((rule.key.clone(), value)),
            Err(Refused::Invalid(message)) => {
                errors.insert(rule.key.clone(), Value::String(message));
            }
            Err(Refused::Crash(crash)) => return Err(crash),
        }
    }
    for key in incoming.keys() {
        if rules.field(key).is_none() {
            errors.insert(key.clone(), Value::String(UNKNOWN_ITEM_FIELD.to_string()));
        }
    }
    Ok((clean, errors))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rule(panel: &str, key: &str) -> &'static Rule {
        panel_rules(panel).unwrap().field(key).unwrap()
    }

    /// 宣言の全部の入力欄（パネルの直下と一覧）から規則が作れ、パネルの直下の鍵の並びが schema の fields と同じこと。
    #[test]
    fn every_field_of_the_schema_has_a_rule() {
        for panel in &schema::schema().panels {
            let rules = panel_rules(&panel.id).unwrap();
            let keys: Vec<&str> = rules.fields.iter().map(|r| r.key.as_str()).collect();
            let want: Vec<&str> = panel.fields.iter().map(|f| f.key.as_str()).collect();
            assert_eq!(keys, want, "{}", panel.id);
            let collections: Vec<&str> = rules.collections.iter().map(|c| c.key.as_str()).collect();
            let want: Vec<&str> = panel.collections.iter().map(|c| c.key.as_str()).collect();
            assert_eq!(collections, want, "{}", panel.id);
        }
        let feeds = panel_rules("news-feeds").unwrap().collection("feeds").unwrap();
        assert_eq!(feeds.max_items, Some(10));
        let interval = feeds.field("interval").unwrap();
        assert_eq!((interval.min, interval.max), (Some(5), Some(1440)));
        assert_eq!(interval.default, json!(60));
        assert!(rule("tts", "default_voice").free_text);
        assert_eq!(rule("tts", "default_voice").source, Some(ChoiceSource::TtsVoices));
        assert_eq!(rule("logging", "log_level").statics.as_ref().unwrap().len(), 4);
    }

    /// 文字の上限・期間の単位・真と読む文字・0 以下の単位が、Python のソースと同じであること。
    #[test]
    fn constants_match_python() {
        let security = include_str!("../../../../../webapp_admin/security.py");
        assert!(security.contains(&format!("MAX_STR_LEN = {}\n", max_str_len())));
        let duration = include_str!("../../../../../webapp_admin/schema/duration.py");
        assert!(duration.contains(&format!("return value, \"{SECOND_LABEL}\"")));
        for (label, factor) in &vocabulary().units {
            assert!(duration.contains(&format!("(\"{label}\", ")), "{label}");
            assert!(*factor > 0);
        }
        let types = include_str!("../../../../../webapp_admin/schema/types_def.py");
        let words: Vec<String> = TRUE_WORDS.iter().map(|w| format!("\"{w}\"")).collect();
        assert!(types.contains(&format!("in ({})", words.join(", "))));
        let validation = include_str!("../../../../../webapp_admin/schema/validation.py");
        for message in [
            CHOOSE,
            NOT_AN_ID,
            NOT_IN_LIST,
            NOT_A_NUMBER,
            NOT_A_DURATION,
            NOT_A_CHOICE,
            NOT_AVAILABLE,
            NO_CHOICES,
            NOT_A_LIST,
            UNKNOWN_CHOICE,
            REQUIRED,
            UNKNOWN_FIELD,
            READ_ONLY,
            UNKNOWN_ITEM_FIELD,
        ] {
            assert!(validation.contains(&format!("\"{message}\"")), "{message}");
        }
    }

    /// 期間の書き方（割り切れる一番大きい単位。0 以下と割り切れないものは秒）。
    #[test]
    fn durations_are_humanized_like_python() {
        assert_eq!(humanize(60), "1分");
        assert_eq!(humanize(2_592_000), "30日");
        assert_eq!(humanize(3600), "1時間");
        assert_eq!(humanize(90), "90秒");
        assert_eq!(humanize(0), "0秒");
        assert_eq!(humanize(-5), "-5秒");
    }

    /// ID: 未設定・数字でない・上付きの数字（拾われない ValueError）・一覧の中か。
    #[test]
    fn ids_are_checked_like_validate_id() {
        let channel = rule("logging", "log_channel_id");
        let none = Map::new();
        let full = json!({"channels": [{"value": "12", "label": "# a"}]});
        let full = full.as_object().unwrap();
        assert_eq!(validate_field(channel, &json!(false), &none), Ok(Clean::Null));
        assert_eq!(validate_field(channel, &json!(" 012 "), &none), Ok(Clean::Int("12".into())));
        assert_eq!(validate_field(channel, &json!(" 12 "), full), Ok(Clean::Int("12".into())));
        assert_eq!(validate_field(channel, &json!("012"), full), Err(invalid(NOT_IN_LIST)));
        assert_eq!(validate_field(channel, &json!("00"), &none), Err(invalid(NOT_AN_ID)));
        assert_eq!(validate_field(channel, &json!("1_2"), &none), Err(invalid(NOT_AN_ID)));
        assert_eq!(validate_field(channel, &json!("１２"), &none), Ok(Clean::Int("12".into())));
        let crash = validate_field(channel, &json!("²"), &none).unwrap_err();
        assert_eq!(
            crash,
            Refused::Crash(Crash::new(
                "ValueError",
                "invalid literal for int() with base 10: '²'"
            ))
        );
    }

    /// 文字: 長さは削る前に数え、NUL と改行をそろえ、1 行なら前後の空白を落とし、空は未設定か必須の文。
    #[test]
    fn texts_are_checked_like_validate_text() {
        let dictionary = panel_rules("tts").unwrap().collection("dictionary").unwrap();
        let word = dictionary.field("word").unwrap();
        let none = Map::new();
        let raw = json!(" a\u{0}b\r\n ");
        assert_eq!(validate_field(word, &raw, &none), Ok(Clean::Text("ab".into())));
        assert_eq!(validate_field(word, &json!("   "), &none), Err(invalid(REQUIRED)));
        let long = "x".repeat(51);
        assert_eq!(
            validate_field(word, &json!(long), &none),
            Err(Refused::Invalid("50 文字以内で入力してください。".into()))
        );
        let message = rule("welcome", "welcome_message");
        let kept = Ok(Clean::Text("  a\nb  ".into()));
        assert_eq!(validate_field(message, &json!("  a\rb  "), &none), kept);
        assert_eq!(validate_field(message, &json!(""), &none), Ok(Clean::Null));
        assert_eq!(validate_field(message, &json!(5), &none), Ok(Clean::Text("5".into())));
    }
}
