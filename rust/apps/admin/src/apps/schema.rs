//! 設定パネルの宣言。Python の `webapp_admin/schema/`（`types_def.py` の `Panel`・`Section`・`Field`・`Collection`・
//! `Widget`・`ChoiceSource` と、`registry.py` の `PANELS`）を JSON に書き出したもの（`tests/fixtures/schema/schema.json`。
//! CI の「基準」が `tests/fixtures/schema/generate.py` で作る）を、ビルドのときに焼き込む（スラッシュコマンドの
//! `definitions.json` と同じやり方。計画の 7. と 11. の 1）。
//!
//! - 画面へ返す形は `wire`（`Panel.to_json()` そのもの。キーの並びも Python のまま）をそのまま使う。本文がバイトまで
//!   同じになる
//! - 値を出し入れする関数は名前（`webapp_admin.schema.panels.logging._log_channel` など）で持つ。読む関数の中身は
//!   [`crate::apps::getters`]（名前 → Rust の関数の表）
//! - 入力欄の種類・既定値・選択肢の供給元は `wire` から読む（`Field.choice_source` は、宣言に供給元が書いてあれば
//!   それ、無ければ種類から決まる供給元。`IMPLIED_SOURCE`）
//!
//! 宣言を変えたら（Python の panels/ を直したら）CI の「基準」が `schema.json` を作り直し、それをコミットすると
//! Rust の管理画面も同じ宣言で動く。宣言に入力欄が増えたのに Rust に読む関数が無ければ、
//! `getters::tests::every_schema_function_has_a_rust_getter` が落ちる。

use std::sync::OnceLock;

use serde_json::{Map, Value};

use crate::python;

/// 焼き込んだ宣言（`tests/fixtures/schema/schema.json`）。
pub const SCHEMA_JSON: &str = include_str!("../../tests/fixtures/schema/schema.json");

/// 入力欄の種類（`Widget`。クライアントの描画とサーバの検証が同じ語を使う）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Widget {
    /// `text`。
    Text,
    /// `textarea`。
    Textarea,
    /// `int`。
    Int,
    /// `duration`（値は秒）。
    Duration,
    /// `bool`。
    Bool,
    /// `select`。
    Select,
    /// `channel`。
    Channel,
    /// `voice_channel`。
    VoiceChannel,
    /// `role`。
    Role,
    /// `checklist`。
    Checklist,
    /// `snowflake`。
    Snowflake,
}

impl Widget {
    /// Python の `Widget` の並び（`schema.json` の `vocabulary.widgets` と同じ）。
    pub const ALL: [Self; 11] = [
        Self::Text,
        Self::Textarea,
        Self::Int,
        Self::Duration,
        Self::Bool,
        Self::Select,
        Self::Channel,
        Self::VoiceChannel,
        Self::Role,
        Self::Checklist,
        Self::Snowflake,
    ];

    /// 宣言に書く語。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Textarea => "textarea",
            Self::Int => "int",
            Self::Duration => "duration",
            Self::Bool => "bool",
            Self::Select => "select",
            Self::Channel => "channel",
            Self::VoiceChannel => "voice_channel",
            Self::Role => "role",
            Self::Checklist => "checklist",
            Self::Snowflake => "snowflake",
        }
    }

    /// 語から引く。
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|widget| widget.as_str() == text)
    }

    /// 種類から決まる選択肢の供給元（`IMPLIED_SOURCE`）。
    pub fn implied_source(self) -> Option<ChoiceSource> {
        match self {
            Self::Channel => Some(ChoiceSource::Channels),
            Self::VoiceChannel => Some(ChoiceSource::VoiceChannels),
            Self::Role => Some(ChoiceSource::Roles),
            _ => None,
        }
    }

    /// 値を Discord の ID として扱う種類か（`_ID_WIDGETS`）。
    fn is_id(self) -> bool {
        matches!(
            self,
            Self::Channel | Self::VoiceChannel | Self::Role | Self::Snowflake
        )
    }
}

/// 実行時に解決する選択肢の供給元（`ChoiceSource`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChoiceSource {
    /// `channels`（テキストチャンネル）。
    Channels,
    /// `voice_channels`。
    VoiceChannels,
    /// `roles`。
    Roles,
    /// `tts_voices`（読み上げの声）。
    TtsVoices,
}

impl ChoiceSource {
    /// Python の `ChoiceSource` の並び（`schema.json` の `vocabulary.choice_sources` と同じ）。
    pub const ALL: [Self; 4] = [
        Self::Channels,
        Self::VoiceChannels,
        Self::Roles,
        Self::TtsVoices,
    ];

    /// 宣言に書く語（`choices` の鍵）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Channels => "channels",
            Self::VoiceChannels => "voice_channels",
            Self::Roles => "roles",
            Self::TtsVoices => "tts_voices",
        }
    }

    /// 語から引く。
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|source| source.as_str() == text)
    }
}

/// パネルの直下の入力欄 1 つ（`Field` のうち、読む側が要るもの）。
#[derive(Clone, Debug, PartialEq)]
pub struct FieldSpec {
    /// 鍵（`values` の鍵）。
    pub key: String,
    /// 種類。
    pub widget: Widget,
    /// 既定値（`Field.default`。宣言に無ければ null）。
    pub default: Value,
    /// 選択肢の供給元（`Field.choice_source`）。
    pub source: Option<ChoiceSource>,
    /// 値を読む関数の名前（`Field.get`）。
    pub get: Option<String>,
    /// 値を書く関数の名前（`Field.set`。A6 が使う）。
    pub set: Option<String>,
}

/// パネルの一覧 1 つ（`Collection` のうち、読む側が要るもの）。
#[derive(Clone, Debug, PartialEq)]
pub struct CollectionSpec {
    /// 鍵（`collections` の鍵）。
    pub key: String,
    /// 一覧を読む関数の名前（`Collection.list`）。
    pub list: Option<String>,
    /// 1 件足す関数の名前（A6）。
    pub add: Option<String>,
    /// 1 件変える関数の名前（A6）。
    pub update: Option<String>,
    /// 1 件消す関数の名前（A6）。
    pub remove: Option<String>,
    /// 入力欄の選択肢の供給元（入力欄の順。重なりは残す）。
    pub item_sources: Vec<ChoiceSource>,
}

/// パネル 1 枚（`Panel`）。
#[derive(Clone, Debug, PartialEq)]
pub struct Panel {
    /// ID（`app_id`）。
    pub id: String,
    /// グループの名前（スタートメニューの見出し）。
    pub group: String,
    /// 開発者だけに見せるか。
    pub dev_only: bool,
    /// 宣言から描けない画面か（値を読まない）。
    pub custom: bool,
    /// バッジを数える関数の名前（`Panel.badge`）。
    pub badge: Option<String>,
    /// `Panel.to_json()`（GET /admin/api/apps/{id} の本文の元）。
    pub wire: Map<String, Value>,
    /// `Panel.tile()`（バッジは null。数は実行時に数える）。
    pub tile: Map<String, Value>,
    /// 直下の入力欄（`Panel.fields`。セクションの順に平らにしたもの）。
    pub fields: Vec<FieldSpec>,
    /// 一覧（`Panel.collections`）。
    pub collections: Vec<CollectionSpec>,
    /// パネルを開くときに解決する供給元（`Panel.choice_sources()` を、`choices.resolve` と同じく語の順に並べたもの）。
    pub sources: Vec<ChoiceSource>,
}

/// 宣言の全体。
#[derive(Clone, Debug, PartialEq)]
pub struct Schema {
    /// パネル（`PANELS` の並び。スタートメニューの並び）。
    pub panels: Vec<Panel>,
}

impl Schema {
    /// ID でパネルを引く（`PANEL_BY_ID.get`）。
    pub fn panel(&self, id: &str) -> Option<&Panel> {
        self.panels.iter().find(|panel| panel.id == id)
    }
}

/// 焼き込んだ宣言（最初に使うときに 1 回だけ読む）。
///
/// 読めないのはビルドの誤り（`schema.json` を手で壊した）なので止まる。`schema::tests` と起動のとき
/// （[`crate::apps::Panels::new`]）にも読むので、本番の要求の途中で初めて気づくことは無い。
pub fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        parse(SCHEMA_JSON)
            .unwrap_or_else(|e| panic!("焼き込んだ schema.json を読めません（ビルドの誤り）: {e}"))
    })
}

fn text_of(value: &Value, what: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{what} が文字ではない"))
}

fn name_of(value: &Value, what: &str) -> Result<Option<String>, String> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(format!("{what} が文字でも null でもない")),
    }
}

fn object_of<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{what} が辞書ではない"))
}

fn array_of<'a>(value: &'a Value, what: &str) -> Result<&'a [Value], String> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{what} が並びではない"))
}

/// `wire` の入力欄 1 つから、種類・既定値・供給元を読む。
fn wire_field(field: &Value, what: &str) -> Result<(Widget, Value, Option<ChoiceSource>), String> {
    let widget_text = text_of(&field["widget"], &format!("{what}.widget"))?;
    let widget =
        Widget::parse(&widget_text).ok_or_else(|| format!("{what}: 知らない種類 {widget_text}"))?;
    let default = field.get("default").cloned().unwrap_or(Value::Null);
    let source = match field.get("choice_source") {
        Some(Value::String(text)) => Some(
            ChoiceSource::parse(text)
                .ok_or_else(|| format!("{what}: 知らない供給元 {text}"))?,
        ),
        Some(_) => return Err(format!("{what}.choice_source が文字ではない")),
        None => widget.implied_source(),
    };
    Ok((widget, default, source))
}

/// `wire` の何番目かのセクションの、`kind`（`fields`・`collections`）の中から鍵の合うものを引く。
fn wire_item<'a>(
    sections: &'a [Value],
    index: &Value,
    kind: &str,
    key: &str,
    what: &str,
) -> Result<&'a Value, String> {
    let index = index
        .as_u64()
        .and_then(|i| usize::try_from(i).ok())
        .ok_or_else(|| format!("{what}.section が数ではない"))?;
    let section = sections
        .get(index)
        .ok_or_else(|| format!("{what}: セクション {index} が wire に無い"))?;
    array_of(&section[kind], &format!("{what} のセクションの {kind}"))?
        .iter()
        .find(|item| item["key"].as_str() == Some(key))
        .ok_or_else(|| format!("{what}: {key} が wire のセクション {index} に無い"))
}

fn parse_panel(panel: &Value) -> Result<Panel, String> {
    let id = text_of(&panel["id"], "panels[].id")?;
    let wire = object_of(&panel["wire"], &format!("{id}.wire"))?.clone();
    let tile = object_of(&panel["tile"], &format!("{id}.tile"))?.clone();
    let group = text_of(&panel["wire"]["group"], &format!("{id}.wire.group"))?;
    let sections = array_of(&panel["wire"]["sections"], &format!("{id}.wire.sections"))?;
    let mut fields = Vec::new();
    for field in array_of(&panel["fields"], &format!("{id}.fields"))? {
        let key = text_of(&field["key"], &format!("{id}.fields[].key"))?;
        let what = format!("{id}.{key}");
        let item = wire_item(sections, &field["section"], "fields", &key, &what)?;
        let (widget, default, source) = wire_field(item, &what)?;
        fields.push(FieldSpec {
            get: name_of(&field["get"], &format!("{what}.get"))?,
            set: name_of(&field["set"], &format!("{what}.set"))?,
            key,
            widget,
            default,
            source,
        });
    }
    let mut collections = Vec::new();
    for collection in array_of(&panel["collections"], &format!("{id}.collections"))? {
        let key = text_of(&collection["key"], &format!("{id}.collections[].key"))?;
        let what = format!("{id}.{key}");
        let item = wire_item(
            sections,
            &collection["section"],
            "collections",
            &key,
            &what,
        )?;
        let mut item_sources = Vec::new();
        for (i, item_field) in array_of(&item["fields"], &format!("{what}.fields"))?
            .iter()
            .enumerate()
        {
            if let (_, _, Some(source)) = wire_field(item_field, &format!("{what}.fields[{i}]"))? {
                item_sources.push(source);
            }
        }
        collections.push(CollectionSpec {
            list: name_of(&collection["list"], &format!("{what}.list"))?,
            add: name_of(&collection["add"], &format!("{what}.add"))?,
            update: name_of(&collection["update"], &format!("{what}.update"))?,
            remove: name_of(&collection["remove"], &format!("{what}.remove"))?,
            key,
            item_sources,
        });
    }
    // `Panel.choice_sources()` は集合。`choices.resolve` が語の順に並べ直して 1 回ずつ取る。
    let mut sources: Vec<ChoiceSource> = fields
        .iter()
        .filter_map(|field| field.source)
        .chain(
            collections
                .iter()
                .flat_map(|collection| collection.item_sources.iter().copied()),
        )
        .collect();
    sources.sort_by_key(|source| source.as_str());
    sources.dedup();
    Ok(Panel {
        dev_only: panel["dev_only"].as_bool().unwrap_or(false),
        custom: panel["custom"].as_bool().unwrap_or(false),
        badge: name_of(&panel["badge"], &format!("{id}.badge"))?,
        id,
        group,
        wire,
        tile,
        fields,
        collections,
        sources,
    })
}

/// `schema.json` の文字を読む。
pub fn parse(text: &str) -> Result<Schema, String> {
    let document: Value = serde_json::from_str(text).map_err(|e| format!("JSON ではない: {e}"))?;
    let panels = array_of(&document["panels"], "panels")?
        .iter()
        .map(parse_panel)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Schema { panels })
}

/// `value in (None, 0, "0", "")`（Python の `==` で比べる。`False == 0`・`0.0 == 0` も当たる）。
fn is_unset_id(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !*b,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty() || text == "0",
        Value::Array(_) | Value::Object(_) => false,
    }
}

/// Python の整数の 10 進の文字を JSON の値にする。64 ビットに収まらないものは文字のまま（出口の `SafeJSONResponse` が
/// 2^53-1 を超える整数を文字にするので、答えの本文は Python と同じ）。
pub fn int_value(text: &str) -> Value {
    if let Ok(i) = text.parse::<i64>() {
        return Value::from(i);
    }
    if let Ok(u) = text.parse::<u64>() {
        return Value::from(u);
    }
    Value::String(text.to_string())
}

/// `Field.to_json_value`。保存されている値を、画面が選択肢と比べられる形にする。
///
/// - ID の種類（チャンネル・ボイス・ロール・スノーフレーク）: 未設定（None・0・"0"・""）は null、ほかは `str()`
/// - 真偽: `bool()`
/// - チェックの一覧: 辞書なら真の鍵、並びなら要素を `str()`、ほかは空
/// - 数・期間: `int()`。読めなければ既定値
/// - ほか: null はそのまま、ほかは `str()`
pub fn to_json_value(widget: Widget, default: &Value, value: &Value) -> Value {
    if widget.is_id() {
        if is_unset_id(value) {
            return Value::Null;
        }
        return Value::String(python::str_of(value));
    }
    match widget {
        Widget::Bool => Value::Bool(python::truthy(value)),
        Widget::Checklist => match value {
            Value::Object(map) => Value::Array(
                map.iter()
                    .filter(|(_, enabled)| python::truthy(enabled))
                    .map(|(key, _)| Value::String(key.clone()))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| Value::String(python::str_of(item)))
                    .collect(),
            ),
            _ => Value::Array(Vec::new()),
        },
        Widget::Int | Widget::Duration => match python::int_text(value) {
            Some(text) => int_value(&text),
            None => default.clone(),
        },
        _ => match value {
            Value::Null => Value::Null,
            other => Value::String(python::str_of(other)),
        },
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn document() -> Value {
        serde_json::from_str(SCHEMA_JSON).unwrap()
    }

    /// 焼き込んだ宣言が読め、パネルの並びと数が `schema.json` と同じで、Python の検査（`registry.validate()`）に
    /// 誤りが無いこと。
    #[test]
    fn the_baked_schema_is_read_in_python_order() {
        let document = document();
        let ids: Vec<&str> = schema().panels.iter().map(|p| p.id.as_str()).collect();
        let want: Vec<&str> = document["panels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, want);
        assert!(ids.len() >= 15, "パネルが足りない（{}）", ids.len());
        assert_eq!(document["problems"], json!([]));
    }

    /// Rust の語の表が、宣言の語彙（`vocabulary`）と同じ並び・同じ中身であること（Python に種類や供給元が増えたら
    /// ここで落ちる）。
    #[test]
    fn the_vocabulary_matches_python() {
        let vocabulary = &document()["vocabulary"];
        let widgets: Vec<&str> = Widget::ALL.iter().map(|w| w.as_str()).collect();
        assert_eq!(json!(widgets), vocabulary["widgets"]);
        let sources: Vec<&str> = ChoiceSource::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(json!(sources), vocabulary["choice_sources"]);
        let mut implied = Map::new();
        for widget in Widget::ALL {
            if let Some(source) = widget.implied_source() {
                implied.insert(widget.as_str().to_string(), json!(source.as_str()));
            }
        }
        assert_eq!(Value::Object(implied), vocabulary["implied_sources"]);
    }

    /// 開くときに取る供給元（`Panel.choice_sources()` を語の順に）。TTS は 3 つ、VC 通知はチャンネルとロール、
    /// ログはチャンネルだけ、custom は無し。
    #[test]
    fn panels_list_their_choice_sources_in_name_order() {
        let sources = |id: &str| -> Vec<&str> {
            schema()
                .panel(id)
                .unwrap()
                .sources
                .iter()
                .map(|s| s.as_str())
                .collect()
        };
        assert_eq!(sources("tts"), ["channels", "tts_voices", "voice_channels"]);
        assert_eq!(sources("vc-notify"), ["channels", "roles"]);
        assert_eq!(sources("logging"), ["channels"]);
        assert_eq!(sources("security"), ["roles"]);
        assert_eq!(sources("reaction-roles"), ["roles"]);
        assert!(sources("monitoring").is_empty());
        assert!(schema().panel("nothing").is_none());
    }

    /// 入力欄の種類と既定値が wire から読めていること（ログのレベルは選択・既定 INFO、地震の最小震度は選択・既定 30）。
    #[test]
    fn fields_carry_their_widget_and_default() {
        let logging = schema().panel("logging").unwrap();
        let level = logging.fields.iter().find(|f| f.key == "log_level").unwrap();
        assert_eq!(level.widget, Widget::Select);
        assert_eq!(level.default, json!("INFO"));
        assert_eq!(level.source, None);
        let channel = &logging.fields[0];
        assert_eq!(channel.key, "log_channel_id");
        assert_eq!(channel.default, Value::Null);
        assert_eq!(channel.source, Some(ChoiceSource::Channels));
        let quake = schema().panel("earthquake").unwrap();
        assert_eq!(quake.fields[1].default, json!(30));
        let tts = schema().panel("tts").unwrap();
        let voice = tts.fields.iter().find(|f| f.key == "default_voice").unwrap();
        assert_eq!(voice.source, Some(ChoiceSource::TtsVoices));
    }

    /// `to_json_value` の手で書いた例（Python の値の比べ方: `False == 0`・`0.0 == 0`、`str()` の書き方、`int()` の読み方）。
    /// 全部の種類 × 値の表は基準 `getters/`。
    #[test]
    fn values_are_normalised_like_to_json_value() {
        let null = Value::Null;
        assert_eq!(to_json_value(Widget::Channel, &null, &json!(false)), null);
        assert_eq!(to_json_value(Widget::Role, &null, &json!(-0.0)), null);
        assert_eq!(to_json_value(Widget::Role, &null, &json!("0")), null);
        assert_eq!(
            to_json_value(Widget::Channel, &null, &json!(800_000_000_000_000_001_u64)),
            json!("800000000000000001")
        );
        assert_eq!(
            to_json_value(Widget::Snowflake, &null, &json!(1.5)),
            json!("1.5")
        );
        assert_eq!(to_json_value(Widget::Bool, &null, &json!("0")), json!(true));
        assert_eq!(
            to_json_value(Widget::Checklist, &null, &json!({"a": true, "b": 0, "c": [1]})),
            json!(["a", "c"])
        );
        assert_eq!(
            to_json_value(Widget::Checklist, &null, &json!([1, "x", null])),
            json!(["1", "x", "None"])
        );
        assert_eq!(to_json_value(Widget::Checklist, &null, &json!("ab")), json!([]));
        assert_eq!(
            to_json_value(Widget::Int, &json!(60), &json!(" １２ ")),
            json!(12)
        );
        assert_eq!(
            to_json_value(Widget::Duration, &json!(600), &json!("abc")),
            json!(600)
        );
        assert_eq!(to_json_value(Widget::Text, &null, &json!(true)), json!("True"));
        assert_eq!(to_json_value(Widget::Select, &null, &null), null);
        assert_eq!(int_value("18446744073709551616"), json!("18446744073709551616"));
        assert_eq!(int_value("-5"), json!(-5));
    }

    /// 宣言の形が崩れていたら、どこが崩れているかの文で失敗すること（起動で止まる）。
    #[test]
    fn broken_schemas_are_rejected_with_a_reason() {
        assert!(parse("[").unwrap_err().contains("JSON"));
        let mut document = document();
        document["panels"][2]["wire"]["sections"][0]["fields"][0]["widget"] = json!("slider");
        let error = parse(&document.to_string()).unwrap_err();
        assert!(error.contains("slider"), "{error}");
    }
}
