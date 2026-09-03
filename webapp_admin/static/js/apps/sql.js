/* SQL エディタ（開発者専用）。

   左にオブジェクトの木、右上にエディタ、右下に結果。pgAdmin でよくやることを
   ひととおり: 表を覗く・DDL を見る・SQL を書いて実行する・結果を CSV に出す。

   実行は既定で読み取り専用（Postgres 側の READ ONLY トランザクション）。
   書き込みは明示的に切り替えたときだけで、切り替えは1回ごとに確認する。 */

import * as api from "../lib/api.js";
import { el, icon, clear, loading } from "../lib/dom.js";
import { toast } from "../lib/toast.js";

const BASE = "/admin/api/sql";
const PREF_KEY = "sycs.sql.prefs";
const DRAFT_KEY = "sycs.sql.draft";
const HISTORY_KEY = "sycs.sql.history";
const HISTORY_MAX = 50;

/* ── 覚え書き（この画面の設定と下書き） ─────────────────── */

function readStore(key, fallback) {
  try {
    return JSON.parse(window.localStorage.getItem(key) || "") ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStore(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* 保存できなくても画面は動く */
  }
}

/* ── 見た目（この画面でしか使わない CSS を必要になってから読む） ── */

function ensureStyles() {
  if (document.getElementById("sql-css")) return;
  document.head.append(
    el("link", { id: "sql-css", rel: "stylesheet", href: "/static/css/sql.css" })
  );
}

/* ── SQL の色分け ────────────────────────────────────────── */

const KEYWORDS = new Set(`
  select from where group by having order limit offset insert into values update set delete
  create alter drop table view index unique primary key foreign references constraint
  join inner left right full outer cross on using union all except intersect distinct
  and or not null is in like ilike between exists case when then else end as asc desc
  with recursive returning conflict do nothing begin commit rollback explain analyze
  analyse verbose grant revoke truncate cascade restrict default check column add rename
  materialized refresh function trigger sequence schema database extension if else
  count sum avg min max coalesce nullif cast now current_timestamp current_date interval
  array unnest generate_series jsonb_agg json_agg string_agg row_number over partition
  true false lateral offset fetch first next rows only window filter
`.trim().split(/\s+/));

const TOKEN = /(--[^\n]*|\/\*[\s\S]*?\*\/)|('(?:[^']|'')*'|\$\$[\s\S]*?\$\$|"(?:[^"]|"")*")|(\b\d+(?:\.\d+)?\b)|([A-Za-z_][A-Za-z0-9_$]*)|(\s+)|([^\s\w])/g;

/** 色分けした断片を <pre> に流し込む（innerHTML は使わない）。 */
function paint(target, sql) {
  const parts = [];
  let match;
  TOKEN.lastIndex = 0;
  while ((match = TOKEN.exec(sql)) !== null) {
    const [text, comment, literal, number, word, space, symbol] = match;
    if (comment) parts.push(["c", text]);
    else if (literal) parts.push(["s", text]);
    else if (number) parts.push(["n", text]);
    else if (word) parts.push([KEYWORDS.has(text.toLowerCase()) ? "k" : "", text]);
    else if (space) parts.push(["", text]);
    else if (symbol) parts.push(["o", text]);
  }
  clear(target).append(
    ...parts.map(([kind, text]) =>
      kind ? el("span", { class: `tok-${kind}`, text }) : document.createTextNode(text)
    ),
    // 最終行が空でも行の高さを保つ
    document.createTextNode("\n")
  );
}

/* ── 小さな部品 ─────────────────────────────────────────── */

const bytes = (n) => {
  if (!n) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
};

const KIND_LABEL = { r: "テーブル", p: "テーブル", v: "ビュー", m: "マテビュー", f: "外部表" };

/* 木の欄は狭いので、Postgres の長い型名は短い別名で出す（psql の表記に寄せる）。 */
const TYPE_ALIAS = [
  ["timestamp with time zone", "timestamptz"],
  ["timestamp without time zone", "timestamp"],
  ["time with time zone", "timetz"],
  ["character varying", "varchar"],
  ["double precision", "float8"],
  ["boolean", "bool"],
  ["integer", "int4"],
  ["bigint", "int8"],
  ["smallint", "int2"],
];

function shortType(type) {
  for (const [long, short] of TYPE_ALIAS) {
    if (type.startsWith(long)) return short + type.slice(long.length);
  }
  return type;
}

/** 予約語や大文字を含む名前だけ引用符で包む。 */
function ident(name) {
  return /^[a-z_][a-z0-9_]*$/.test(name) && !KEYWORDS.has(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

function toolButton(label, iconName, onclick, extraClass = "") {
  return el("button", { class: `btn btn-sm ${extraClass}`, type: "button", onclick }, icon(iconName), label);
}

/* ── 本体 ───────────────────────────────────────────────── */

export async function mount(win) {
  ensureStyles();
  win.body.classList.add("is-plain");
  clear(win.body).append(loading("接続先を調べています…"));

  let servers;
  try {
    ({ servers } = await api.get(`${BASE}/servers`));
  } catch (error) {
    clear(win.body).append(el("div", { class: "empty sql-fatal", text: `接続先を取得できませんでした（${error.message}）` }));
    return;
  }
  if (!servers.length) {
    clear(win.body).append(el("div", { class: "empty sql-fatal", text: "接続先が設定されていません。" }));
    return;
  }

  const prefs = readStore(PREF_KEY, {});
  const state = {
    servers,
    server: servers.find((s) => s.id === prefs.server) || servers[0],
    database: null,
    limit: Number(prefs.limit) || 500,
    timeout: Number(prefs.timeout) || 15,
    write: false,          // 書き込みは開くたびに切る
    objects: null,
    running: null,
    results: [],
  };
  const databases = state.server.databases.map((d) => d.name);
  state.database = databases.includes(prefs.database) ? prefs.database : (databases[0] || state.server.defaultDatabase);

  const ui = buildLayout(win, state);
  clear(win.body).append(ui.root);
  ui.setServer(state.server, state.database);
  await ui.loadObjects();
  ui.editor.focus();
}

function buildLayout(win, state) {
  /* ── 上部の操作列 ─────────────────────────────────────── */
  const serverSelect = el(
    "select",
    { class: "select sql-select", onchange: () => selectServer(serverSelect.value) },
    state.servers.map((server) =>
      el("option", { value: server.id, text: server.label, selected: server.id === state.server.id })
    )
  );
  const databaseSelect = el("select", { class: "select sql-select", onchange: () => selectDatabase(databaseSelect.value) });
  const limitInput = el("input", {
    class: "input sql-number", type: "number", min: "1", max: "5000", value: String(state.limit),
    title: "取り出す行の上限",
    onchange: () => { state.limit = clampNumber(limitInput, 1, 5000, 500); savePrefs(); },
  });
  const timeoutInput = el("input", {
    class: "input sql-number", type: "number", min: "1", max: "120", value: String(state.timeout),
    title: "1文あたりの制限時間（秒）",
    onchange: () => { state.timeout = clampNumber(timeoutInput, 1, 120, 15); savePrefs(); },
  });

  const modeButton = el("button", { class: "btn btn-sm sql-mode", type: "button", onclick: toggleMode });
  const runButton = el("button", { class: "btn btn-sm btn-primary", type: "button", onclick: run },
                       icon("bi-play-fill"), "実行");
  const cancelButton = el("button", { class: "btn btn-sm btn-danger", type: "button", hidden: true, onclick: cancel },
                          icon("bi-slash-circle-fill"), "中止");
  const status = el("span", { class: "sql-status small muted" });

  const bar = el(
    "div",
    { class: "sql-bar" },
    serverSelect,
    databaseSelect,
    el("button", {
      class: "btn btn-sm btn-quiet btn-icon", type: "button", title: "オブジェクトを読み直す",
      "aria-label": "オブジェクトを読み直す", onclick: () => loadObjects(true),
    }, icon("bi-arrow-clockwise")),
    el("span", { class: "sql-bar-sep" }),
    runButton,
    cancelButton,
    modeButton,
    el("label", { class: "sql-bar-label small muted" }, "上限", limitInput),
    el("label", { class: "sql-bar-label small muted" }, "秒", timeoutInput),
    el("span", { class: "row-end" }),
    status
  );

  /* ── 左: オブジェクトの木 ─────────────────────────────── */
  const filter = el("input", {
    class: "input sql-filter", type: "search", placeholder: "テーブルを絞り込み…",
    oninput: () => renderTree(),
  });
  const tree = el("div", { class: "sql-tree" });
  const side = el("div", { class: "sql-side" }, el("div", { class: "sql-side-head" }, filter), tree);

  /* ── 右上: エディタ ───────────────────────────────────── */
  const gutter = el("div", { class: "sql-gutter", "aria-hidden": "true" });
  const highlight = el("pre", { class: "sql-highlight", "aria-hidden": "true" });
  const editor = el("textarea", {
    class: "sql-input", spellcheck: "false", autocomplete: "off", autocapitalize: "off",
    wrap: "off", "aria-label": "SQL",
    oninput: sync,
    onscroll: syncScroll,
    onkeydown: onKeyDown,
    onclick: () => closeSuggest(),
    // 変換中は下地（色付き）を隠して素の文字を見せる。透明のままだと
    // 日本語を打っている最中だけ何も見えなくなる。
    oncompositionstart: () => code.classList.add("is-composing"),
    oncompositionend: () => { code.classList.remove("is-composing"); sync(); },
  });
  const suggest = el("div", { class: "sql-suggest", hidden: true });
  const code = el("div", { class: "sql-code" }, gutter, el("div", { class: "sql-code-inner" }, highlight, editor, suggest));

  /* ── 右下: 結果 ───────────────────────────────────────── */
  const resultTabs = el("div", { class: "sql-result-tabs" });
  const resultBody = el("div", { class: "sql-result-body" });
  const results = el("div", { class: "sql-results" }, resultTabs, resultBody);

  const splitter = el("div", { class: "sql-splitter", title: "ドラッグで高さを変える" });
  const main = el("div", { class: "sql-main" }, bar, code, splitter, results);
  const root = el("div", { class: "sql-app" }, side, main);

  wireSplitter(splitter, code);

  /* ── 状態と描画 ───────────────────────────────────────── */

  function savePrefs() {
    writeStore(PREF_KEY, {
      server: state.server.id, database: state.database, limit: state.limit, timeout: state.timeout,
    });
  }

  function draftKey() {
    return `${DRAFT_KEY}.${state.server.id}.${state.database}`;
  }

  function setServer(server, database) {
    state.server = server;
    state.database = database;
    clear(databaseSelect).append(
      ...(server.databases.length ? server.databases : [{ name: database }]).map((db) =>
        el("option", {
          value: db.name,
          text: db.bytes ? `${db.name}（${bytes(db.bytes)}）` : db.name,
          selected: db.name === database,
        })
      )
    );
    editor.value = readStore(draftKey(), "") || defaultQuery();
    sync();
    renderMode();
    if (server.error) toast(`${server.label}: ${server.error}`, "danger", { duration: 8000 });
    savePrefs();
  }

  function selectServer(id) {
    const server = state.servers.find((s) => s.id === id);
    if (!server) return;
    const first = server.databases[0]?.name || server.defaultDatabase;
    setServer(server, first);
    loadObjects();
  }

  function selectDatabase(name) {
    saveDraft();
    state.database = name;
    editor.value = readStore(draftKey(), "") || defaultQuery();
    sync();
    savePrefs();
    loadObjects();
  }

  function defaultQuery() {
    return "-- Ctrl+Enter で実行（選択範囲があればその部分だけ）\nSELECT now();\n";
  }

  function saveDraft() {
    writeStore(draftKey(), editor.value);
  }

  /* ── 木 ───────────────────────────────────────────────── */

  async function loadObjects(notify = false) {
    clear(tree).append(loading("オブジェクトを読み込み中…"));
    try {
      state.objects = await api.get(
        `${BASE}/objects?server=${encodeURIComponent(state.server.id)}&database=${encodeURIComponent(state.database)}`
      );
      renderTree();
      if (notify) toast("オブジェクトを読み直しました", "success");
    } catch (error) {
      state.objects = null;
      clear(tree).append(el("div", { class: "empty", text: error.message }));
    }
  }

  function renderTree() {
    if (!state.objects) return;
    const needle = filter.value.trim().toLowerCase();
    const nodes = [];
    for (const schema of state.objects.schemas) {
      const tables = schema.tables.filter(
        (table) => !needle || table.name.toLowerCase().includes(needle)
                || table.columns.some((column) => column.name.toLowerCase().includes(needle))
      );
      if (!tables.length) continue;
      nodes.push(
        el("div", { class: "sql-tree-schema" }, icon("bi-boxes"), schema.name,
           el("span", { class: "sql-tree-count", text: String(tables.length) })),
        ...tables.map((table) => tableNode(schema.name, table))
      );
    }
    clear(tree).append(
      ...(nodes.length ? nodes : [el("div", { class: "empty", text: needle ? "見つかりません" : "テーブルがありません" })])
    );
  }

  function tableNode(schemaName, table) {
    const columns = el("div", { class: "sql-tree-columns", hidden: true });
    const head = el(
      "div",
      { class: "sql-tree-table", title: `${KIND_LABEL[table.kind] || ""} 約 ${table.approxRows.toLocaleString()} 行 / ${bytes(table.bytes)}` },
      el("button", {
        class: "sql-tree-name", type: "button",
        onclick: () => {
          if (!columns.children.length) {
            columns.append(...table.columns.map(columnRow));
          }
          columns.hidden = !columns.hidden;
          head.classList.toggle("is-open", !columns.hidden);
        },
      }, icon(table.kind === "v" || table.kind === "m" ? "bi-file-text" : "bi-list"), table.name),
      el("span", { class: "sql-tree-actions" },
         el("button", {
           class: "sql-tree-action", type: "button", title: "先頭の行を見る",
           onclick: () => runSnippet(`SELECT * FROM ${ident(schemaName)}.${ident(table.name)} LIMIT ${state.limit};`),
         }, icon("bi-play-fill")),
         el("button", {
           class: "sql-tree-action", type: "button", title: "定義（DDL）",
           onclick: () => showDdl(schemaName, table.name),
         }, icon("bi-file-text")))
    );
    return el("div", { class: "sql-tree-item" }, head, columns);
  }

  function columnRow(column) {
    return el(
      "button",
      {
        class: "sql-tree-column", type: "button",
        title: `${column.name} ${column.type}${column.default ? `（既定値: ${column.default}）` : ""}`,
        onclick: () => insertAtCaret(column.name),
      },
      el("span", { class: "sql-col-name", text: column.name }),
      el("span", { class: "sql-col-type", text: shortType(column.type) }),
      column.pk ? el("span", { class: "sql-col-flag", text: "PK" }) : null,
      !column.pk && column.notNull ? el("span", { class: "sql-col-flag muted", text: "NN" }) : null
    );
  }

  async function showDdl(schemaName, table) {
    try {
      const { ddl } = await api.get(
        `${BASE}/ddl?server=${encodeURIComponent(state.server.id)}&database=${encodeURIComponent(state.database)}`
        + `&schema=${encodeURIComponent(schemaName)}&table=${encodeURIComponent(table)}`
      );
      showMessage(el("pre", { class: "log-view", text: ddl }), `${schemaName}.${table} の定義`);
    } catch (error) {
      toast(error.message, "danger");
    }
  }

  /* ── エディタ ─────────────────────────────────────────── */

  function sync() {
    paint(highlight, editor.value);
    const lines = editor.value.split("\n").length;
    if (gutter.childElementCount !== lines) {
      clear(gutter).append(
        ...Array.from({ length: lines }, (_, i) => el("div", { class: "sql-gutter-line", text: String(i + 1) }))
      );
    }
    syncScroll();
    saveDraft();
  }

  function syncScroll() {
    highlight.style.transform = `translate(${-editor.scrollLeft}px, ${-editor.scrollTop}px)`;
    gutter.scrollTop = editor.scrollTop;
  }

  /** 木の列名をクリックして挿す。続けて別の列を押しても読めるよう、
      直前が識別子の文字（英数字・_・"・]）のときだけ ", " を前置する。
      "table1." の直後や空白の直後はそのまま挿すので、修飾名を組み立てたり
      SELECT の直後に置いたりする分には区切りが増えない。 */
  function insertAtCaret(text) {
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    const before = editor.value.slice(Math.max(0, start - 1), start);
    const insert = /[\w"\]]/.test(before) ? `, ${text}` : text;
    editor.setRangeText(insert, start, end, "end");
    editor.focus();
    sync();
  }

  function selectedSql() {
    const { selectionStart, selectionEnd, value } = editor;
    const picked = value.slice(selectionStart, selectionEnd).trim();
    return picked || value;
  }

  function onKeyDown(event) {
    if (suggestOpen() && handleSuggestKey(event)) return;

    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      run();
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.code === "Space") {
      event.preventDefault();
      openSuggest();
      return;
    }
    if (event.key === "Tab") {
      event.preventDefault();
      indent(event.shiftKey);
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key === "/") {
      event.preventDefault();
      toggleComment();
    }
  }

  function indent(back) {
    const { selectionStart, selectionEnd, value } = editor;
    if (selectionStart === selectionEnd && !back) {
      editor.setRangeText("  ", selectionStart, selectionEnd, "end");
      sync();
      return;
    }
    const from = value.lastIndexOf("\n", selectionStart - 1) + 1;
    const to = value.indexOf("\n", selectionEnd);
    const end = to === -1 ? value.length : to;
    const block = value.slice(from, end);
    const next = block
      .split("\n")
      .map((line) => (back ? line.replace(/^ {1,2}/, "") : "  " + line))
      .join("\n");
    editor.setRangeText(next, from, end, "select");
    sync();
  }

  function toggleComment() {
    const { selectionStart, selectionEnd, value } = editor;
    const from = value.lastIndexOf("\n", selectionStart - 1) + 1;
    const to = value.indexOf("\n", selectionEnd);
    const end = to === -1 ? value.length : to;
    const lines = value.slice(from, end).split("\n");
    const commented = lines.every((line) => !line.trim() || line.trimStart().startsWith("--"));
    const next = lines
      .map((line) => (commented ? line.replace(/^(\s*)-- ?/, "$1") : line.trim() ? `-- ${line}` : line))
      .join("\n");
    editor.setRangeText(next, from, end, "select");
    sync();
  }

  /* ── 入力補完（Ctrl+Space） ───────────────────────────── */

  let suggestItems = [];
  let suggestIndex = 0;

  const suggestOpen = () => !suggest.hidden;

  function currentWord() {
    const upto = editor.value.slice(0, editor.selectionStart);
    const match = /[A-Za-z_][A-Za-z0-9_]*$/.exec(upto);
    return match ? match[0] : "";
  }

  function candidates(word) {
    const needle = word.toLowerCase();
    const names = new Set();
    for (const schema of state.objects?.schemas || []) {
      names.add(schema.name);
      for (const table of schema.tables) {
        names.add(table.name);
        for (const column of table.columns) names.add(column.name);
      }
    }
    for (const keyword of KEYWORDS) names.add(keyword.toUpperCase());
    return [...names]
      .filter((name) => name.toLowerCase().startsWith(needle) && name.toLowerCase() !== needle)
      .sort((a, b) => a.length - b.length || a.localeCompare(b))
      .slice(0, 12);
  }

  function openSuggest() {
    const word = currentWord();
    suggestItems = candidates(word);
    if (!suggestItems.length) {
      closeSuggest();
      return;
    }
    suggestIndex = 0;
    clear(suggest).append(
      ...suggestItems.map((name, index) =>
        el("button", {
          class: `sql-suggest-item${index === 0 ? " is-active" : ""}`, type: "button",
          onclick: () => acceptSuggest(index),
        }, name)
      )
    );
    const { line, column } = caretPosition();
    suggest.style.left = `${column}px`;
    suggest.style.top = `${line}px`;
    suggest.hidden = false;
  }

  function closeSuggest() {
    suggest.hidden = true;
    suggestItems = [];
  }

  function caretPosition() {
    const upto = editor.value.slice(0, editor.selectionStart);
    const lines = upto.split("\n");
    const metrics = charMetrics();
    /* 1文字の幅は「10文字を測って10で割った」小数。行数・桁数に掛けるので、
       下の行・長い行ほど誤差が積もり、候補がキャレットから離れていく。
       置く直前に丸める。 */
    return {
      line: Math.round(lines.length * metrics.height + 6 - editor.scrollTop),
      column: Math.round(
        (lines[lines.length - 1].length) * metrics.width + 10 - editor.scrollLeft),
    };
  }

  let metricsCache = null;
  function charMetrics() {
    if (metricsCache) return metricsCache;
    const probe = el("span", { class: "sql-probe", text: "0000000000" });
    code.append(probe);
    const rect = probe.getBoundingClientRect();
    metricsCache = { width: rect.width / 10, height: rect.height };
    probe.remove();
    return metricsCache;
  }

  function handleSuggestKey(event) {
    if (event.key === "Escape") { closeSuggest(); event.preventDefault(); return true; }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const delta = event.key === "ArrowDown" ? 1 : -1;
      suggestIndex = (suggestIndex + delta + suggestItems.length) % suggestItems.length;
      [...suggest.children].forEach((node, index) => node.classList.toggle("is-active", index === suggestIndex));
      return true;
    }
    if (event.key === "Enter" || event.key === "Tab") {
      event.preventDefault();
      acceptSuggest(suggestIndex);
      return true;
    }
    return false;
  }

  function acceptSuggest(index) {
    const name = suggestItems[index];
    if (!name) return;
    const word = currentWord();
    const start = editor.selectionStart - word.length;
    editor.setRangeText(name, start, editor.selectionStart, "end");
    closeSuggest();
    editor.focus();
    sync();
  }

  /* ── 実行 ─────────────────────────────────────────────── */

  function renderMode() {
    clear(modeButton).append(
      icon(state.write ? "bi-pencil" : "bi-shield-check"),
      state.write ? "書き込み" : "読み取り専用"
    );
    modeButton.classList.toggle("btn-danger", state.write);
    modeButton.title = state.write
      ? "COMMIT します。切り替えると読み取り専用に戻ります。"
      : "READ ONLY トランザクションで実行し、必ずロールバックします。";
  }

  function toggleMode() {
    if (!state.write) {
      const ok = window.confirm(
        "書き込みモードに切り替えます。\n実行した SQL はコミットされ、元に戻せません。よろしいですか？"
      );
      if (!ok) return;
    }
    state.write = !state.write;
    renderMode();
  }

  function runSnippet(sql) {
    editor.value = sql.endsWith("\n") ? sql : sql + "\n";
    sync();
    run();
  }

  async function run() {
    if (state.running) return;
    const sql = selectedSql().trim();
    if (!sql) {
      toast("SQL が空です", "danger");
      return;
    }
    closeSuggest();

    const token = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    state.running = token;
    state.lastStatus = null;
    runButton.disabled = true;
    cancelButton.hidden = false;
    const startedAt = performance.now();
    status.textContent = "実行中…";

    try {
      const payload = await api.post(`${BASE}/query`, {
        server: state.server.id,
        database: state.database,
        sql,
        write: state.write,
        limit: state.limit,
        timeout: state.timeout,
        token,
      });
      renderResults(payload);
      rememberHistory(sql, payload);
    } catch (error) {
      showMessage(el("p", { class: "sql-error-message" }, icon("bi-exclamation-triangle-fill"), error.message), "エラー");
      setStatus("失敗しました");
      toast(error.message, "danger", { duration: 6000 });
    } finally {
      state.running = null;
      runButton.disabled = false;
      cancelButton.hidden = true;
      // 結果側で状態を出していなければ、せめて所要時間を出す
      if (!state.lastStatus) setStatus(`${Math.round(performance.now() - startedAt)} ms`);
    }
  }

  async function cancel() {
    if (!state.running) return;
    try {
      const { message } = await api.post(`${BASE}/cancel`, { token: state.running });
      toast(message, "info");
    } catch (error) {
      toast(error.message, "danger");
    }
  }

  function setStatus(text) {
    state.lastStatus = text;
    status.textContent = text;
  }

  /* ── 結果 ─────────────────────────────────────────────── */

  function renderResults(payload) {
    state.results = payload.results || [];
    clear(resultTabs);
    clear(resultBody);

    const tabs = [];
    state.results.forEach((result, index) => {
      tabs.push(
        el("button", {
          class: `sql-result-tab${index === 0 ? " is-active" : ""}`, type: "button",
          onclick: () => selectResult(index),
        }, `結果 ${index + 1}`, el("span", { class: "sql-result-tag", text: result.status }))
      );
    });
    if (payload.error) {
      tabs.push(
        el("button", {
          class: `sql-result-tab is-error${state.results.length ? "" : " is-active"}`, type: "button",
          onclick: () => showError(payload.error),
        }, icon("bi-exclamation-triangle-fill"), "エラー")
      );
    }
    tabs.push(
      el("button", { class: "sql-result-tab", type: "button", onclick: showHistory },
         icon("bi-hourglass-split"), "履歴")
    );
    resultTabs.append(...tabs);

    if (payload.error && !state.results.length) {
      showError(payload.error);
    } else if (state.results.length) {
      selectResult(0);
    }

    const total = state.results.reduce((sum, r) => sum + r.rowCount, 0);
    const mode = payload.outsideTransaction
      ? "トランザクション外で実行"
      : (payload.committed ? "コミット" : "ロールバック");
    setStatus(`${state.results.length} 文・${total.toLocaleString()} 行・${payload.elapsedMs} ms・${mode}`);
    if (payload.error) {
      toast(payload.error.message, "danger", { duration: 8000 });
    } else if (payload.committed) {
      toast(`コミットしました（${total.toLocaleString()} 行）`, "success");
    }
  }

  function selectResult(index) {
    [...resultTabs.children].forEach((tab, i) => tab.classList.toggle("is-active", i === index));
    const result = state.results[index];
    if (!result) return;
    clear(resultBody).append(resultView(result));
  }

  function resultView(result) {
    const head = el(
      "div",
      { class: "sql-result-head small muted" },
      `${result.status}・${result.rowCount.toLocaleString()} 行・${result.elapsedMs} ms`,
      result.truncated ? el("span", { class: "chip warning", text: `先頭 ${state.limit} 行だけ表示` }) : null,
      el("span", { class: "row-end" }),
      result.rows.length
        ? toolButton("CSV", "bi-file-text", () => downloadCsv(result), "btn-quiet")
        : null
    );

    if (!result.columns.length) {
      return el("div", { class: "sql-result-view" }, head,
                el("div", { class: "empty", text: "この文は行を返しません。" }));
    }

    const table = el(
      "table",
      { class: "sql-grid" },
      el("thead", {}, el("tr", {},
        el("th", { class: "sql-grid-rownum" }, "#"),
        ...result.columns.map((column) =>
          el("th", {}, el("span", { class: "sql-grid-name", text: column.name }),
             el("span", { class: "sql-grid-type", text: column.type }))
        )
      )),
      el("tbody", {}, result.rows.map((row, index) =>
        el("tr", {}, el("td", { class: "sql-grid-rownum", text: String(index + 1) }),
           ...row.map((value) => cellView(value)))
      ))
    );
    return el("div", { class: "sql-result-view" }, head, el("div", { class: "sql-grid-scroll" }, table));
  }

  function cellView(value) {
    if (value === null || value === undefined) {
      return el("td", { class: "sql-null" }, "NULL");
    }
    if (typeof value === "number" || (typeof value === "string" && /^-?\d+(\.\d+)?$/.test(value))) {
      return el("td", { class: "sql-num", text: String(value) });
    }
    if (typeof value === "object") {
      return el("td", { class: "sql-json", text: JSON.stringify(value) });
    }
    return el("td", { text: String(value) });
  }

  function showError(error) {
    [...resultTabs.children].forEach((tab) => tab.classList.toggle("is-active", tab.classList.contains("is-error")));
    const where = Number.isInteger(error.statementIndex) ? `${error.statementIndex + 1} 文目` : "";
    clear(resultBody).append(
      el("div", { class: "sql-error" },
         el("p", { class: "sql-error-message" }, icon("bi-exclamation-triangle-fill"), error.message),
         el("dl", { class: "sql-error-meta" },
            ...pair("状態", error.sqlstate),
            ...pair("位置", error.position ? `${where ? where + " の " : ""}${error.position} 文字目` : where),
            ...pair("詳細", error.detail),
            ...pair("ヒント", error.hint)))
    );
    if (error.position) markErrorPosition(error);
  }

  function pair(label, value) {
    if (!value) return [];
    return [el("dt", { text: label }), el("dd", { text: String(value) })];
  }

  /** エラー位置へキャレットを移す（何文目かを踏まえて数える）。 */
  function markErrorPosition(error) {
    const sql = selectedSql();
    const statements = sql.split(";");
    const index = Number.isInteger(error.statementIndex) ? error.statementIndex : 0;
    const offset = statements.slice(0, index).reduce((sum, part) => sum + part.length + 1, 0);
    const at = Math.min(offset + error.position - 1, editor.value.length);
    editor.focus();
    editor.setSelectionRange(at, at);
  }

  function showMessage(node, title) {
    clear(resultTabs).append(
      el("button", { class: "sql-result-tab is-active", type: "button" }, title),
      el("button", { class: "sql-result-tab", type: "button", onclick: showHistory },
         icon("bi-hourglass-split"), "履歴")
    );
    clear(resultBody).append(el("div", { class: "sql-result-view" }, node));
  }

  /* ── 履歴 ─────────────────────────────────────────────── */

  function rememberHistory(sql, payload) {
    const history = readStore(HISTORY_KEY, []);
    history.unshift({
      sql,
      at: new Date().toISOString(),
      database: `${state.server.label}/${state.database}`,
      ok: !payload.error,
      rows: (payload.results || []).reduce((sum, r) => sum + r.rowCount, 0),
      ms: payload.elapsedMs,
    });
    writeStore(HISTORY_KEY, history.slice(0, HISTORY_MAX));
  }

  function showHistory() {
    const history = readStore(HISTORY_KEY, []);
    [...resultTabs.children].forEach((tab) => tab.classList.remove("is-active"));
    resultTabs.lastElementChild?.classList.add("is-active");
    clear(resultBody).append(
      el("div", { class: "sql-result-view" },
         el("div", { class: "sql-result-head small muted" }, `直近 ${history.length} 件`,
            el("span", { class: "row-end" }),
            history.length
              ? toolButton("消す", "bi-trash", () => { writeStore(HISTORY_KEY, []); showHistory(); }, "btn-quiet")
              : null),
         history.length
           ? el("div", { class: "sql-history" }, history.map(historyRow))
           : el("div", { class: "empty", text: "まだありません" }))
    );
  }

  function historyRow(entry) {
    return el(
      "button",
      { class: "sql-history-item", type: "button", onclick: () => { editor.value = entry.sql; sync(); editor.focus(); } },
      el("span", { class: `sql-history-dot ${entry.ok ? "ok" : "ng"}` }),
      el("code", { class: "sql-history-sql", text: entry.sql.replace(/\s+/g, " ").slice(0, 160) }),
      el("span", { class: "sql-history-meta small muted",
                   text: `${new Date(entry.at).toLocaleString("ja-JP")}・${entry.rows} 行・${entry.ms} ms` })
    );
  }

  /* ── CSV ──────────────────────────────────────────────── */

  function downloadCsv(result) {
    const escape = (value) => {
      if (value === null || value === undefined) return "";
      const text = typeof value === "object" ? JSON.stringify(value) : String(value);
      return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
    };
    const lines = [result.columns.map((c) => escape(c.name)).join(",")];
    for (const row of result.rows) lines.push(row.map(escape).join(","));
    const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: `query-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.csv` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  win.addCleanup(() => {
    saveDraft();
    closeSuggest();
  });

  showHistory();

  return { root, editor, setServer, loadObjects };
}

function clampNumber(input, min, max, fallback) {
  const value = Number(input.value);
  const next = Number.isFinite(value) ? Math.max(min, Math.min(max, Math.round(value))) : fallback;
  input.value = String(next);
  return next;
}

/** エディタと結果の境目をドラッグで動かす。 */
function wireSplitter(splitter, code) {
  let startY = 0;
  let startHeight = 0;

  const onMove = (event) => {
    // 実測値（小数）を基準に足し引きするので、書き出す前に丸める。
    // 丸めないと境界線がにじんだまま残る。
    const next = Math.round(Math.max(90, Math.min(
      startHeight + (event.clientY - startY), splitter.parentElement.clientHeight - 160)));
    code.style.height = `${next}px`;
  };
  const onUp = () => {
    document.removeEventListener("pointermove", onMove);
    document.removeEventListener("pointerup", onUp);
    document.body.classList.remove("is-resizing-rows");
  };

  splitter.addEventListener("pointerdown", (event) => {
    startY = event.clientY;
    startHeight = code.getBoundingClientRect().height;
    document.body.classList.add("is-resizing-rows");
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    event.preventDefault();
  });
}
