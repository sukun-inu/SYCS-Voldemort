/* スキーマ（/admin/api/apps/{id}）からウィンドウの中身を描く。

   保存は明示保存。変更された項目だけを PUT し、結果はその応答で画面に反映する
   （リダイレクトもリロードもしない）。追加・削除だけは即時実行する。 */

import * as api from "../lib/api.js";
import { el, icon, clear, loading } from "../lib/dom.js";
import { toast } from "../lib/toast.js";
import { createTabs } from "../lib/tabs.js";
import { createWidget } from "./widgets.js";

/* checklist（複数選択）は「どれが選ばれているか」という集合であって、並び順に
   意味は無い。並び順まで比べると、サーバー側の順序がたまたま変われば
   （例: dict の元が frozenset で、文字列ハッシュのランダム化により反復順序が
   起動のたびに変わる）、中身が同じでも「変更あり」と誤検知し続け、保存しても
   ずっと未保存のまま、という不具合になる。配列同士は集合として比べる。 */
function same(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    const bSet = new Set(b);
    return a.every((v) => bSet.has(v));
  }
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

export async function mountPanel(win, app) {
  win.body.replaceChildren(loading());
  const schema = await api.get(`/admin/api/apps/${app.id}`);
  if (schema.kind === "custom") {
    await mountCustom(win, schema);
    return;
  }
  renderPanel(win, schema);
}

/** スキーマから描けない画面の描画先を、パネルの client 宣言で振り分ける。 */
async function mountCustom(win, schema) {
  if (schema.client && schema.client !== "iframe") {
    const module = await import(`../apps/${schema.client}.js`);
    module.mount(win, schema);
    return;
  }
  mountLegacy(win, schema);
}

/** 未移行の画面（ユーザー状態監査・開発者パネル）は既存ページを埋め込む。 */
function mountLegacy(win, schema) {
  win.body.classList.add("is-plain");
  win.body.replaceChildren(
    el("iframe", { src: schema.path, title: schema.title, loading: "eager" })
  );
}

function renderPanel(win, schema) {
  const url = `/admin/api/apps/${schema.id}`;
  const widgets = new Map();
  const baseline = { ...schema.values };

  /* 中身と保存バーを分ける。

     以前は保存バーも中身と一緒に流れていて、position:sticky で下に貼り付けて
     いた。すると開いた直後から、画面に入りきらない項目の上にバーが重なる
     （実測で「クールダウン（秒）」の見出しごと 22px、その欄が 48px 隠れていた）。
     しかも本体の下パディング 15px ぶんだけバーが浮くので、その隙間から隠れた
     欄が覗く。「途中で切れている」ように見えるのはこれ。

     送るのは中身だけにして、保存バーは下に置いたままにする。 */
  const container = el("div", { class: "panel" });
  const scroller = el("div", { class: "panel-scroll" });
  const sections = schema.sections.map((section) =>
    renderSection(section, schema, widgets, () => onChange())
  );

  if (schema.layout === "tabs" && sections.length > 1) {
    scroller.append(
      createTabs(schema.sections.map((section, index) => ({ title: section.title, node: sections[index] }))).el
    );
  } else {
    scroller.append(...sections);
  }
  container.append(scroller);

  /* ── 保存バー ─────────────────────────────────────────── */
  const status = el("span", { class: "savebar-status", text: "変更はありません" });
  const saveButton = el("button", { class: "btn btn-primary", type: "button", disabled: true },
                        icon("bi-check-lg"), "保存");
  const discardButton = el("button", { class: "btn", type: "button", disabled: true }, "変更を破棄");
  const hasFields = widgets.size > 0;

  if (hasFields) {
    container.append(el("div", { class: "savebar" }, status, el("span", { class: "row-end" }), discardButton, saveButton));
  }

  clear(win.body).append(container);

  // 値を読めなかった項目（services 側の失敗）は、既定値に見えてしまうので明示する
  for (const [key, message] of Object.entries(schema.errors || {})) {
    widgets.get(key)?.setError(`現在の値を読み取れませんでした（${message}）`);
  }

  function changedKeys() {
    return [...widgets.keys()].filter((key) => !same(widgets.get(key).get(), baseline[key]));
  }

  function applyEnabledWhen() {
    for (const [, widget] of widgets) {
      const dependency = widget.field.enabled_when;
      if (!dependency) continue;
      const source = widgets.get(dependency);
      if (source) widget.setEnabled(Boolean(source.get()));
    }
  }

  function onChange() {
    const dirty = changedKeys();
    saveButton.disabled = dirty.length === 0;
    discardButton.disabled = dirty.length === 0;
    status.classList.toggle("is-dirty", dirty.length > 0);
    status.textContent = dirty.length ? `未保存の変更 ${dirty.length} 件` : "変更はありません";
    win.setDirty(dirty.length > 0);
    applyEnabledWhen();
  }

  function applyResult(payload) {
    const saved = new Set(payload.saved || []);
    const errors = payload.errors || {};
    const dirtyBefore = new Set(changedKeys());

    for (const [key, widget] of widgets) {
      if (errors[key]) {
        widget.setError(errors[key]);
        continue;
      }
      widget.setError("");
      if (payload.values && key in payload.values) {
        baseline[key] = payload.values[key];
        if (saved.has(key) || !dirtyBefore.has(key)) widget.set(payload.values[key]);
      }
    }
    onChange();
  }

  async function save() {
    const dirty = changedKeys();
    if (!dirty.length) return;

    const values = {};
    for (const key of dirty) values[key] = widgets.get(key).get();

    saveButton.disabled = true;
    status.classList.remove("is-error");
    status.textContent = "保存中…";

    try {
      const result = await api.put(url, { values });
      applyResult(result);
      toast(`${result.saved.length} 件を保存しました`, "success");
    } catch (error) {
      if (error.status === 422 && error.payload) {
        applyResult(error.payload);
        status.classList.add("is-error");
        toast("保存できなかった項目があります。内容を確認してください。", "danger");
      } else {
        status.classList.add("is-error");
        status.textContent = "保存に失敗しました";
        toast(`保存に失敗しました（${error.message}）`, "danger");
      }
      onChange();
    }
  }

  saveButton.addEventListener("click", save);
  discardButton.addEventListener("click", () => {
    for (const [key, widget] of widgets) {
      widget.set(baseline[key]);
      widget.setError("");
    }
    onChange();
  });

  win.beforeClose = async () => {
    if (!changedKeys().length) return true;
    return window.confirm("未保存の変更があります。破棄して閉じますか？");
  };

  applyEnabledWhen();
  onChange();
}

function renderSection(section, schema, widgets, onChange) {
  const body = el("div", { class: "section-body" });

  for (const field of section.fields) {
    const widget = createWidget(field, schema.values[field.key], schema.choices || {});
    widget.onInput(onChange);
    widgets.set(field.key, widget);
    body.append(widget.el);
  }

  for (const collection of section.collections) {
    body.append(renderCollection(collection, schema));
  }

  return el(
    "section",
    { class: "section" },
    el(
      "div",
      // data-specular: ポインタに追従する鏡面（wm/specular.js が座標を入れる）
      { class: "section-head", "data-specular": "" },
      el("h2", { class: "section-title", text: section.title }),
      section.help ? el("p", { class: "section-help", text: section.help }) : null
    ),
    body
  );
}

/* ── コレクション（追加・削除は即時実行） ─────────────────── */

function labelFor(field, value, choices) {
  if (value === null || value === undefined || value === "") return "未設定";
  const options = Array.isArray(field.choices)
    ? field.choices
    : field.choice_source
      ? choices[field.choice_source] || []
      : [];
  const hit = options.find((option) => option.value === String(value));
  return hit ? hit.label : String(value);
}

function renderCollection(collection, schema) {
  const url = `/admin/api/apps/${schema.id}/collections/${collection.key}`;
  const choices = schema.choices || {};
  const listEl = el("div", { class: "stack" });
  const countChip = el("span", { class: "chip" });
  let items = schema.collections?.[collection.key] || [];
  let editingId = null;

  const formWidgets = collection.fields.map((field) => createWidget(field, null, choices));
  const submitButton = el("button", { class: "btn btn-primary", type: "button" }, icon("bi-plus-lg"), "追加");
  const cancelButton = el("button", { class: "btn", type: "button", hidden: true }, "取消");

  function resetForm() {
    editingId = null;
    for (const widget of formWidgets) {
      widget.set(widget.field.default ?? null);
      widget.setError("");
    }
    submitButton.replaceChildren(icon("bi-plus-lg"), document.createTextNode("追加"));
    cancelButton.hidden = true;
  }

  function startEdit(item) {
    editingId = String(item[collection.id_key] ?? item.id);
    for (const widget of formWidgets) widget.set(item[widget.field.key] ?? null);
    submitButton.replaceChildren(icon("bi-check-lg"), document.createTextNode("更新"));
    cancelButton.hidden = false;
    formWidgets[0]?.focus();
  }

  function renderRows() {
    clear(listEl);
    countChip.textContent = collection.max_items
      ? `${items.length} / ${collection.max_items} 件`
      : `${items.length} 件`;

    if (!items.length) {
      // 読み取りに失敗したときの空欄は「まだ無い」と区別が付かない
      const failure = schema.errors?.[collection.key];
      listEl.append(el("div", {
        class: "empty",
        text: failure
          ? `一覧を読み取れませんでした（${failure}）`
          : `${collection.item_label}はまだありません。`,
      }));
    } else {
      const rows = items.map((item) => {
        const [first, ...rest] = collection.fields;
        const main = labelFor(first, item[first.key], choices);
        const sub = rest
          .map((field) => `${field.label}: ${labelFor(field, item[field.key], choices)}`)
          .join(" / ");
        const id = String(item[collection.id_key] ?? item.id);
        return el(
          "div",
          { class: "list-row" },
          el(
            "div",
            { class: "grow list-main" },
            el("div", { class: "truncate", text: main }),
            sub ? el("div", { class: "list-sub truncate", text: sub }) : null
          ),
          collection.can_update
            ? el("button", { class: "btn btn-sm", type: "button", onclick: () => startEdit(item) },
                 icon("bi-pencil"), "編集")
            : null,
          collection.can_remove
            ? el("button", {
                class: "btn btn-sm btn-danger", type: "button", title: "削除",
                onclick: () => remove(id, main),
              }, icon("bi-trash"))
            : null
        );
      });
      listEl.append(el("div", { class: "list" }, rows));
    }

    const full = collection.max_items !== undefined && items.length >= collection.max_items;
    submitButton.disabled = full && editingId === null;
  }

  async function submit() {
    const values = {};
    for (const widget of formWidgets) {
      widget.setError("");
      values[widget.field.key] = widget.get();
    }

    // resetForm() が editingId を消すので、どちらの操作だったかを先に控える
    const wasEditing = editingId !== null;
    submitButton.disabled = true;
    try {
      const result = wasEditing
        ? await api.put(`${url}/${encodeURIComponent(editingId)}`, { values })
        : await api.post(url, { values });
      items = result.items || [];
      resetForm();
      renderRows();
      toast(wasEditing ? "更新しました" : "追加しました", "success");
    } catch (error) {
      if (error.status === 422) {
        const errors = error.fieldErrors;
        for (const widget of formWidgets) {
          if (errors[widget.field.key]) widget.setError(errors[widget.field.key]);
        }
        if (errors.__all__) toast(errors.__all__, "danger");
        if (error.payload.items) { items = error.payload.items; renderRows(); }
      } else {
        toast(`保存に失敗しました（${error.message}）`, "danger");
      }
    } finally {
      // 押せるかどうかは件数で決まる。ここで一律に戻すと、満杯でも押せてしまう
      renderRows();
    }
  }

  async function remove(id, label) {
    if (!window.confirm(`「${label}」を削除しますか？`)) return;
    try {
      const result = await api.del(`${url}/${encodeURIComponent(id)}`);
      items = result.items || [];
      if (editingId === id) resetForm();
      renderRows();
      toast("削除しました", "success");
    } catch (error) {
      toast(`削除に失敗しました（${error.message}）`, "danger");
    }
  }

  submitButton.addEventListener("click", submit);
  cancelButton.addEventListener("click", () => { resetForm(); renderRows(); });

  resetForm();
  renderRows();

  return el(
    "div",
    { class: "stack" },
    el("div", { class: "row" },
       el("span", { class: "field-label grow", text: collection.label }),
       countChip),
    collection.help ? el("p", { class: "field-help", text: collection.help }) : null,
    listEl,
    collection.can_add
      ? el(
          "div",
          { class: "stack" },
          el("div", { class: "input-row" }, formWidgets.map((widget) => widget.el)),
          el("div", { class: "row" }, el("span", { class: "grow" }), cancelButton, submitButton)
        )
      : null
  );
}
