/* 開発者パネル。本番データに直接影響する操作をまとめた画面。
   操作はすべて /admin/api/dev/* を叩き、結果はトーストで返す。 */

import * as api from "../lib/api.js";
import { el, icon, clear, loading } from "../lib/dom.js";
import { createTabs } from "../lib/tabs.js";
import { toast } from "../lib/toast.js";

const BASE = "/admin/api/dev";

/* ── 小さな部品 ─────────────────────────────────────────── */

function field(label, control, help) {
  return el(
    "div",
    { class: "field" },
    el("span", { class: "field-label", text: label }),
    control,
    help ? el("p", { class: "field-help", text: help }) : null
  );
}

function input(props = {}) {
  return el("input", { class: "input", type: "text", ...props });
}

function panel(title, ...children) {
  return el(
    "section",
    { class: "section" },
    el("div", { class: "section-head" }, el("h2", { class: "section-title", text: title })),
    el("div", { class: "section-body" }, children)
  );
}

/** 押している間は無効化し、結果をトーストで返すボタン。 */
/** confirm は固定文字列のほか、クリック時点の状態で文言を変えたい場合は
    関数（() => string）でも渡せる。 */
function actionButton(label, iconName, handler, { variant = "btn", confirm = null } = {}) {
  const button = el("button", { class: `btn ${variant}`, type: "button" }, icon(iconName), label);
  button.addEventListener("click", async () => {
    const message = typeof confirm === "function" ? confirm() : confirm;
    if (message && !window.confirm(message)) return;
    const original = button.textContent;
    button.disabled = true;
    try {
      const result = await handler();
      if (result && result.message) toast(result.message, "success");
    } catch (error) {
      toast(error.message || "失敗しました", "danger", { duration: 6000 });
    } finally {
      button.disabled = false;
      button.textContent = original;
      button.prepend(icon(iconName));
    }
  });
  return button;
}

function rows(items, render, emptyText) {
  if (!items.length) return el("div", { class: "empty", text: emptyText });
  return el("div", { class: "list" }, items.map(render));
}

/* ── 本体 ───────────────────────────────────────────────── */

export async function mount(win) {
  clear(win.body).append(loading());
  const data = await api.get(`${BASE}/overview`);

  const guildOptions = data.guilds.map((guild) =>
    el("option", { value: guild.id, text: `${guild.name}（${guild.id}）` })
  );

  // 窓の高さいっぱいをタブの中身に使う（ログが窓の半分しか映らなかった）
  win.body.classList.add("is-filled");
  const logs = logsTab(win);

  const tabs = createTabs([
    { title: "送信", node: sendTab(data, guildOptions) },
    { title: "地震", node: earthquakeTab(guildOptions) },
    { title: "タスク", node: tasksTab(data), badge: data.pending_signals.length || null },
    { title: "設定", node: settingsTab(data) },
    { title: "キャッシュ", node: cacheTab(data), badge: data.cache.entries.length || null },
    { title: "通知テスト", node: notifyTab(guildOptions) },
    { title: "調査", node: lookupTab(data) },
    { title: "ログ", node: logs.node, onShow: logs.onShow },
  ]);

  const bot = data.bot_user || {};
  clear(win.body).append(
    el(
      "div",
      { class: "stack dev-panel" },
      el(
        "div",
        { class: "row" },
        el("span", { class: "chip danger", text: "DEV ONLY" }),
        el("span", { class: "list-sub grow",
                     text: `${bot.global_name || bot.username || "Bot"} / ${data.guilds.length} ギルド` })
      ),
      tabs.el
    )
  );
}

/* ── 送信 ───────────────────────────────────────────────── */

function sendTab(data, guildOptions) {
  const channelId = input({ placeholder: "チャンネルID", inputmode: "numeric" });
  const content = el("textarea", { class: "textarea", placeholder: "送信するメッセージ" });

  const messageUrl = input({ placeholder: "https://discord.com/channels/…" });
  const targetChannel = input({ placeholder: "転送先チャンネルID", inputmode: "numeric" });

  const newsQuery = input({ placeholder: "検索クエリ（例: 生成AI）" });
  const newsChannel = input({ placeholder: "チャンネルID", inputmode: "numeric" });

  // チャンネルID検索: ギルドを選ぶと一覧を引いて、クリックで各入力欄へ入れる
  const guildSelect = el("select", { class: "select" },
                         el("option", { value: "", text: "ギルドを選択" }), guildOptions.map((o) => o.cloneNode(true)));
  const channelList = el("div", { class: "stack" });

  guildSelect.addEventListener("change", async () => {
    if (!guildSelect.value) return clear(channelList);
    clear(channelList).append(loading("チャンネルを取得中…"));
    try {
      const result = await api.get(`${BASE}/channels?guild_id=${guildSelect.value}`);
      clear(channelList).append(
        rows(
          result.channels,
          (channel) =>
            el(
              "div",
              { class: "list-row" },
              el("span", { class: "grow truncate", text: `# ${channel.name}` }),
              el("span", { class: "list-sub mono", text: channel.id }),
              el("button", {
                class: "btn btn-sm", type: "button",
                onclick: () => {
                  channelId.value = channel.id;
                  newsChannel.value = channel.id;
                  targetChannel.value = channel.id;
                  toast(`#${channel.name} のIDを入力しました`, "success", { duration: 2000 });
                },
              }, "使う")
            ),
          "テキストチャンネルが見つかりません。"
        )
      );
    } catch (error) {
      clear(channelList).append(el("div", { class: "empty", text: `取得できませんでした（${error.message}）` }));
    }
  });

  return el(
    "div",
    { class: "stack" },
    panel("チャンネルIDを調べる", field("ギルド", guildSelect), channelList),
    panel(
      "メッセージ送信",
      field("チャンネルID", channelId),
      field("内容", content),
      el("div", { class: "row" }, el("span", { class: "grow" }),
         actionButton("送信", "bi-send", async () => {
           const result = await api.post(`${BASE}/send-message`, {
             channel_id: channelId.value, content: content.value,
           });
           content.value = "";
           return result;
         }, { variant: "btn-primary", confirm: "このメッセージを送信しますか？" }))
    ),
    panel(
      "メッセージ転送",
      field("元メッセージURL", messageUrl),
      field("転送先チャンネルID", targetChannel),
      el("div", { class: "row" }, el("span", { class: "grow" }),
         actionButton("転送", "bi-arrow-right", () =>
           api.post(`${BASE}/forward-message`, {
             message_url: messageUrl.value, target_channel_id: targetChannel.value,
           })))
    ),
    panel(
      "ニュース送信テスト",
      field("検索クエリ", newsQuery),
      field("チャンネルID", newsChannel),
      el("div", { class: "row" }, el("span", { class: "grow" }),
         actionButton("取得して送信", "bi-newspaper", () =>
           api.post(`${BASE}/news-send`, { query: newsQuery.value, channel_id: newsChannel.value })))
    )
  );
}

/* ── 地震リプレイ ───────────────────────────────────────── */

const _ALL_GUILDS = "__all__";

function earthquakeTab(guildOptions) {
  const eventJson = el("textarea", { class: "textarea", placeholder: "地震イベントJSON", rows: 8 });
  const historyList = el("div", { class: "stack" }, el("div", { class: "empty", text: "「直近の地震を取得」を押してください。" }));

  // 送信先を必ず選ばせる（未選択のまま実行できないようにする）。
  // 全サーバー送信は一覧の最後に置いた明示的な選択肢としてだけ残す
  // ―― 誤って全サーバーへ届いて情報が錯乱するのを防ぐため。
  const guildSelect = el(
    "select",
    { class: "select" },
    el("option", { value: "", text: "送信先のギルドを選択…" }),
    guildOptions.map((o) => o.cloneNode(true)),
    el("option", { value: _ALL_GUILDS, text: "⚠️ 全サーバーへ送信（本番相当・注意）" })
  );

  const loadButton = actionButton("直近の地震を取得", "bi-arrow-clockwise", async () => {
    clear(historyList).append(loading());
    const result = await api.get(`${BASE}/earthquakes`);
    // サーバは失敗しても200で返す（理由は error に入る）。原因を画面にも出す。
    clear(historyList).append(
      rows(
        result.events,
        (event) =>
          el(
            "div",
            { class: "list-row" },
            el("div", { class: "grow list-main" },
               el("div", { class: "truncate", text: `${event.place}（${event.scale_label}）` }),
               el("div", { class: "list-sub", text: `${event.time || "-"} / M${event.magnitude ?? "-"}` })),
            el("button", {
              class: "btn btn-sm", type: "button",
              onclick: () => { eventJson.value = event.json; toast("JSONを読み込みました", "success", { duration: 2000 }); },
            }, "選ぶ")
          ),
        result.error ? `取得できませんでした: ${result.error}` : "地震情報がありません。"
      )
    );
    return null;
  });

  const replayButton = actionButton(
    "リプレイをキューに追加", "bi-broadcast-pin",
    () => {
      const guildId = guildSelect.value === _ALL_GUILDS ? "" : guildSelect.value;
      return api.post(`${BASE}/earthquake-replay`, { event_json: eventJson.value, guild_id: guildId });
    },
    {
      variant: "btn-primary",
      confirm: () =>
        guildSelect.value === _ALL_GUILDS
          ? "この地震速報を全サーバーへ実際に通知しますか？"
          : `この地震速報を「${guildSelect.selectedOptions[0]?.textContent || guildSelect.value}」へ実際に通知しますか？`,
    }
  );
  // 送信先を選ぶまでは押せない（全サーバーへの誤爆をここでも防ぐ）。
  replayButton.disabled = true;
  guildSelect.addEventListener("change", () => { replayButton.disabled = !guildSelect.value; });

  return el(
    "div",
    { class: "stack" },
    panel("直近の地震から選ぶ", el("div", { class: "row" }, loadButton), historyList),
    panel(
      "リプレイ実行",
      field("送信先", guildSelect, "テスト用の通知を実際に送るギルドを選びます。"),
      field("イベントJSON", eventJson, "earthquake / hypocenter キーを含む P2PQuake 形式の JSON。"),
      el("div", { class: "row" }, el("span", { class: "grow" }), replayButton)
    )
  );
}

/* ── タスク ─────────────────────────────────────────────── */

function tasksTab(data) {
  const pendingEl = el("div", { class: "stack" });

  function renderPending(signals) {
    clear(pendingEl).append(
      signals.length
        ? el("div", { class: "list" }, signals.map((name) =>
            el("div", { class: "list-row" }, icon("bi-hourglass-split"),
               el("span", { class: "grow mono", text: name }),
               el("span", { class: "chip", text: "待機中" }))))
        : el("div", { class: "empty", text: "待機中のシグナルはありません。" })
    );
  }
  renderPending(data.pending_signals);

  const buttons = Object.entries(data.tasks).map(([task, label]) =>
    el("div", { class: "list-row" },
       el("span", { class: "grow", text: label }),
       actionButton("実行", "bi-play-fill", async () => {
         const result = await api.post(`${BASE}/signal/${task}`, {});
         renderPending(result.pending_signals || []);
         return result;
       }, { confirm: `「${label}」を実行しますか？` }))
  );

  return el(
    "div",
    { class: "stack" },
    panel("待機中のシグナル", pendingEl),
    panel("タスクを実行", el("div", { class: "list" }, buttons))
  );
}

/* ── ギルド設定 ─────────────────────────────────────────── */

function settingsTab(data) {
  const viewer = el("pre", { class: "log-view", hidden: true });
  const filePicker = el("input", { type: "file", accept: "application/json", hidden: true });

  async function show(guildId) {
    viewer.hidden = false;
    viewer.textContent = "読み込み中…";
    try {
      const result = await api.get(`${BASE}/settings/${guildId}`);
      viewer.textContent = JSON.stringify(result.settings, null, 2);
      viewer.dataset.guildId = guildId;
    } catch (error) {
      viewer.textContent = `取得できませんでした（${error.message}）`;
    }
  }

  function download(guildId) {
    const blob = new Blob([viewer.textContent], { type: "application/json" });
    const link = el("a", { href: URL.createObjectURL(blob), download: `guild_${guildId}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
  }

  let importTarget = null;
  filePicker.addEventListener("change", async () => {
    const file = filePicker.files?.[0];
    if (!file || !importTarget) return;
    try {
      const settings = JSON.parse(await file.text());
      const result = await api.post(`${BASE}/settings/${importTarget}/import`, { settings });
      toast(result.message, "success");
      show(importTarget);
    } catch (error) {
      toast(`インポートに失敗しました（${error.message}）`, "danger", { duration: 6000 });
    } finally {
      filePicker.value = "";
      importTarget = null;
    }
  });

  const list = rows(
    data.settings_guild_ids,
    (guildId) => {
      const guild = data.guilds.find((g) => g.id === guildId);
      return el(
        "div",
        { class: "list-row" },
        el("div", { class: "grow list-main" },
           el("div", { class: "truncate", text: guild ? guild.name : "（Bot 不参加）" }),
           el("div", { class: "list-sub mono", text: guildId })),
        el("button", { class: "btn btn-sm", type: "button", onclick: () => show(guildId) }, "表示"),
        el("button", { class: "btn btn-sm", type: "button",
                       onclick: async () => { await show(guildId); download(guildId); } }, "書き出し"),
        el("button", {
          class: "btn btn-sm btn-danger", type: "button",
          onclick: () => {
            if (!window.confirm(`ギルド ${guildId} の設定をファイルで置き換えますか？（元に戻せません）`)) return;
            importTarget = guildId;
            filePicker.click();
          },
        }, "取り込み")
      );
    },
    "保存された設定がありません。"
  );

  return el("div", { class: "stack" }, panel("ギルド設定", list, filePicker, viewer));
}

/* ── キャッシュ ─────────────────────────────────────────── */

function cacheTab(data) {
  const listEl = el("div", { class: "stack" });

  function render(entries) {
    clear(listEl).append(
      rows(
        entries,
        (entry) =>
          el(
            "div",
            { class: "list-row" },
            el("div", { class: "grow list-main" },
               el("div", { class: "truncate", text: entry.title }),
               el("div", { class: "list-sub", text: `${entry.size_mb} MB / guild:${entry.guild_id || "-"}` })),
            entry.expired ? el("span", { class: "chip danger", text: "期限切れ" }) : el("span", { class: "chip", text: "有効" }),
            el("button", {
              class: "btn btn-sm btn-danger", type: "button", title: "削除",
              onclick: async () => {
                if (!window.confirm("このキャッシュを削除しますか？")) return;
                try {
                  const result = await api.del(`${BASE}/cache/${encodeURIComponent(entry.token)}`);
                  render(result.entries || []);
                  toast(result.message, "success");
                } catch (error) {
                  toast(`削除に失敗しました（${error.message}）`, "danger");
                }
              },
            }, icon("bi-trash"))
          ),
        "キャッシュはありません。"
      )
    );
  }
  render(data.cache.entries);

  return el(
    "div",
    { class: "stack" },
    panel(
      "DJAudio キャッシュ",
      el("div", { class: "row" },
         el("span", { class: "grow list-sub", text: `期限切れ ${data.cache.expired} 件` }),
         actionButton("期限切れを掃除", "bi-trash", async () => {
           const result = await api.post(`${BASE}/cache/purge`, {});
           render(result.entries || []);
           return result;
         }, { confirm: "期限切れキャッシュをすべて削除しますか？" })),
      listEl
    )
  );
}

/* ── 通知テスト ─────────────────────────────────────────── */

function notifyTab(guildOptions) {
  const guildSelect = el("select", { class: "select" },
                         el("option", { value: "", text: "ギルドを選択" }), guildOptions.map((o) => o.cloneNode(true)));

  const send = (kind) => () => api.post(`${BASE}/test-notify/${kind}`, { guild_id: guildSelect.value });

  return el(
    "div",
    { class: "stack" },
    panel(
      "通知テスト",
      field("対象ギルド", guildSelect, "設定済みのチャンネルへテスト通知を送ります。"),
      el("div", { class: "row" },
         actionButton("ウェルカム通知", "bi-person-plus", send("welcome")),
         actionButton("VC通知", "bi-mic", send("vc")))
    )
  );
}

/* ── 調査（ユーザー / スティッキー / 環境変数） ───────────── */

function lookupTab(data) {
  const userId = input({ placeholder: "ユーザーID", inputmode: "numeric" });
  const userResult = el("div", { class: "stack" });

  const lookup = actionButton("調べる", "bi-search", async () => {
    clear(userResult).append(loading());
    try {
      const user = await api.get(`${BASE}/user?user_id=${encodeURIComponent(userId.value.trim())}`);
      clear(userResult).append(
        el("div", { class: "list-row" },
           user.avatar_url ? el("img", { class: "tray-avatar", src: user.avatar_url, alt: "" }) : icon("bi-person"),
           el("div", { class: "grow list-main" },
              el("div", { text: user.global_name || user.username || "-" }),
              el("div", { class: "list-sub mono", text: user.id })),
           user.bot ? el("span", { class: "chip", text: "BOT" }) : null,
           el("span", { class: "list-sub", text: `作成 ${user.created_at}` }))
      );
    } catch (error) {
      clear(userResult).append(el("div", { class: "empty", text: error.message }));
    }
    return null;
  });

  const envRows = data.env_rows.map((row) =>
    el("div", { class: "list-row" },
       el("span", { class: "grow mono truncate", text: row.key }),
       el("span", { class: "list-sub mono truncate", text: row.value || "—" }),
       el("span", {
         class: `chip ${row.status === "missing" ? "danger" : row.status === "set" ? "accent" : ""}`,
         text: row.status === "set" ? "設定済み" : row.status === "default" ? "既定値" : "未設定",
       }))
  );

  const stickyRows = rows(
    data.stickies,
    (sticky) =>
      el("div", { class: "list-row" },
         el("div", { class: "grow list-main" },
            el("div", { class: "truncate", text: sticky.content || "(空)" }),
            el("div", { class: "list-sub mono", text: `guild:${sticky.guild_id} / ch:${sticky.channel_id}` })),
         sticky.pending_delete ? el("span", { class: "chip danger", text: "削除保留" }) : null),
    "スティッキーはありません。"
  );

  return el(
    "div",
    { class: "stack" },
    panel("ユーザーを調べる",
          el("div", { class: "input-row" }, el("div", { class: "field grow" }, userId), lookup),
          userResult),
    panel("環境変数", el("div", { class: "list" }, envRows)),
    panel("全ギルドのスティッキー", stickyRows)
  );
}

/* ── ログ ───────────────────────────────────────────────── */

/* ログの行から重大度を見て色を分ける。
   形式は "2026-08-24 03:00:00 [ERROR] logger: 本文"。level が読めない行（例外の
   スタックトレースなど）は、直前の行の色を引き継いで1つのまとまりに見せる。 */
const LOG_LEVEL = /\b(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG)\b/;
const LEVEL_CLASS = {
  CRITICAL: "is-error", ERROR: "is-error", WARNING: "is-warn", WARN: "is-warn",
  INFO: "", DEBUG: "is-debug",
};

function renderLogLines(target, lines) {
  let carried = "";
  const nodes = lines.map((line) => {
    const level = LOG_LEVEL.exec(line.slice(0, 80));
    if (level) carried = LEVEL_CLASS[level[1].toUpperCase()] ?? "";
    return el("div", { class: `log-line ${carried}`.trim(), text: line || " " });
  });
  clear(target).append(...nodes);
}

const REFRESH_MS = 5000;

/**
 * ログ表示。開いた時点で自動で読み込み、開いている間だけ一定間隔で追いかける。
 * @returns {{node: HTMLElement, onShow: () => void}}
 */
function logsTab(win) {
  const source = el("select", { class: "select" },
                    el("option", { value: "bot", text: "bot.log" }),
                    el("option", { value: "admin", text: "admin.log" }));
  const lines = el("input", { class: "input", type: "number", value: "500", min: "10", max: "1000" });
  const follow = el("input", { type: "checkbox", checked: true });
  const output = el("pre", { class: "log-view", text: "読み込み中…" });
  const status = el("span", { class: "small muted log-status" });

  let busy = false;
  let timer = null;

  async function load({ quiet = false } = {}) {
    if (busy) return;
    busy = true;
    try {
      const result = await api.get(`${BASE}/logs?source=${source.value}&lines=${lines.value || 500}`);
      // 読んでいる途中で下へ飛ばされると邪魔なので、いちばん下に居るときだけ追尾する
      const atBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 24;
      if (result.lines.length) {
        renderLogLines(output, result.lines);
      } else {
        clear(output).append(el("div", { class: "log-line is-debug", text: "（空です）" }));
      }
      if (atBottom) output.scrollTop = output.scrollHeight;
      status.textContent = `${result.lines.length} 行・${new Date().toLocaleTimeString("ja-JP")} 更新`;
    } catch (error) {
      status.textContent = `読み込めません（${error.message}）`;
      if (!quiet) toast(error.message, "danger");
    } finally {
      busy = false;
    }
  }

  const node = el(
    "div",
    { class: "stack log-pane" },
    panel(
      "ログ",
      el("div", { class: "row log-toolbar" },
         source,
         lines,
         el("label", { class: "check log-follow" }, follow, el("span", { class: "check-text", text: "自動更新" })),
         actionButton("再読み込み", "bi-arrow-clockwise", () => load().then(() => null)),
         el("span", { class: "row-end" }),
         status),
      output
    )
  );

  // タブが表に出ている間だけ動かす。裏に居るとき・窓を閉じたあとは何もしない。
  timer = window.setInterval(() => {
    if (!follow.checked || node.hidden || document.hidden || !node.isConnected) return;
    load({ quiet: true });
  }, REFRESH_MS);
  win.addCleanup(() => window.clearInterval(timer));

  source.addEventListener("change", () => load());
  lines.addEventListener("change", () => load());

  return { node, onShow: () => load({ quiet: true }) };
}
