/* VC録音。録音の状況・開始と停止・保存済みアーカイブ・設定をまとめて扱う。

   開始と停止は Bot 側でしか行えないため、ここでは API 経由でシグナルを置く。
   反映には数十秒かかるので、状況は定期的に取り直す。 */

import * as api from "../lib/api.js";
import { el, icon, clear, loading } from "../lib/dom.js";
import { toast } from "../lib/toast.js";

const BASE = "/admin/api/recording";
const POLL_INTERVAL = 5000;

function field(label, control, help) {
  return el(
    "div",
    { class: "field" },
    el("span", { class: "field-label", text: label }),
    control,
    help ? el("p", { class: "field-help", text: help }) : null
  );
}

function section(title, ...children) {
  return el(
    "section",
    { class: "section" },
    el("div", { class: "section-head" }, el("h2", { class: "section-title", text: title })),
    el("div", { class: "section-body" }, children)
  );
}

function duration(seconds) {
  const total = Math.max(0, Math.floor(seconds || 0));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h ? `${h}時間${m}分${s}秒` : `${m}分${s}秒`;
}

/** 押している間は無効化し、結果をトーストで返すボタン。 */
function actionButton(label, iconName, handler, { variant = "btn", confirm = null } = {}) {
  const button = el("button", { class: `btn ${variant}`, type: "button" }, icon(iconName), label);
  button.addEventListener("click", async () => {
    if (confirm && !window.confirm(confirm)) return;
    button.disabled = true;
    try {
      const result = await handler();
      if (result && result.message) toast(result.message, "success");
    } catch (error) {
      toast(error.message || "失敗しました", "danger", { duration: 6000 });
    } finally {
      button.disabled = false;
    }
  });
  return button;
}

export async function mount(win) {
  clear(win.body).append(loading());

  const statusBox = el("div", { class: "stack" });
  const listBox = el("div", { class: "stack" });

  const channelInput = el("input", {
    class: "input", type: "text", placeholder: "録音するVCのチャンネルID", inputmode: "numeric",
  });

  const enabledInput = el("input", { class: "input", type: "checkbox" });
  const maxMinutesInput = el("input", { class: "input", type: "number", min: "1", max: "720" });
  const retentionInput = el("input", { class: "input", type: "number", min: "1", max: "30" });
  const announceInput = el("input", {
    class: "input", type: "text", placeholder: "未入力ならVCのチャット欄", inputmode: "numeric",
  });
  const excludedInput = el("input", {
    class: "input", type: "text", placeholder: "ユーザーIDをカンマ区切り（空で全員録音）",
  });

  const startButton = actionButton(
    "録音を開始", "bi-record-circle",
    async () => {
      const result = await api.post(`${BASE}/start`, { channel_id: channelInput.value.trim() });
      setTimeout(refresh, 1500);
      return result;
    },
    {
      variant: "btn-primary",
      confirm: "このVCの録音を開始します。参加者には録音中であることが通知されます。よろしいですか？",
    }
  );

  const stopButton = actionButton(
    "録音を停止", "bi-stop-circle",
    async () => {
      const result = await api.post(`${BASE}/stop`, {});
      setTimeout(refresh, 2500);
      return result;
    },
    { variant: "btn-danger", confirm: "録音を停止して書き出しますか？" }
  );

  const saveButton = actionButton("設定を保存", "bi-save", async () => {
    const excluded = excludedInput.value
      .split(",").map((v) => v.trim()).filter(Boolean);
    return api.put(`${BASE}/settings`, {
      enabled: enabledInput.checked,
      max_minutes: Number(maxMinutesInput.value),
      retention_days: Number(retentionInput.value),
      announce_channel_id: announceInput.value.trim(),
      excluded_user_ids: excluded,
    });
  }, { variant: "btn-primary" });

  function renderStatus(session, settings) {
    clear(statusBox);
    if (!session) {
      statusBox.append(
        el("div", { class: "empty", text: "現在このサーバーでは録音していません。" }),
        field("VCのチャンネルID", channelInput,
              "録音したいボイスチャンネルのIDを入れてください。開始すると参加者へ通知されます。"),
        el("div", { class: "row" }, startButton)
      );
      if (!settings.enabled) {
        statusBox.prepend(
          el("div", { class: "empty", text: "録音機能が無効です。下の設定で有効にしてください。" })
        );
      }
      return;
    }

    const remaining = Math.max(0, session.max_seconds - session.elapsed_seconds);
    statusBox.append(
      el("div", { class: "row" },
         el("span", { class: "chip danger", text: "● 録音中" }),
         el("span", { class: "list-sub grow", text: `${session.channel_name}（${session.channel_id}）` })),
      el("div", { class: "list" },
         el("div", { class: "list-row" },
            el("span", { class: "grow", text: "経過時間" }),
            el("span", { class: "mono", text: duration(session.elapsed_seconds) })),
         el("div", { class: "list-row" },
            el("span", { class: "grow", text: "自動停止まで" }),
            el("span", { class: "mono", text: duration(remaining) })),
         el("div", { class: "list-row" },
            el("span", { class: "grow", text: "開始した人" }),
            el("span", { class: "list-sub", text: session.started_by || "-" })),
         el("div", { class: "list-row" },
            el("span", { class: "grow", text: "現在のサイズ" }),
            el("span", { class: "mono", text: `${(session.output_bytes / 1024 / 1024).toFixed(1)} MB` }))),
      el("p", { class: "field-label", text: "録音中の参加者" }),
      session.speakers.length
        ? el("div", { class: "list" },
             session.speakers.map((s) =>
               el("div", { class: "list-row" },
                  el("span", { class: "grow truncate", text: s.name }),
                  el("span", { class: "list-sub mono", text: `発話 ${duration(s.voiced_seconds)}` }))))
        : el("div", { class: "empty", text: "まだ誰も発言していません。" }),
      el("div", { class: "row" }, stopButton)
    );
  }

  function renderList(recordings) {
    clear(listBox);
    if (!recordings.length) {
      listBox.append(el("div", { class: "empty", text: "保存されている録音はありません。" }));
      return;
    }
    listBox.append(
      el("div", { class: "list" },
         recordings.map((r) =>
           el("div", { class: "list-row" },
              el("div", { class: "grow list-main" },
                 el("div", { class: "truncate", text: r.title }),
                 el("div", { class: "list-sub", text: `${r.size_mb} MB / 残り約${r.remaining_hours}時間` })),
              el("a", { class: "btn btn-sm", href: r.url, target: "_blank", rel: "noopener" },
                 icon("bi-download"), "ダウンロード"))))
    );
  }

  function renderSettings(settings) {
    enabledInput.checked = Boolean(settings.enabled);
    maxMinutesInput.value = settings.max_minutes;
    retentionInput.value = settings.retention_days;
    announceInput.value = settings.announce_channel_id || "";
    excludedInput.value = (settings.excluded_user_ids || []).join(", ");
  }

  let timer = null;

  async function refresh() {
    try {
      const payload = await api.get(BASE);
      renderStatus(payload.session, payload.settings);
      renderList(payload.recordings);
      if (!settingsTouched) renderSettings(payload.settings);
    } catch (error) {
      clear(statusBox).append(
        el("div", { class: "empty", text: `状況を取得できませんでした（${error.message}）` })
      );
    }
  }

  // 設定を触っている最中に定期更新で上書きしない
  let settingsTouched = false;
  for (const input of [enabledInput, maxMinutesInput, retentionInput, announceInput, excludedInput]) {
    input.addEventListener("input", () => { settingsTouched = true; });
    input.addEventListener("change", () => { settingsTouched = true; });
  }

  clear(win.body).append(
    el(
      "div",
      { class: "stack" },
      section("録音の状況", statusBox),
      section("保存されている録音", listBox),
      section(
        "設定",
        field("録音機能を有効にする", enabledInput),
        field("自動停止までの時間（分）", maxMinutesInput, "1〜720 分。既定は 360 分（6時間）。"),
        field("保存期間（日）", retentionInput, "1〜30 日。過ぎるとダウンロードリンクが失効します。"),
        field("通知チャンネルID（省略可）", announceInput,
              "開始・完了の通知先。未入力ならVCのチャット欄へ送ります。"),
        field("録音しないユーザーID", excludedInput,
              "本人の希望で録音対象から外す場合に指定します。Discord 側で /record exclude を使ってもらっても構いません。"),
        el("div", { class: "row" }, el("span", { class: "grow" }), saveButton)
      )
    )
  );

  await refresh();
  timer = window.setInterval(refresh, POLL_INTERVAL);
  // ウィンドウを閉じたら取得を止める（閉じたのに裏で叩き続けないように）
  win.addCleanup(() => window.clearInterval(timer));
}
