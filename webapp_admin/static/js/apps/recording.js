/* VC録音。録音の状況・開始と停止・保存済みアーカイブ・設定をまとめて扱う。

   開始と停止は Bot 側でしか行えないため、ここでは API 経由でシグナルを置く。
   反映には数十秒かかるので、状況は定期的に取り直す。 */

import * as api from "../lib/api.js";
import { createMixer } from "./mixer.js";
import { fillSelect, selectValue } from "../lib/choices.js";
import { el, icon, clear, loading, field } from "../lib/dom.js";
import { toast } from "../lib/toast.js";

const BASE = "/admin/api/recording";
const POLL_INTERVAL = 5000;

/** オン・オフの欄。チェックと文字を横に並べる。
 *
 *  スキーマ駆動の画面（forms/widgets.js）が同じ見た目にしているので、
 *  こちらだけ「ラベルが上・箱が中央」になっていると座りが悪い。 */
function toggleField(label, input, help) {
  return el(
    "div",
    { class: "field" },
    el("label", { class: "check" }, input, el("span", { class: "check-text", text: label })),
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

  // ID を手打ちさせず選ばせる。一覧が空のとき（Bot トークン未設定など）は
  // 設定する手段が無くならないよう手入力へ切り替える。
  const channelSelect = el("select", { class: "select" });
  const channelManual = el("input", {
    class: "input", type: "text", placeholder: "録音するVCのチャンネルID", inputmode: "numeric",
  });
  const channelNote = el("p", { class: "field-help" });
  const channelBox = el("div", { class: "stack" }, channelSelect, channelManual, channelNote);
  let channelManualMode = false;
  const channelValue = () =>
    (channelManualMode ? channelManual.value.trim() : channelSelect.value);

  const enabledInput = el("input", { type: "checkbox" });
  const autoStartInput = el("input", { type: "checkbox" });
  // 自動録音の対象VC。未選択なら読み上げと同じVCに従う。
  const autoVcSelect = el("select", { class: "select" });
  const autoVcManual = el("input", {
    class: "input", type: "text", placeholder: "VCのチャンネルID", inputmode: "numeric",
  });
  const autoVcNote = el("p", { class: "field-help" });
  const autoVcBox = el("div", { class: "stack" }, autoVcSelect, autoVcManual, autoVcNote);
  let autoVcManualMode = false;
  const autoVcValue = () =>
    (autoVcManualMode ? autoVcManual.value.trim() : autoVcSelect.value);
  const maxMinutesInput = el("input", { class: "input", type: "number", min: "0", max: "720" });
  const retentionInput = el("input", { class: "input", type: "number", min: "1", max: "30" });
  const announceSelect = el("select", { class: "select" });
  const announceManual = el("input", {
    class: "input", type: "text", placeholder: "未入力ならVCのチャット欄", inputmode: "numeric",
  });
  const announceNote = el("p", { class: "field-help" });
  const announceBox = el("div", { class: "stack" }, announceSelect, announceManual, announceNote);
  let announceManualMode = false;
  const announceValue = () =>
    (announceManualMode ? announceManual.value.trim() : announceSelect.value);

  /** 一覧が取れたらプルダウン、取れなければ ID の手入力にする。 */
  function fillChannels(select, manual, note, list, { voice, placeholder, emptyNote, preselect }) {
    if (!list || !list.length) {
      manual.hidden = false;
      select.hidden = true;
      note.textContent = emptyNote;
      // 一覧が無くても、既定が分かっているなら入れておく
      if (preselect && !manual.value) manual.value = String(preselect);
      return true;   // 手入力モード
    }
    const keep = select.value;
    manual.hidden = true;
    select.hidden = false;
    note.textContent = "";
    // 触っていない欄には既定を入れておく（毎回選び直させないため）
    const wanted = keep || (preselect ? String(preselect) : "");
    fillSelect(select, list, { placeholder, value: wanted });
    return false;
  }
  const excludedInput = el("input", {
    class: "input", type: "text", placeholder: "ユーザーIDをカンマ区切り（空で全員録音）",
  });

  const startButton = actionButton(
    "録音を開始", "bi-record-circle",
    async () => {
      const result = await api.post(`${BASE}/start`, { channel_id: channelValue() });
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
      auto_start: autoStartInput.checked,
      vc_channel_id: autoVcValue(),
      max_minutes: Number(maxMinutesInput.value),
      retention_days: Number(retentionInput.value),
      announce_channel_id: announceValue(),
      excluded_user_ids: excluded,
    });
  }, { variant: "btn-primary" });

  function renderStatus(session, settings) {
    clear(statusBox);
    if (!session) {
      statusBox.append(
        el("div", { class: "empty", text: "現在このサーバーでは録音していません。" }),
        field("録音するVC", channelBox,
              "開始すると、そのVCの参加者へ録音中であることが通知されます。"),
        el("div", { class: "row" }, startButton)
      );
      if (!settings.enabled) {
        statusBox.prepend(
          el("div", { class: "empty", text: "録音機能が無効です。下の設定で有効にしてください。" })
        );
      }
      return;
    }

    // 無制限のときは残り時間ではなく、何が起きたら止まるのかを出す
    const stopsAt = session.unlimited
      ? "全員が退出したとき"
      : duration(Math.max(0, session.max_seconds - session.elapsed_seconds));
    statusBox.append(
      el("div", { class: "row" },
         el("span", { class: "chip danger", text: "● 録音中" }),
         el("span", { class: "list-sub grow", text: `${session.channel_name}（${session.channel_id}）` })),
      el("div", { class: "list" },
         el("div", { class: "list-row" },
            el("span", { class: "grow", text: "経過時間" }),
            el("span", { class: "mono", text: duration(session.elapsed_seconds) })),
         el("div", { class: "list-row" },
            el("span", { class: "grow", text: session.unlimited ? "停止条件" : "自動停止まで" }),
            el("span", { class: session.unlimited ? "list-sub" : "mono", text: stopsAt })),
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
      // ここが空だとミキサーの入口も消える。機能が無いのか、まだ録音が無いだけ
      // なのかが画面から分からなくなるので、理由を書いておく。
      listBox.append(
        el("div", { class: "empty" },
           el("div", { text: "保存されている録音はありません。" }),
           el("div", { class: "list-sub", text:
             "録音を停止すると、ここに並びます。各行の「ミキサー」から、" +
             "参加者ごとの波形を同じ時間軸に並べて再生・確認できます。" }))
      );
      return;
    }
    listBox.append(
      el("div", { class: "list" },
         recordings.map((r) =>
           el("div", { class: "list-row" },
              el("div", { class: "grow list-main" },
                 el("div", { class: "truncate", text: r.title }),
                 el("div", { class: "list-sub", text: `${r.size_mb} MB / 残り約${r.remaining_hours}時間` })),
              el("button", {
                class: "btn btn-sm", type: "button",
                onclick: () => openMixer(r),
              }, icon("bi-sliders"), "ミキサー"),
              el("a", { class: "btn btn-sm", href: r.url, target: "_blank", rel: "noopener" },
                 icon("bi-download"), "ダウンロード"))))
    );
  }

  // 設定されている ID が一覧に無いとき（チャンネルが消えた・Bot から見えない・
  // 種類が違う）。値は保持したまま、その旨を出す。
  const UNKNOWN_CHANNEL_NOTE =
    "設定されているチャンネルが一覧にありません。削除されたか、Bot から見えない可能性があります。"
    + "そのままにすれば設定は変わりません。";
  let missingAutoVc = false;
  let missingAnnounce = false;

  function renderSettings(settings) {
    enabledInput.checked = Boolean(settings.enabled);
    autoStartInput.checked = Boolean(settings.auto_start);
    const autoVcId = settings.vc_channel_id ? String(settings.vc_channel_id) : "";
    if (autoVcManualMode) autoVcManual.value = autoVcId;
    else missingAutoVc = selectValue(autoVcSelect, autoVcId);
    maxMinutesInput.value = settings.max_minutes;
    retentionInput.value = settings.retention_days;
    const announceId = settings.announce_channel_id ? String(settings.announce_channel_id) : "";
    if (announceManualMode) announceManual.value = announceId;
    else missingAnnounce = selectValue(announceSelect, announceId);
    excludedInput.value = (settings.excluded_user_ids || []).join(", ");

    // 一覧に出てこない ID を選んでいる（消えた／権限が無い／種類が違う）ときは、
    // なぜ見慣れない表示になっているのかを書く。黙って直っているように見せない。
    const orphan = [missingAutoVc && "録音するVC", missingAnnounce && "通知チャンネル"]
      .filter(Boolean).join("・");
    autoVcNote.textContent = missingAutoVc ? UNKNOWN_CHANNEL_NOTE : "";
    announceNote.textContent = missingAnnounce ? UNKNOWN_CHANNEL_NOTE : "";
    if (orphan) console.warn(`[recording] 一覧に無いチャンネルが設定されています: ${orphan}`);
  }

  // ── ミキサー表示 ───────────────────────────────────────
  // ウィンドウはアプリIDで一意なので録音ごとに窓を開けない。パネルの中身を
  // 差し替えて開き、「戻る」で一覧へ帰る。開いているあいだは定期更新を止める
  // （5秒ごとの再描画で画面ごと消えてしまうため）。
  let mixerHandle = null;
  const rootView = el("div", { class: "stack" });

  async function openMixer(recording) {
    if (timer) { window.clearInterval(timer); timer = null; }
    const stage = el("div", { class: "stack" });
    clear(win.body).append(
      el("div", { class: "stack" },
         el("div", { class: "row" },
            // ミキサーの操作列（32px）のすぐ上に来るので、btn-sm（26px）に
            // しない。1つだけ小さいボタンが乗っていると、列が2段とも半端に見える。
            el("button", {
              class: "btn", type: "button", onclick: () => closeMixer(),
            }, icon("bi-arrow-left"), "録音一覧へ戻る"),
            el("span", { class: "list-sub grow truncate", text: recording.title })),
         stage)
    );
    try {
      mixerHandle = await createMixer(stage, {
        manifestUrl: `${recording.url}/mixer`,
        clipUrl: `${recording.url}/clip`,
      });
    } catch (error) {
      clear(stage).append(
        el("div", { class: "empty", text: `ミキサーを開けませんでした（${error.message}）` })
      );
    }
  }

  function closeMixer() {
    if (mixerHandle) { mixerHandle.destroy(); mixerHandle = null; }
    clear(win.body).append(rootView);
    refresh();
    if (!timer) timer = window.setInterval(refresh, POLL_INTERVAL);
  }

  let timer = null;

  // チャンネル一覧は数秒おきに取り直す必要がない。取れるまでは要求し、
  // 一度揃ったら状況だけを取りに行く（Discord のレート制限に当たるため）。
  let haveChannels = false;

  async function refresh() {
    try {
      const payload = await api.get(haveChannels ? `${BASE}?include_channels=0` : BASE);
      if (!haveChannels) {
        applyChannels(payload);
      }
      renderStatus(payload.session, payload.settings);
      renderList(payload.recordings);
      if (!settingsTouched) renderSettings(payload.settings);
    } catch (error) {
      clear(statusBox).append(
        el("div", { class: "empty", text: `状況を取得できませんでした（${error.message}）` })
      );
    }
  }

  function applyChannels(payload) {
    channelManualMode = fillChannels(channelSelect, channelManual, channelNote,
        payload.voice_channels, {
          preselect: payload.default_vc_channel_id,
          voice: true, placeholder: "録音するVCを選択",
          emptyNote: "ボイスチャンネルの一覧を取得できませんでした。ID を直接入力できます。",
        });
    announceManualMode = fillChannels(announceSelect, announceManual, announceNote,
        payload.channels, {
          voice: false, placeholder: "VCのチャット欄へ送る（既定）",
          emptyNote: "チャンネルの一覧を取得できませんでした。ID を直接入力できます。",
        });
    autoVcManualMode = fillChannels(autoVcSelect, autoVcManual, autoVcNote,
        payload.voice_channels, {
          voice: true, placeholder: "読み上げと同じVC（既定）",
          emptyNote: "ボイスチャンネルの一覧を取得できませんでした。ID を直接入力できます。",
        });
    // 取れなかったときは次の更新でもう一度試す
    haveChannels = Boolean((payload.voice_channels || []).length
                           || (payload.channels || []).length);
  }

  // 設定を触っている最中に定期更新で上書きしない
  let settingsTouched = false;
  for (const input of [enabledInput, autoStartInput, autoVcSelect, autoVcManual,
                       maxMinutesInput, retentionInput,
                       announceSelect, announceManual, excludedInput]) {
    input.addEventListener("input", () => { settingsTouched = true; });
    input.addEventListener("change", () => { settingsTouched = true; });
  }

  // 一覧の画面は使い回す（ミキサーから戻ってきたときに組み立て直さない）
  rootView.append(
      section("録音の状況", statusBox),
      section("保存されている録音", listBox,
              el("p", { class: "field-help", text:
                "「ミキサー」を押すと、参加者ごとのトラックを同じ時間軸に並べて" +
                "波形表示・再生できます（ミュート／ソロ／音量、波形クリックで頭出し）。" +
                "途中から参加した人は冒頭が、途中で抜けた人は末尾が無音になります。" })),
      section(
        "設定",
        toggleField("録音を有効にする", enabledInput,
              "オフにすると、自動録音も手動の開始もできません。"),
        toggleField("自動で録音する", autoStartInput,
              "オンにすると、対象VCに人が入った時点で録音を始めます。"
              + "読み上げとは独立したスイッチで、両方オンなら同じ接続で両方動きます。"),
        field("自動録音の対象VC（省略可）", autoVcBox,
              "未選択なら読み上げ（TTS）の対象VCに従います。録音だけ別のVCを狙うときに指定します。"),
        field("自動停止までの時間（分）", maxMinutesInput,
              "0〜720 分。0 にすると時間では止めず、VC から全員が退出するまで録り続けます。既定は 360 分（6時間）。"),
        field("保存期間（日）", retentionInput, "1〜30 日。過ぎるとダウンロードリンクが失効します。"),
        field("通知チャンネル（省略可）", announceBox,
              "開始・完了の通知先。未選択ならVCのチャット欄へ送ります。"),
        field("録音しないユーザーID", excludedInput,
              "本人の希望で録音対象から外す場合に指定します。Discord 側で /record exclude を使ってもらっても構いません。"),
        el("div", { class: "row" }, el("span", { class: "grow" }), saveButton)
      )
  );
  clear(win.body).append(rootView);

  await refresh();
  timer = window.setInterval(refresh, POLL_INTERVAL);
  // ウィンドウを閉じたら取得と再生を止める（閉じたのに裏で動き続けないように）
  win.addCleanup(() => {
    window.clearInterval(timer);
    if (mixerHandle) mixerHandle.destroy();
  });
}
