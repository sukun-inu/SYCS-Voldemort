'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const hasBootstrap = typeof bootstrap !== 'undefined';

  document.querySelectorAll('.confirm-form').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const message = form.dataset.msg || '本当に実行しますか？';
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  document.querySelectorAll('[data-auto-dismiss="true"]').forEach((alert) => {
    if (!hasBootstrap) return;
    window.setTimeout(() => {
      bootstrap.Alert.getOrCreateInstance(alert).close();
    }, 5200);
  });

  const sidebarToggle = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');
  const sidebarBackdrop = document.getElementById('sidebar-backdrop');

  const closeSidebar = () => {
    if (!sidebar || !sidebarToggle || !sidebarBackdrop) return;
    sidebar.classList.remove('is-open');
    sidebarToggle.setAttribute('aria-expanded', 'false');
    sidebarBackdrop.hidden = true;
  };

  const openSidebar = () => {
    if (!sidebar || !sidebarToggle || !sidebarBackdrop) return;
    sidebar.classList.add('is-open');
    sidebarToggle.setAttribute('aria-expanded', 'true');
    sidebarBackdrop.hidden = false;
  };

  if (sidebarToggle && sidebar && sidebarBackdrop) {
    sidebarToggle.addEventListener('click', () => {
      if (sidebar.classList.contains('is-open')) {
        closeSidebar();
      } else {
        openSidebar();
      }
    });

    sidebarBackdrop.addEventListener('click', closeSidebar);
    sidebar.querySelectorAll('.sidebar-link').forEach((link) => {
      link.addEventListener('click', closeSidebar);
    });
  }

  document.querySelectorAll('form').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const requiredFields = form.querySelectorAll('[required]');
      let isValid = true;

      requiredFields.forEach((field) => {
        if (!field.value.trim()) {
          field.classList.add('is-invalid');
          isValid = false;
        } else {
          field.classList.remove('is-invalid');
        }
      });

      if (!isValid) {
        event.preventDefault();
      }
    });
  });

  document.querySelectorAll('input, select, textarea').forEach((field) => {
    field.addEventListener('input', () => {
      field.classList.remove('is-invalid');
    });
    field.addEventListener('change', () => {
      field.classList.remove('is-invalid');
    });
  });

  if (hasBootstrap) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((element) => {
      bootstrap.Tooltip.getOrCreateInstance(element);
    });

    document.querySelectorAll('[data-bs-toggle="popover"]').forEach((element) => {
      bootstrap.Popover.getOrCreateInstance(element);
    });
  }

  document.querySelectorAll('[data-toggle-password]').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.querySelector(button.dataset.togglePassword);
      if (!input) return;

      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      button.innerHTML = isPassword
        ? '<i class="bi bi-eye-slash"></i>'
        : '<i class="bi bi-eye"></i>';
    });
  });

  const parseJsonDataset = (elementId, datasetKey, fallback = {}) => {
    const element = document.getElementById(elementId);
    if (!element || !element.dataset[datasetKey]) return fallback;

    try {
      return JSON.parse(element.dataset[datasetKey]);
    } catch (error) {
      return fallback;
    }
  };

  const setButtonLabel = (element, iconClass, label) => {
    if (!element) return;
    element.innerHTML = `<i class="bi ${iconClass} me-2"></i>${label}`;
  };

  const clearInvalidState = (...fields) => {
    fields.forEach((field) => field?.classList.remove('is-invalid'));
  };

  const initStickyEditor = () => {
    const formCard = document.getElementById('sticky-form-card');
    const select = document.getElementById('sticky_channel_id');
    const area = document.getElementById('sticky_content');
    const title = document.getElementById('sticky-form-title');
    const submit = document.getElementById('sticky-submit');
    const cancel = document.getElementById('sticky-cancel');

    if (!formCard || !select || !area || !title || !submit || !cancel) return;

    const stickies = parseJsonDataset('sticky-data', 'stickiesJson');

    document.querySelectorAll('[data-edit-sticky]').forEach((button) => {
      button.addEventListener('click', () => {
        const channelId = button.dataset.editSticky;
        const entry = stickies[channelId] || {};

        select.value = channelId || '';
        area.value = entry.content || '';
        clearInvalidState(select, area);

        title.innerHTML = '<i class="bi bi-pencil"></i>編集';
        setButtonLabel(submit, 'bi-check-lg', '更新');
        cancel.classList.remove('d-none');
        formCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });

    cancel.addEventListener('click', () => {
      select.value = '';
      area.value = '';
      clearInvalidState(select, area);

      title.innerHTML = '<i class="bi bi-plus-circle"></i>追加';
      setButtonLabel(submit, 'bi-check-lg', '設定');
      cancel.classList.add('d-none');
    });
  };

  const initFeedEditor = () => {
    const formCard = document.getElementById('feed-form-card');
    const action = document.getElementById('feed-action');
    const feedIdField = document.getElementById('feed-id-field');
    const channel = document.getElementById('news_channel_id');
    const query = document.getElementById('feed_query');
    const interval = document.getElementById('feed_interval');
    const title = document.getElementById('feed-form-title');
    const submit = document.getElementById('feed-submit');
    const cancel = document.getElementById('feed-cancel');

    if (!formCard || !action || !feedIdField || !channel || !query || !interval || !title || !submit || !cancel) return;

    const feeds = parseJsonDataset('feed-data', 'feedsJson');
    const editableFields = [channel, query, interval];

    document.querySelectorAll('[data-edit-feed]').forEach((button) => {
      button.addEventListener('click', () => {
        const feedId = button.dataset.editFeed;
        const feed = feeds[feedId] || {};

        action.value = 'edit';
        feedIdField.value = feedId || '';
        channel.value = String(feed.channel_id || '');
        query.value = feed.query || '';
        interval.value = feed.interval || 60;
        clearInvalidState(...editableFields);

        title.innerHTML = '<i class="bi bi-pencil"></i>フィードを編集';
        setButtonLabel(submit, 'bi-check-lg', '更新');
        cancel.classList.remove('d-none');
        formCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });

    cancel.addEventListener('click', () => {
      action.value = 'add';
      feedIdField.value = '';
      channel.value = '';
      query.value = '';
      interval.value = '60';
      clearInvalidState(...editableFields);

      title.innerHTML = '<i class="bi bi-plus-circle"></i>フィードを追加';
      setButtonLabel(submit, 'bi-plus-lg', '追加');
      cancel.classList.add('d-none');
    });
  };

  initStickyEditor();
  initFeedEditor();

  document.querySelectorAll('[data-copy-to-clipboard]').forEach((button) => {
    button.addEventListener('click', async () => {
      const text = button.dataset.copyToClipboard;
      const originalHtml = button.innerHTML;

      try {
        await navigator.clipboard.writeText(text);
        button.innerHTML = '<i class="bi bi-check"></i> コピー完了';
        button.disabled = true;
        window.setTimeout(() => {
          button.innerHTML = originalHtml;
          button.disabled = false;
        }, 1800);
      } catch (error) {
        button.innerHTML = '<i class="bi bi-exclamation-circle"></i> 失敗';
        window.setTimeout(() => {
          button.innerHTML = originalHtml;
        }, 1800);
      }
    });
  });

  document.querySelectorAll('[data-loading-text]').forEach((button) => {
    button.addEventListener('click', () => {
      if (button.disabled) return;
      const form = button.closest('form');
      if (form && !form.checkValidity()) return;
      const loadingText = button.dataset.loadingText || '処理中';
      button.dataset.originalHtml = button.innerHTML;
      button.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${loadingText}`;
      button.disabled = true;
    });
  });

  const metricsRoot = document.querySelector('[data-metrics-url]');
  if (metricsRoot) {
    const updated = metricsRoot.querySelector('[data-metrics-updated]');
    const updateMetrics = async () => {
      try {
        const response = await fetch(metricsRoot.dataset.metricsUrl, {
          headers: { Accept: 'application/json' },
          credentials: 'same-origin',
          cache: 'no-store',
        });

        if (!response.ok) {
          throw new Error(`metrics ${response.status}`);
        }

        const payload = await response.json();
        Object.entries(payload.metrics || {}).forEach(([key, metric]) => {
          const card = metricsRoot.querySelector(`[data-metric-card="${key}"]`);
          if (!card) return;

          const value = Number(metric.percent || 0);
          const ring = card.querySelector('[data-ring]');
          const display = card.querySelector('[data-metric-display]');
          const detail = card.querySelector('[data-metric-detail]');

          ring?.style.setProperty('--value', Math.max(0, Math.min(value, 100)).toFixed(2));
          if (display) display.textContent = metric.display || `${value.toFixed(1)}%`;
          if (detail) detail.textContent = metric.detail || '';
          card.setAttribute('aria-label', `${metric.label || key}: ${metric.display || value}`);
        });

        if (updated) {
          updated.textContent = `更新 ${payload.updated_at || '--:--:--'}`;
          updated.classList.remove('warning');
          updated.classList.add('accent');
        }
      } catch (error) {
        if (updated) {
          updated.textContent = '取得失敗';
          updated.classList.remove('accent');
          updated.classList.add('warning');
        }
      }
    };

    updateMetrics();
    window.setInterval(updateMetrics, 5000);
  }

  const incidentsRoot = document.querySelector('[data-incidents-url]');
  if (incidentsRoot) {
    const list = incidentsRoot.querySelector('[data-incident-list]');
    const count = incidentsRoot.querySelector('[data-incidents-count]');

    const iconForIncident = (kind) => {
      if (kind === 'downtime') return 'bi-power';
      if (kind === 'exception') return 'bi-bug';
      if (kind === 'http_error') return 'bi-exclamation-octagon';
      if (kind === 'resource_alert') return 'bi-activity';
      return 'bi-info-circle';
    };

    const renderEmptyIncidents = () => {
      if (!list) return;
      list.innerHTML = '';
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      const inner = document.createElement('div');
      const icon = document.createElement('i');
      icon.className = 'bi bi-check-circle';
      const text = document.createElement('p');
      text.className = 'mb-0';
      text.textContent = '記録済みの異常はありません。';
      inner.append(icon, text);
      empty.append(inner);
      list.append(empty);
    };

    const renderIncidents = (incidents) => {
      if (!list) return;
      list.innerHTML = '';

      if (!incidents.length) {
        renderEmptyIncidents();
        return;
      }

      incidents.slice(0, 8).forEach((incident) => {
        const row = document.createElement('article');
        row.className = `incident-row severity-${incident.severity || 'info'}`;

        const iconWrap = document.createElement('div');
        iconWrap.className = 'incident-icon';
        const icon = document.createElement('i');
        icon.className = `bi ${iconForIncident(incident.kind)}`;
        iconWrap.append(icon);

        const body = document.createElement('div');
        body.className = 'min-w-0';
        const title = document.createElement('h3');
        title.className = 'incident-title';
        title.textContent = incident.title || 'Incident';
        const message = document.createElement('p');
        message.className = 'incident-message';
        message.textContent = incident.message || '';
        body.append(title, message);

        const meta = document.createElement('div');
        meta.className = 'incident-meta';
        meta.textContent = incident.duration
          ? `${incident.created_at || ''} / ${incident.duration}`
          : incident.created_at || '';

        row.append(iconWrap, body, meta);
        list.append(row);
      });
    };

    const updateIncidents = async () => {
      try {
        const response = await fetch(incidentsRoot.dataset.incidentsUrl, {
          headers: { Accept: 'application/json' },
          credentials: 'same-origin',
          cache: 'no-store',
        });

        if (!response.ok) {
          throw new Error(`incidents ${response.status}`);
        }

        const payload = await response.json();
        const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
        renderIncidents(incidents);
        if (count) {
          count.textContent = `${incidents.length} 件`;
          count.classList.remove('warning');
          count.classList.add('accent');
        }
      } catch (error) {
        if (count) {
          count.textContent = '取得失敗';
          count.classList.remove('accent');
          count.classList.add('warning');
        }
      }
    };

    updateIncidents();
    window.setInterval(updateIncidents, 10000);
  }

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    closeSidebar();

    if (!hasBootstrap) return;
    document.querySelectorAll('.modal.show').forEach((modal) => {
      bootstrap.Modal.getInstance(modal)?.hide();
    });
  });

  // ── 自動保存 ──────────────────────────────────────────────
  const _autosaveTimers = new WeakMap();

  const doAutoSave = async (form) => {
    const statusEl = form.querySelector('.autosave-status');
    const textEl   = statusEl?.querySelector('.autosave-text');
    const iconEl   = statusEl?.querySelector('.autosave-icon');

    if (iconEl) { iconEl.className = 'bi bi-cloud-upload autosave-icon saving'; }
    if (textEl)   textEl.textContent = '保存中…';

    try {
      const resp = await fetch(window.location.href, {
        method: 'POST',
        body: new FormData(form),
        credentials: 'same-origin',
      });
      if (!resp.ok) throw new Error(String(resp.status));
      if (iconEl) { iconEl.className = 'bi bi-cloud-check-fill autosave-icon ok'; }
      if (textEl)   textEl.textContent = '保存済み';
      window.setTimeout(() => {
        if (iconEl) { iconEl.className = 'bi bi-cloud-check-fill autosave-icon'; }
        if (textEl)   textEl.textContent = '変更は自動保存されます';
      }, 2000);
    } catch (_) {
      if (iconEl) { iconEl.className = 'bi bi-cloud-slash-fill autosave-icon error'; }
      if (textEl)   textEl.textContent = '保存失敗';
      window.setTimeout(() => {
        if (iconEl) { iconEl.className = 'bi bi-cloud-check-fill autosave-icon'; }
        if (textEl)   textEl.textContent = '変更は自動保存されます';
      }, 3000);
    }
  };

  const scheduleAutoSave = (form) => {
    if (_autosaveTimers.has(form)) clearTimeout(_autosaveTimers.get(form));
    _autosaveTimers.set(form, window.setTimeout(() => {
      _autosaveTimers.delete(form);
      doAutoSave(form);
    }, 250));
  };

  document.querySelectorAll('form[data-autosave]').forEach((form) => {
    const actionsEl = form.querySelector('.form-actions');
    if (actionsEl) {
      actionsEl.innerHTML = `
        <span class="autosave-status" aria-live="polite">
          <i class="bi bi-cloud-check-fill autosave-icon"></i>
          <span class="autosave-text">変更は自動保存されます</span>
        </span>`;
    }
    form.querySelectorAll('select, input[type="checkbox"], input[type="radio"], input[type="number"], input[type="range"]')
      .forEach((field) => field.addEventListener('change', () => scheduleAutoSave(form)));
  });
});
