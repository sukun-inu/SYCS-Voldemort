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
      const loadingText = button.dataset.loadingText || '処理中';
      button.dataset.originalHtml = button.innerHTML;
      button.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${loadingText}`;
      button.disabled = true;
    });
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    closeSidebar();

    if (!hasBootstrap) return;
    document.querySelectorAll('.modal.show').forEach((modal) => {
      bootstrap.Modal.getInstance(modal)?.hide();
    });
  });
});
