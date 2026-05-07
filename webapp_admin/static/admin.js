'use strict';

// ─── Dark Mode detection ────────────────────────
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
console.log('Dark mode:', prefersDark ? 'enabled' : 'disabled');

// ─── Delete confirmation ────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Confirm dialogs
  document.querySelectorAll('.confirm-form').forEach((form) => {
    form.addEventListener('submit', (e) => {
      const msg = form.dataset.msg || '本当に実行しますか？';
      if (!window.confirm(msg)) {
        e.preventDefault();
      }
    });
  });

  // ─── Fade flash messages ────────────────────
  const alerts = document.querySelectorAll('.alert:not(.alert-dismissible [data-bs-dismiss="alert"])');
  alerts.forEach((alert) => {
    setTimeout(() => {
      const bsAlert = new bootstrap.Alert(alert);
      bsAlert.close();
    }, 5000);
  });

  // ─── Smooth navigation highlight ─────────────
  const currentPage = window.location.pathname;
  document.querySelectorAll('.sidebar-link').forEach((link) => {
    if (link.getAttribute('href') === currentPage) {
      link.classList.add('active');
    }
  });

  // ─── Mobile sidebar toggle (if needed) ──────
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('show');
    });
    // Close sidebar when link clicked
    sidebar.querySelectorAll('.sidebar-link').forEach((link) => {
      link.addEventListener('click', () => {
        sidebar.classList.remove('show');
      });
    });
  }

  // ─── Form validation feedback ───────────────
  const forms = document.querySelectorAll('form');
  forms.forEach((form) => {
    form.addEventListener('submit', (e) => {
      const inputs = form.querySelectorAll('[required]');
      let isValid = true;

      inputs.forEach((input) => {
        if (!input.value.trim()) {
          input.classList.add('is-invalid');
          isValid = false;
        } else {
          input.classList.remove('is-invalid');
        }
      });

      if (!isValid) e.preventDefault();
    });
  });

  // ─── Clear validation on input ──────────────
  document.querySelectorAll('input, select, textarea').forEach((input) => {
    input.addEventListener('input', () => {
      input.classList.remove('is-invalid');
    });
  });

  // ─── Tooltip initialization ─────────────────
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((el) => {
    new bootstrap.Tooltip(el);
  });

  // ─── Popovers initialization ────────────────
  document.querySelectorAll('[data-bs-toggle="popover"]').forEach((el) => {
    new bootstrap.Popover(el);
  });

  // ─── Toggle password visibility ─────────────
  document.querySelectorAll('[data-toggle-password]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = document.querySelector(btn.dataset.togglePassword);
      if (input) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.innerHTML = isPassword ? 
          '<i class="bi bi-eye-slash"></i>' : 
          '<i class="bi bi-eye"></i>';
      }
    });
  });

  // ─── Copy to clipboard ──────────────────────
  document.querySelectorAll('[data-copy-to-clipboard]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const text = btn.dataset.copyToClipboard;
      try {
        await navigator.clipboard.writeText(text);
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check"></i> コピー完了';
        btn.classList.add('disabled');
        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.classList.remove('disabled');
        }, 2000);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });
  });

  // ─── Loading state for buttons ──────────────
  document.querySelectorAll('button[data-loading-text]').forEach((btn) => {
    btn.addEventListener('click', function() {
      if (!this.disabled) {
        const originalHtml = this.innerHTML;
        const loadingText = this.dataset.loadingText;
        this.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>' + loadingText;
        this.disabled = true;
        setTimeout(() => {
          this.innerHTML = originalHtml;
          this.disabled = false;
        }, 3000);
      }
    });
  });

  // ─── Auto-clear form messages ───────────────
  document.querySelectorAll('.form-feedback').forEach((feedback) => {
    setTimeout(() => {
      feedback.style.transition = 'opacity 0.3s ease';
      feedback.style.opacity = '0';
      setTimeout(() => {
        feedback.remove();
      }, 300);
    }, 4000);
  });
});

// ─── Keyboard shortcuts ──────────────────────────
document.addEventListener('keydown', (e) => {
  // Escape to close modals and popovers
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal.show').forEach((modal) => {
      const bsModal = bootstrap.Modal.getInstance(modal);
      if (bsModal) bsModal.hide();
    });
  }
  // Ctrl/Cmd + K for quick search (if implemented)
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    // Implement quick search if needed
  }
});

// ─── Accessibility: Focus management ────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Tab') {
    document.body.classList.add('focus-visible');
  }
});
document.addEventListener('mousedown', () => {
  document.body.classList.remove('focus-visible');
});
