'use strict';

// 削除ボタンに確認ダイアログ
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.confirm-form').forEach((form) => {
    form.addEventListener('submit', (e) => {
      const msg = form.dataset.msg || '本当に実行しますか？';
      if (!window.confirm(msg)) {
        e.preventDefault();
      }
    });
  });
});
