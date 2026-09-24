/**
 * Optional progressive enhancements for shared Grayhaven Systems LLC web
 * components. Native controls remain usable without JavaScript.
 */
(function () {
  'use strict';

  async function copyText(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }

    const fallback = document.createElement('textarea');
    fallback.value = value;
    fallback.setAttribute('readonly', 'true');
    fallback.className = 'clipboard-fallback';
    document.body.appendChild(fallback);
    fallback.select();
    const copied = document.execCommand('copy');
    fallback.remove();
    if (!copied) throw new Error('Clipboard copy was rejected');
  }

  document.addEventListener('click', function (event) {
    if (!(event.target instanceof Element)) return;

    const button = event.target.closest('[data-copy-target]');
    if (!(button instanceof HTMLButtonElement)) return;

    let target;
    try {
      target = document.querySelector(button.dataset.copyTarget || '');
    } catch {
      return;
    }
    const value = target && (target.dataset.copyValue || target.textContent.trim());
    if (!value) return;

    copyText(value).then(function () {
      const original = button.innerHTML;
      const originalLabel = button.getAttribute('aria-label');
      const originalTitle = button.getAttribute('title');
      button.innerHTML =
        '<i class="fa-solid fa-check" aria-hidden="true"></i>' +
        '<span class="visually-hidden">Copied</span>';
      button.setAttribute('aria-label', 'Copied');
      button.setAttribute('title', 'Copied');
      window.setTimeout(function () {
        button.innerHTML = original;
        if (originalLabel === null) button.removeAttribute('aria-label');
        else button.setAttribute('aria-label', originalLabel);
        if (originalTitle === null) button.removeAttribute('title');
        else button.setAttribute('title', originalTitle);
      }, 1800);
    }).catch(function () {
      window.prompt('Copy this value', value);
    });
  });

  function datetimeLocalNow(timeZone) {
    const values = new Intl.DateTimeFormat('en-CA', {
      timeZone: timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23'
    }).formatToParts(new Date()).reduce(function (result, part) {
      result[part.type] = part.value;
      return result;
    }, {});

    return values.year + '-' + values.month + '-' + values.day + 'T' +
      values.hour + ':' + values.minute + ':' + values.second;
  }

  document.querySelectorAll('[data-set-now-for]').forEach(function (button) {
    button.addEventListener('click', function () {
      const input = document.querySelector(button.dataset.setNowFor || '');
      if (!(input instanceof HTMLInputElement)) return;

      input.value = datetimeLocalNow(
        input.dataset.timezone ||
          Intl.DateTimeFormat().resolvedOptions().timeZone
      );
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
  });

  document.querySelectorAll('[data-verification-code]').forEach(
    function (group) {
      const inputs = Array.from(group.querySelectorAll('input'));

      function distributeDigits(value) {
        const digits = value.replace(/\D/g, '').slice(0, inputs.length);
        inputs.forEach(function (input, index) {
          input.value = digits[index] || '';
        });
        const focusIndex = Math.min(digits.length, inputs.length - 1);
        inputs[focusIndex].focus();
        inputs[focusIndex].select();
      }

      group.addEventListener('paste', function (event) {
        const clipboard = event.clipboardData;
        const digits = clipboard
          ? clipboard.getData('text').replace(/\D/g, '')
          : '';
        if (digits.length === inputs.length) {
          event.preventDefault();
          distributeDigits(digits);
        }
      });

      inputs.forEach(function (input, index) {
        input.addEventListener('input', function () {
          const digits = input.value.replace(/\D/g, '');
          if (digits.length > 1) {
            distributeDigits(digits);
            return;
          }
          input.value = digits;
          if (digits && index < inputs.length - 1) {
            inputs[index + 1].focus();
            inputs[index + 1].select();
          }
        });

        input.addEventListener('focus', function () { input.select(); });
        input.addEventListener('keydown', function (event) {
          if (event.key === 'Backspace' && !input.value && index > 0) {
            event.preventDefault();
            inputs[index - 1].value = '';
            inputs[index - 1].focus();
          } else if (event.key === 'ArrowLeft' && index > 0) {
            event.preventDefault();
            inputs[index - 1].focus();
          } else if (event.key === 'ArrowRight' && index < inputs.length - 1) {
            event.preventDefault();
            inputs[index + 1].focus();
          }
        });
      });
    }
  );

  function dismissAlert(alert) {
    if (!(alert instanceof HTMLElement) ||
        alert.classList.contains('is-dismissing')) return;

    alert.classList.add('is-dismissing');
    window.setTimeout(function () { alert.remove(); }, 300);
  }

  function scheduleAlertDismissal(alert) {
    if (!(alert instanceof HTMLElement) ||
        alert.dataset.dismissScheduled === 'true') return;

    alert.dataset.dismissScheduled = 'true';
    window.setTimeout(function () { dismissAlert(alert); }, 4500);
  }

  document.querySelectorAll('.alert[data-auto-dismiss]').forEach(
    scheduleAlertDismissal
  );

  document.addEventListener('click', function (event) {
    const dismiss = event.target instanceof Element
      ? event.target.closest('[data-alert-dismiss]')
      : null;
    if (!(dismiss instanceof HTMLButtonElement)) return;
    dismissAlert(dismiss.closest('.alert'));
  });

  const notificationOptions = {
    info: { icon: 'fa-circle-info', role: 'status' },
    success: { icon: 'fa-circle-check', role: 'status' },
    warning: { icon: 'fa-triangle-exclamation', role: 'status' },
    error: { icon: 'fa-circle-xmark', role: 'alert' }
  };

  document.querySelectorAll('[data-notification-trigger]').forEach(
    function (button) {
      button.addEventListener('click', function () {
        const launcher = button.closest('[data-notification-launcher]');
        const select = launcher &&
          launcher.querySelector('[data-notification-tone]');
        let target;
        try {
          target = document.querySelector(
            button.dataset.notificationTarget || ''
          );
        } catch {
          return;
        }
        if (!(select instanceof HTMLSelectElement) ||
            !(target instanceof HTMLElement)) return;

        const tone = Object.hasOwn(notificationOptions, select.value)
          ? select.value
          : 'info';
        const option = notificationOptions[tone];
        const selectedOption = select.selectedOptions[0];
        const notification = document.createElement('div');
        notification.className =
          'alert alert-' + tone + ' alert-with-icon';
        notification.setAttribute('role', option.role);
        notification.dataset.autoDismiss = '';

        const icon = document.createElement('i');
        icon.className = 'fa-solid ' + option.icon;
        icon.setAttribute('aria-hidden', 'true');
        const message = document.createElement('span');
        message.className = 'alert-message';
        message.textContent = selectedOption &&
          selectedOption.dataset.notificationMessage
          ? selectedOption.dataset.notificationMessage
          : 'Example notification';
        const dismiss = document.createElement('button');
        dismiss.className = 'alert-dismiss';
        dismiss.type = 'button';
        dismiss.setAttribute('aria-label', 'Dismiss notification');
        dismiss.dataset.alertDismiss = '';
        const dismissIcon = document.createElement('i');
        dismissIcon.className = 'fa-solid fa-xmark';
        dismissIcon.setAttribute('aria-hidden', 'true');
        dismiss.append(dismissIcon);

        notification.append(icon, message, dismiss);
        target.replaceChildren(notification);
        scheduleAlertDismissal(notification);
      });
    }
  );

  document.querySelectorAll('[data-file-input]').forEach(function (input) {
    const control = input.closest('.file-control');
    const name = control && control.querySelector('[data-file-name]');
    if (!(input instanceof HTMLInputElement) || !(name instanceof HTMLElement)) {
      return;
    }

    input.addEventListener('change', function () {
      const files = input.files ? Array.from(input.files) : [];
      name.textContent = files.length
        ? files.map(function (file) { return file.name; }).join(', ')
        : 'No file selected';
    });
  });

  document.querySelectorAll('[data-range-percentage]').forEach(
    function (control) {
      const input = control.querySelector('input[type="range"]');
      const output = control.querySelector('output');
      if (!(input instanceof HTMLInputElement) ||
          !(output instanceof HTMLOutputElement)) return;

      function updatePercentage() {
        const minimum = Number(input.min || 0);
        const maximum = Number(input.max || 100);
        const value = Number(input.value);
        const percentage = maximum > minimum
          ? Math.round(((value - minimum) / (maximum - minimum)) * 100)
          : 0;
        output.value = percentage + '%';
      }

      input.addEventListener('input', updatePercentage);
      updatePercentage();
    }
  );

  document.querySelectorAll('form[data-validate-form]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      form.reportValidity();
    });
  });

  document.querySelectorAll('[data-dialog-open]').forEach(function (button) {
    button.addEventListener('click', function () {
      const dialog = document.querySelector(button.dataset.dialogOpen || '');
      if (!(dialog instanceof HTMLDialogElement) || dialog.open) return;
      if (button.dataset.dialogMode === 'nonmodal') dialog.show();
      else dialog.showModal();
    });
  });

  document.addEventListener('pointerdown', function (event) {
    document.querySelectorAll('dialog.dialog-nonmodal[open]').forEach(
      function (dialog) {
        if (!dialog.contains(event.target)) dialog.close('dismiss');
      }
    );
  });

})();
