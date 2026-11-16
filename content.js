/**
 * FastPass - Zero-Click Autofill Content Script
 * Detects login & 2FA fields in top-level HTTPS/localhost pages and autofills.
 */

(function () {
  'use strict';

  // Top-level HTTPS or localhost only (prevent iframe harvesting & plain-HTTP leaks).
  if (window.self !== window.top) return;
  const isLocal = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);
  if (location.protocol !== 'https:' && !isLocal) return;

  let cachedCredential = null;
  let totpFetchedAt = 0;
  let totpRefreshPending = false;

  const OTP_SELECTOR = [
    'input[autocomplete="one-time-code"]',
    'input[name*="totp" i]',
    'input[name*="otp" i]',
    'input[name*="2fa" i]',
    'input[name*="mfa" i]',
    'input[name*="two_factor" i]',
    'input[name*="twofactor" i]',
    'input[name*="verification_code" i]',
    'input[name*="security_code" i]',
    'input[id*="totp" i]',
    'input[id*="otp" i]',
    'input[id*="2fa" i]',
    'input[id*="mfa" i]',
    'input[id*="verification" i]',
    'input[aria-label*="totp" i]',
    'input[aria-label*="otp" i]',
    'input[aria-label*="authenticator" i]',
    'input[aria-label*="verification" i]',
    'input[placeholder*="totp" i]',
    'input[placeholder*="authenticator" i]',
    'input[placeholder*="6-digit" i]',
    'input[placeholder*="verification code" i]',
    'input[placeholder*="security code" i]',
    'input[inputmode="numeric"][maxlength="6"]'
  ];

  const USERNAME_SELECTOR = [
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[type="email"]',
    'input[name*="username" i]',
    'input[name*="login" i]',
    'input[name*="user" i]',
    'input[name*="email" i]',
    'input[id*="username" i]',
    'input[id*="login" i]',
    'input[id*="email" i]'
  ];

  const FILLABLE_SELECTOR = ['input[type="password"]', ...OTP_SELECTOR, ...USERNAME_SELECTOR].join(', ');

  // Keep state in this isolated world rather than DOM attributes readable by page JS.
  const filledValues = new WeakMap();
  const userEdited = new WeakSet();
  let observer = null;
  let fillDebounceTimer = null;

  function isVisible(el) {
    if (!el || !el.isConnected) return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function isOtpField(input) {
    return !!input && input.matches(OTP_SELECTOR.join(','));
  }

  function isFillableUsername(input) {
    return isVisible(input) && !input.disabled && !input.readOnly && !isOtpField(input);
  }

  function fillInput(input, value) {
    if (!input || !value) return false;
    if (filledValues.get(input) === value || userEdited.has(input)) return false;

    const firstFill = !filledValues.has(input);

    // Use native value setter so React/Vue controlled inputs see the change.
    const descriptor =
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), 'value') ||
      (window.HTMLInputElement && Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value'));
    if (descriptor?.set) descriptor.set.call(input, value);
    else input.value = value;

    filledValues.set(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
    input.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));

    // Track only real user keystrokes (isTrusted) once per input.
    if (firstFill) {
      input.addEventListener('input', (e) => {
        if (e.isTrusted) userEdited.add(input);
      });
    }
    return true;
  }

  function findUsernameInput(passwordInput) {
    const usernameQuery = USERNAME_SELECTOR.join(',');
    const form = passwordInput.form;

    if (form) {
      const formInputs = Array.from(form.querySelectorAll(
        'input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])'
      ));
      const prioritized = formInputs.find(input => isFillableUsername(input) && input.matches(usernameQuery));
      if (prioritized) return prioritized;

      const formElements = Array.from(form.elements);
      const passIdx = formElements.indexOf(passwordInput);
      const preceding = formInputs.filter(
        input => isFillableUsername(input) && formElements.indexOf(input) < passIdx
      );
      if (preceding.length > 0) return preceding[preceding.length - 1];
    }

    return Array.from(document.querySelectorAll(usernameQuery)).find(isFillableUsername) || null;
  }

  function findTotpInput(excluded = []) {
    for (const el of document.querySelectorAll(OTP_SELECTOR.join(','))) {
      if (excluded.includes(el)) continue;
      if (el.type === 'password' || el.type === 'hidden' || el.disabled || el.readOnly) continue;
      if (isVisible(el)) return el;
    }
    return null;
  }

  function isTotpStale() {
    if (!totpFetchedAt) return true;
    return Math.floor(Date.now() / 30000) !== Math.floor(totpFetchedAt / 30000);
  }

  function executeAutofill() {
    if (!cachedCredential) return;
    if (!document.querySelector(FILLABLE_SELECTOR)) return;

    if (cachedCredential.totpCode && isTotpStale()) {
      if (!totpRefreshPending) {
        totpRefreshPending = true;
        requestCredential(executeAutofill);
      }
      return;
    }

    const { username, password, totpCode } = cachedCredential;
    const filled = [];

    const passwordInputs = Array.from(
      document.querySelectorAll('input[type="password"]:not([disabled]):not([readonly])')
    ).filter(input => isVisible(input) && (input.getAttribute('autocomplete') || '').toLowerCase() !== 'new-password');

    if (passwordInputs.length > 0) {
      const passInput = passwordInputs[0];
      if (password) {
        fillInput(passInput, password);
        filled.push(passInput);
      }
      if (username) {
        const userInput = findUsernameInput(passInput);
        if (userInput && !filled.includes(userInput)) {
          fillInput(userInput, username);
          filled.push(userInput);
        }
      }
    } else if (username) {
      const userInput = Array.from(document.querySelectorAll(USERNAME_SELECTOR.join(',')))
        .filter(isFillableUsername)[0];
      if (userInput) {
        fillInput(userInput, username);
        filled.push(userInput);
      }
    }

    if (totpCode) {
      const totpInput = findTotpInput(filled);
      if (totpInput) fillInput(totpInput, totpCode);
    }
  }

  function scheduleAutofill() {
    clearTimeout(fillDebounceTimer);
    fillDebounceTimer = setTimeout(executeAutofill, 150);
  }

  function requestCredential(onReady) {
    try {
      chrome.runtime.sendMessage({ action: 'GET_AUTOFILL' }, (response) => {
        totpRefreshPending = false;
        if (chrome.runtime.lastError || !response?.success || !response.credential) return;
        cachedCredential = response.credential;
        totpFetchedAt = Date.now();
        if (onReady) onReady();
      });
    } catch {
      // Extension context invalidated.
    }
  }

  function init() {
    requestCredential(() => {
      executeAutofill();

      if (!observer && document.body) {
        observer = new MutationObserver(scheduleAutofill);
        // Watch class/style/hidden so pre-rendered 2FA panels revealed later still autofill.
        observer.observe(document.body, {
          childList: true,
          subtree: true,
          attributes: true,
          attributeFilter: ['style', 'class', 'hidden']
        });

        document.addEventListener('focusin', (e) => {
          if (e.target?.tagName === 'INPUT') scheduleAutofill();
        }, true);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
