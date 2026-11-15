/**
 * FastPass - Zero-Click Autofill Content Script
 * Injected in isolated world on matching web pages.
 * Detects login & 2FA fields and autofills credentials without user clicks.
 */

(function () {
  'use strict';

  // Security: only run in top-level window (prevent iframe credential harvesting)
  if (window.self !== window.top) {
    return;
  }

  // Security: never type a password into a page served over plain HTTP
  // (localhost excepted). Anyone on the network could read it.
  // Keep in sync with LOCAL_HOST_RE in background.js and the `matches` list in
  // manifest.json: content scripts are not modules, so this cannot be shared.
  const isLocal = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);
  if (location.protocol !== 'https:' && !isLocal) {
    return;
  }

  let cachedCredential = null;
  let totpFetchedAt = 0;
  let totpRefreshPending = false;

  // Inputs that can hold a 2FA / one-time code.
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

  // Inputs that can hold a username / email (step-1 login pages).
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

  // Every field this script can fill. The cheap "is there anything to do
  // here?" gate uses this, so it can never be narrower than the fillers —
  // a 2FA-only page has no password field at all.
  const FILLABLE_SELECTOR = ['input[type="password"]', ...OTP_SELECTOR, ...USERNAME_SELECTOR].join(', ');

  // Security: filled and user-edited state stays in this isolated world, never on the DOM.
  // Any data-* attribute would be readable by the page's own JavaScript.
  const filledValues = new WeakMap();
  const userEdited = new WeakSet();
  let observer = null;
  let fillDebounceTimer = null;

  // Check if an element is visible to the user
  function isVisible(el) {
    if (!el || !el.isConnected) return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  // Check if an input looks like a 2FA / OTP field (to avoid picking it as username)
  function isOtpField(input) {
    return !!input && input.matches(OTP_SELECTOR.join(','));
  }

  function isFillableUsername(input) {
    return isVisible(input) && !input.disabled && !input.readOnly && !isOtpField(input);
  }

  // Safely fill an input field across standard DOM, React, Angular, and Vue
  function fillInput(input, value) {
    if (!input || !value) return false;
    if (filledValues.get(input) === value) return false; // Already filled with this value
    if (userEdited.has(input)) return false; // Do not overwrite user typing

    // Use native prototype setter to bypass React 16+ virtual DOM property hijacking
    const prototype = Object.getPrototypeOf(input);
    let descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
    if (!descriptor && window.HTMLInputElement) {
      descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    }
    if (descriptor && descriptor.set) {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }

    filledValues.set(input, value);

    // Dispatch synthetic events so framework state managers (React, Vue, form validation) register the value
    input.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
    input.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));

    // If user starts typing manually, respect their input and do not re-overwrite.
    // Only a real keystroke counts: the events dispatched just above are
    // synthetic (isTrusted === false), and a `once` listener would be consumed
    // by one of them before the user ever gets a chance to type.
    input.addEventListener('input', (e) => {
      if (e.isTrusted) userEdited.add(input);
    });

    return true;
  }

  // Find the username input associated with a password input
  function findUsernameInput(passwordInput) {
    const usernameSelector = USERNAME_SELECTOR.join(',');
    const form = passwordInput.form;

    // 1. Search within the same form if available
    if (form) {
      const formInputs = Array.from(form.querySelectorAll('input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])'));

      const prioritized = formInputs.find(input => isFillableUsername(input) && input.matches(usernameSelector));
      if (prioritized) return prioritized;

      // Fallback: pick the closest visible text input before the password input
      const visibleInputs = formInputs.filter(isFillableUsername);
      const passIdx = Array.from(form.elements).indexOf(passwordInput);
      const preceding = visibleInputs.filter(input => Array.from(form.elements).indexOf(input) < passIdx);
      if (preceding.length > 0) {
        return preceding[preceding.length - 1];
      }
    }

    // 2. Fallback to any visible username/email input in the document
    return Array.from(document.querySelectorAll(usernameSelector)).find(isFillableUsername) || null;
  }

  // Find TOTP / 2FA verification code input
  function findTotpInput(excludedInputs = []) {
    const elements = Array.from(document.querySelectorAll(OTP_SELECTOR.join(',')));
    for (const el of elements) {
      if (excludedInputs.includes(el)) continue;
      if (el.type === 'password' || el.type === 'hidden' || el.disabled || el.readOnly) continue;
      if (isVisible(el)) {
        return el;
      }
    }
    return null;
  }

  // Main autofill execution
  function executeAutofill() {
    if (!cachedCredential) return;
    // Cheap early exit: most mutations on most pages have no login field at all.
    if (!document.querySelector(FILLABLE_SELECTOR)) return;

    // TOTP codes expire every 30s. Refresh from the service worker (which
    // re-verifies the sender host) before filling a stale one.
    if (cachedCredential.totpCode && isTotpStale()) {
      if (!totpRefreshPending) {
        totpRefreshPending = true;
        requestCredential(executeAutofill);
      }
      return;
    }

    const { username, password, totpCode } = cachedCredential;
    const filledElements = [];

    // 1. Password fields (ignore registration / change-password 'new-password' fields)
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]:not([disabled]):not([readonly])'))
      .filter(input => {
        if (!isVisible(input)) return false;
        const auto = (input.getAttribute('autocomplete') || '').toLowerCase();
        return auto !== 'new-password';
      });

    if (passwordInputs.length > 0) {
      // Only fill primary password field to avoid overwriting confirmation fields
      const passInput = passwordInputs[0];
      if (password) {
        fillInput(passInput, password);
        filledElements.push(passInput);
      }

      // Associated username field
      if (username) {
        const userInput = findUsernameInput(passInput);
        if (userInput && !filledElements.includes(userInput)) {
          fillInput(userInput, username);
          filledElements.push(userInput);
        }
      }
    } else if (username) {
      // Step-1 username-only login page
      const usernameInputs = Array.from(document.querySelectorAll(USERNAME_SELECTOR.join(',')))
        .filter(isFillableUsername);
      if (usernameInputs.length > 0) {
        fillInput(usernameInputs[0], username);
        filledElements.push(usernameInputs[0]);
      }
    }

    // 2. TOTP / 2FA field (if 2FA code is available)
    if (totpCode) {
      const totpInput = findTotpInput(filledElements);
      if (totpInput) {
        fillInput(totpInput, totpCode);
      }
    }
  }

  // Debounced autofill trigger for DOM changes (SPAs, dynamic login modals)
  function scheduleAutofill() {
    if (fillDebounceTimer) clearTimeout(fillDebounceTimer);
    fillDebounceTimer = setTimeout(() => {
      executeAutofill();
    }, 150);
  }

  // A cached TOTP code is only valid for its 30s window
  function isTotpStale() {
    if (!totpFetchedAt) return true;
    return Math.floor(Date.now() / 30000) !== Math.floor(totpFetchedAt / 30000);
  }

  // Ask the service worker for the matching credential. The worker re-checks
  // the sender hostname every time, so this is not a new trust path.
  function requestCredential(onReady) {
    try {
      chrome.runtime.sendMessage({ action: 'GET_AUTOFILL' }, (response) => {
        totpRefreshPending = false;
        if (chrome.runtime.lastError) {
          // Extension might be reloading or context invalidated
          return;
        }
        if (response && response.success && response.credential) {
          cachedCredential = response.credential;
          totpFetchedAt = Date.now();
          if (onReady) onReady();
        }
      });
    } catch (e) {
      // Context invalidated or extension unloaded
    }
  }

  // Initialize: request matching credentials from service worker
  function init() {
    requestCredential(() => {
      // Autofill immediately
      executeAutofill();

      // Observe subsequent DOM mutations and modal visibility toggles (SPAs, React modals)
      if (!observer && document.body) {
        observer = new MutationObserver(() => {
          scheduleAutofill();
        });
        // Attribute watching is needed because 2FA steps are often already in
        // the DOM and revealed by a class/style change. The FILLABLE_SELECTOR
        // gate above keeps each of those events to a single cheap query.
        observer.observe(document.body, {
          childList: true,
          subtree: true,
          attributes: true,
          attributeFilter: ['style', 'class', 'hidden']
        });

        // Trigger autofill if a user focuses into an unpopulated input in a modal
        document.addEventListener('focusin', (e) => {
          if (e.target && e.target.tagName === 'INPUT') {
            scheduleAutofill();
          }
        }, true);
      }
    });
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
