import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Behavioural test for the autofill path in content.js. The script is a browser
// IIFE, so it is executed in a vm sandbox against a hand-rolled fake DOM.
//
// The fake DOM implements only what content.js touches: the attribute-selector
// grammar it actually uses (`[attr]`, `[attr="v"]`, `[attr*="v" i]`,
// `:not([attr])`), and a synchronous dispatchEvent that honours isTrusted.
//
// The regression these tests pin down: fillInput dispatched its own synthetic
// `input` event, which a listener left over from the *previous* fill consumed.
// That marked the field as user-edited forever, so a 2FA code box stopped
// refreshing after its second 30s window.
const source = readFileSync(new URL('../content.js', import.meta.url), 'utf8');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// --- minimal selector engine ------------------------------------------------

function matchCompound(el, compound) {
  const tag = compound.match(/^[a-zA-Z][a-zA-Z0-9]*/);
  if (tag && tag[0].toLowerCase() !== String(el.tagName).toLowerCase()) return false;

  const attributes = /:not\(\[([^\]]+)\]\)|\[([^\]]+)\]/g;
  const rest = compound.slice(tag ? tag[0].length : 0);
  let part;
  while ((part = attributes.exec(rest)) !== null) {
    const negated = part[1] !== undefined;
    const parsed = (part[1] ?? part[2]).match(/^([a-zA-Z-]+)\s*(?:([*^$]?=)\s*"([^"]*)"\s*(i)?)?$/);
    if (!parsed) return false;
    const [, name, op, value, caseInsensitive] = parsed;

    const actual = el.getAttribute(name);
    let hit;
    if (op === undefined) {
      hit = actual !== null && actual !== '';
    } else if (caseInsensitive) {
      hit = op === '*'
        ? String(actual ?? '').toLowerCase().includes(value.toLowerCase())
        : String(actual ?? '').toLowerCase() === value.toLowerCase();
    } else {
      hit = op === '*' ? String(actual ?? '').includes(value) : String(actual ?? '') === value;
    }
    if (negated ? hit : !hit) return false;
  }
  return true;
}

function matchesSelector(el, selector) {
  return selector.split(',').some((part) => matchCompound(el, part.trim()));
}

// --- fake DOM ---------------------------------------------------------------

class FakeEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.isTrusted = false; // events built in JS are never trusted
    Object.assign(this, init);
  }
}

class FakeMutationObserver {
  static instances = [];
  constructor(callback) {
    this.callback = callback;
    FakeMutationObserver.instances.push(this);
  }
  observe() {}
  disconnect() {}
  trigger() {
    this.callback([], this);
  }
}

function createFakePage({ credential = null } = {}) {
  const inputs = [];
  let nextCredential = credential;

  // content.js reads the TOTP window through Date.now(); the test drives it.
  let now = 1_000_000_000_000;
  class FakeDate extends Date {
    static now() {
      return now;
    }
  }

  function createInput({ type = 'text', attrs = {} } = {}) {
    const el = {
      tagName: 'INPUT',
      type,
      value: '',
      disabled: false,
      readOnly: false,
      form: null,
      isConnected: true,
      _attrs: { type, ...attrs },
      _listeners: new Map(),
      getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this._attrs, name) ? this._attrs[name] : null;
      },
      matches: (selector) => matchesSelector(el, selector),
      getBoundingClientRect: () => ({ width: 120, height: 24, top: 0, left: 0 }),
      addEventListener(type, fn, options) {
        const list = this._listeners.get(type) || [];
        list.push({ fn, once: !!(options && options.once) });
        this._listeners.set(type, list);
      },
      removeEventListener(type, fn) {
        this._listeners.set(type, (this._listeners.get(type) || []).filter((l) => l.fn !== fn));
      },
      dispatchEvent(event) {
        for (const listener of [...(this._listeners.get(event.type) || [])]) {
          listener.fn.call(this, event);
          if (listener.once) this.removeEventListener(event.type, listener.fn);
        }
        return true;
      }
    };
    inputs.push(el);
    return el;
  }

  const document = {
    readyState: 'complete',
    body: { nodeType: 1 },
    querySelector: (selector) => document.querySelectorAll(selector)[0] || null,
    querySelectorAll: (selector) => inputs.filter((el) => matchesSelector(el, selector)),
    addEventListener() {},
    createElement: () => ({})
  };

  const window = {
    getComputedStyle: () => ({ display: 'block', visibility: 'visible', opacity: '1' })
  };
  window.self = window;
  window.top = window;

  const chrome = {
    runtime: {
      lastError: undefined,
      sendMessage(message, callback) {
        if (message.action === 'GET_AUTOFILL') {
          queueMicrotask(() => callback({ success: true, credential: nextCredential }));
        }
      }
    }
  };

  const sandbox = vm.createContext({
    window,
    document,
    chrome,
    location: { protocol: 'https:', hostname: 'example.com' },
    MutationObserver: FakeMutationObserver,
    Event: FakeEvent,
    Date: FakeDate,
    setTimeout,
    clearTimeout,
    console,
    queueMicrotask
  });

  // Runs init() immediately (readyState is already 'complete'). Must be called
  // after the test has created its inputs.
  function start() {
    vm.runInContext(source, sandbox);
  }

  return {
    createInput,
    start,
    setCredential(next) {
      nextCredential = next;
    },
    advanceClock(ms) {
      now += ms;
    },
    // Let the sendMessage round-trip and the initial autofill land.
    settle: () => delay(20),
    // Simulate a DOM mutation (the 30s TOTP rollover path) and let the
    // 150ms debounce in content.js fire.
    async autofill() {
      FakeMutationObserver.instances.at(-1).trigger();
      await delay(250);
    }
  };
}

// --- tests ------------------------------------------------------------------

test('a 2FA field keeps refreshing across TOTP windows (regression)', async () => {
  // The input must exist before the script runs: init() autofills immediately.
  const page = createFakePage({ credential: { username: '', password: '', totpCode: '111111' } });
  const input = page.createInput({ type: 'text', attrs: { autocomplete: 'one-time-code' } });

  page.start();
  await page.settle();
  assert.equal(input.value, '111111');

  // Next 30s window: content.js sees a stale code, re-asks the worker and
  // types the new one into the same field.
  page.advanceClock(30_000);
  page.setCredential({ username: '', password: '', totpCode: '222222' });
  await page.autofill();
  assert.equal(input.value, '222222');

  // This third window is the one that used to be swallowed: the previous
  // fill's `once` listener consumed this fill's own synthetic input event.
  page.advanceClock(30_000);
  page.setCredential({ username: '', password: '', totpCode: '333333' });
  await page.autofill();
  assert.equal(input.value, '333333');
});

test('a real keystroke is never overwritten by autofill', async () => {
  const page = createFakePage({ credential: { username: '', password: '', totpCode: '111111' } });
  const input = page.createInput({ type: 'text', attrs: { autocomplete: 'one-time-code' } });

  page.start();
  await page.settle();
  assert.equal(input.value, '111111');

  // The user types: trusted event, unlike the synthetic ones from fillInput.
  input.value = 'typed-by-user';
  input.dispatchEvent({ type: 'input', isTrusted: true });

  // Next window brings a fresh code, which must not replace real typing.
  page.advanceClock(30_000);
  page.setCredential({ username: '', password: '', totpCode: '222222' });
  await page.autofill();
  assert.equal(input.value, 'typed-by-user');
});
