import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { getVerifiedSenderHost, isExtensionPage, handleMessage } from '../background.js';
import { saveCredential, _resetKeyCache } from '../storage.js';
import { installFakeChromeStorage } from './helpers/fake-chrome.js';

const EXT_ID = 'test-extension-id';
const EXT_ORIGIN = `chrome-extension://${EXT_ID}/`;

function sendMsg(message, sender) {
  return new Promise((resolve) => {
    const isAsync = handleMessage(message, sender, resolve);
    if (!isAsync) resolve(undefined);
  });
}

let prevChrome;

beforeEach(() => {
  _resetKeyCache();
  prevChrome = globalThis.chrome;
  installFakeChromeStorage({
    runtime: {
      id: EXT_ID,
      getURL: (path = '') => EXT_ORIGIN + path
    }
  });
});

afterEach(() => {
  globalThis.chrome = prevChrome;
});

test('getVerifiedSenderHost enforces top-level frame and HTTPS or localhost HTTP', () => {
  assert.equal(getVerifiedSenderHost({ url: 'https://example.com/login', frameId: 0 }), 'example.com');
  assert.equal(getVerifiedSenderHost({ url: 'http://localhost:3000/login', frameId: 0 }), 'localhost');
  assert.equal(getVerifiedSenderHost({ url: 'http://127.0.0.1:8080/', frameId: 0 }), '127.0.0.1');
  assert.equal(getVerifiedSenderHost({ url: 'http://[::1]:8080/', frameId: 0 }), '[::1]');

  // Reject plain HTTP on non-localhost
  assert.equal(getVerifiedSenderHost({ url: 'http://example.com/login', frameId: 0 }), null);
  // Reject subframes and missing frameId
  assert.equal(getVerifiedSenderHost({ url: 'https://example.com/login', frameId: 1 }), null);
  assert.equal(getVerifiedSenderHost({ url: 'https://example.com/login' }), null);
  // Reject tab.url fallback when sender.url is missing
  assert.equal(getVerifiedSenderHost({ frameId: 0, tab: { url: 'https://example.com/' } }), null);
  // Reject non-web schemes
  assert.equal(getVerifiedSenderHost({ url: `${EXT_ORIGIN}popup.html`, frameId: 0 }), null);
  assert.equal(getVerifiedSenderHost({ url: 'file:///tmp/login.html', frameId: 0 }), null);
});

test('isExtensionPage verifies runtime id and sender.url without tab fallback', () => {
  assert.equal(isExtensionPage({ id: EXT_ID, url: `${EXT_ORIGIN}popup.html` }), true);
  assert.equal(isExtensionPage({ id: 'other-ext', url: `${EXT_ORIGIN}popup.html` }), false);
  assert.equal(isExtensionPage({ id: EXT_ID, url: 'https://example.com' }), false);
  assert.equal(isExtensionPage({ id: EXT_ID, tab: { url: `${EXT_ORIGIN}popup.html` } }), false);
});

test('GET_AUTOFILL rejects plain HTTP and subframes, returns matching credential without totpSecret', async () => {
  await saveCredential({
    hostname: 'example.com',
    username: 'alice',
    password: 'secret-password',
    totpSecret: 'JBSWY3DPEHPK3PXP'
  });

  const httpBlocked = await sendMsg(
    { action: 'GET_AUTOFILL' },
    { url: 'http://example.com/login', frameId: 0 }
  );
  assert.equal(httpBlocked.success, false);

  const iframeBlocked = await sendMsg(
    { action: 'GET_AUTOFILL' },
    { url: 'https://example.com/login', frameId: 2 }
  );
  assert.equal(iframeBlocked.success, false);

  const ok = await sendMsg(
    { action: 'GET_AUTOFILL' },
    { url: 'https://example.com/login', frameId: 0 }
  );
  assert.equal(ok.success, true);
  assert.equal(ok.credential.username, 'alice');
  assert.equal(ok.credential.password, 'secret-password');
  assert.match(ok.credential.totpCode, /^[0-9]{6}$/);
  assert.equal('totpSecret' in ok.credential, false);
});

test('Vault management actions reject web senders and REFRESH_TOTP omits passwords', async () => {
  const webSender = { id: EXT_ID, url: 'https://evil.com/', frameId: 0 };
  const extSender = { id: EXT_ID, url: `${EXT_ORIGIN}popup.html` };

  for (const action of ['LIST_ALL', 'REFRESH_TOTP', 'ADD_CREDENTIAL', 'DELETE_CREDENTIAL']) {
    const res = await sendMsg({ action, payload: { hostname: 'a.com', password: 'pw', id: '1' } }, webSender);
    assert.equal(res.success, false);
    assert.equal(res.error, 'Unauthorized sender');
  }

  const added = await sendMsg(
    { action: 'ADD_CREDENTIAL', payload: { hostname: 'a.com', username: 'u', password: 'pw', totpSecret: 'JBSWY3DPEHPK3PXP' } },
    extSender
  );
  assert.equal(added.success, true);

  const refreshed = await sendMsg({ action: 'REFRESH_TOTP' }, extSender);
  assert.equal(refreshed.success, true);
  assert.equal(refreshed.codes.length, 1);
  assert.match(refreshed.codes[0].totpCode, /^[0-9]{6}$/);
  assert.equal('password' in refreshed.codes[0], false);
  assert.equal('totpSecret' in refreshed.codes[0], false);

  const deleted = await sendMsg({ action: 'DELETE_CREDENTIAL', payload: { id: added.entry.id } }, extSender);
  assert.equal(deleted.success, true);
});
