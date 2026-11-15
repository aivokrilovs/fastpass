import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  saveCredential,
  deleteCredential,
  getCredentials,
  _resetKeyCache
} from '../storage.js';
import { generateTOTP, decrypt } from '../crypto.js';
import { installFakeChromeStorage } from './helpers/fake-chrome.js';

beforeEach(() => {
  _resetKeyCache();
  installFakeChromeStorage();
});

test('Full lifecycle: Add, Autofill, Dynamic TOTP, Spoof Defense, Delete', async () => {
  const totpSecret = 'JBSWY3DPEHPK3PXP';
  const targetHost = '*.github.com, github.com';

  // 1. Popup adds credential
  const saved = await saveCredential({
    hostname: targetHost,
    username: 'alice@example.com',
    password: 'P@ssword123456!',
    totpSecret: 'jbsw y3dp ehpk 3pxp'
  });

  assert.ok(saved.id);
  assert.equal(saved.hostname, '*.github.com, github.com');
  assert.equal(saved.hasTotp, true);

  // 2. Content script simulation on legitimate site: https://github.com/login
  const senderLegit = { url: 'https://github.com/login' };
  const legitHost = new URL(senderLegit.url).hostname;
  const matches = await getCredentials(legitHost);

  assert.equal(matches.length, 1);
  const cred = matches[0];
  assert.equal(cred.username, 'alice@example.com');
  assert.equal(cred.password, 'P@ssword123456!');

  // Compute TOTP code (same as background worker does)
  const code = await generateTOTP(cred.totpSecret);
  assert.match(code, /^[0-9]{6}$/);

  // 3. Subdomain autofill test: https://login.github.com/session
  const senderSubdomain = { url: 'https://login.github.com/session' };
  const subMatches = await getCredentials(new URL(senderSubdomain.url).hostname);
  assert.equal(subMatches.length, 1);
  assert.equal(subMatches[0].username, 'alice@example.com');

  // 4. Malicious website simulation: https://evil.com/phishing.html
  const senderEvil = { url: 'https://evil.com/phishing.html' };
  const evilHost = new URL(senderEvil.url).hostname;
  const evilMatches = await getCredentials(evilHost);
  assert.equal(evilMatches.length, 0, 'Evil site must NOT receive credentials');

  // 5. Lookalike / spoofing domain simulation: https://github.com.attacker.com
  const senderSpoof = { url: 'https://github.com.attacker.com/login' };
  const spoofHost = new URL(senderSpoof.url).hostname;
  const spoofMatches = await getCredentials(spoofHost);
  assert.equal(spoofMatches.length, 0, 'Spoof domain must NOT receive credentials');

  // 6. Delete credential
  const delSuccess = await deleteCredential(saved.id);
  assert.equal(delSuccess, true);

  const afterDeleteMatches = await getCredentials(legitHost);
  assert.equal(afterDeleteMatches.length, 0);
});
