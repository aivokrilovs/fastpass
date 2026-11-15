import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeHostname,
  matchHostname,
  saveCredential,
  deleteCredential,
  reorderCredential,
  getCredentials,
  getMasterKey,
  _resetKeyCache
} from '../storage.js';
import { installFakeChromeStorage } from './helpers/fake-chrome.js';

let fakeLocal;

beforeEach(() => {
  _resetKeyCache();
  fakeLocal = installFakeChromeStorage();
});

test('Hostname normalization', () => {
  assert.equal(normalizeHostname('https://github.com/login?return_to=foo'), 'github.com');
  assert.equal(normalizeHostname('http://www.example.com/index.html'), 'example.com');
  assert.equal(normalizeHostname('SUB.DOMAIN.EXAMPLE.COM:8080/path'), 'sub.domain.example.com');
  assert.equal(normalizeHostname('localhost:3000'), 'localhost');
  assert.equal(normalizeHostname(''), '');
  // Multiple domains and globs
  assert.equal(normalizeHostname('*.example.com, example.co.uk'), '*.example.com, example.co.uk');
  assert.equal(normalizeHostname('https://*.example.com:8080, http://www.example.co.uk/path'), '*.example.com, example.co.uk');
});

test('Hostname matching security', () => {
  // Exact match without wildcard
  assert.equal(matchHostname('example.com', 'example.com'), true);
  assert.equal(matchHostname('example.com', 'www.example.com'), true);
  assert.equal(matchHostname('www.example.com', 'example.com'), true);
  // Without explicit blob, subdomains do NOT match
  assert.equal(matchHostname('example.com', 'login.example.com'), false);

  // Explicit blobbing: *.example.com matches root and all subdomains
  assert.equal(matchHostname('*.example.com', 'example.com'), true);
  assert.equal(matchHostname('*.example.com', 'www.example.com'), true);
  assert.equal(matchHostname('*.example.com', 'login.example.com'), true);
  assert.equal(matchHostname('*.example.com', 'auth.corp.example.com'), true);

  // Spoofing attempts MUST be rejected
  assert.equal(matchHostname('*.example.com', 'badexample.com'), false);
  assert.equal(matchHostname('*.example.com', 'example.com.attacker.com'), false);
  assert.equal(matchHostname('*.example.com', 'example.com-evil.org'), false);

  // Multiple domains with explicit blobbing (e.g. *.example.com,example.co.uk)
  const multiPattern = '*.example.com,example.co.uk';
  assert.equal(matchHostname(multiPattern, 'login.example.com'), true);
  assert.equal(matchHostname(multiPattern, 'example.com'), true);
  assert.equal(matchHostname(multiPattern, 'example.co.uk'), true);
  assert.equal(matchHostname(multiPattern, 'www.example.co.uk'), true);
  assert.equal(matchHostname(multiPattern, 'login.example.co.uk'), false); // no wildcard on example.co.uk
  assert.equal(matchHostname(multiPattern, 'evil.com'), false);

  // Custom wildcard globs stay within a single DNS label
  assert.equal(matchHostname('app-*.internal', 'app-dev.internal'), true);
  assert.equal(matchHostname('app-*.internal', 'app-prod.internal'), true);
  assert.equal(matchHostname('app-*.internal', 'app-1.evil.internal'), false);
  assert.equal(matchHostname('app-*.internal', 'other.internal'), false);

  // Malformed or overly broad wildcards must not crash or match unrelated domains
  assert.equal(matchHostname('*.**', 'example.com'), false);
  assert.equal(matchHostname('*', 'example.com'), false);
  assert.equal(matchHostname('*.ab*.com', 'a.com'), false);

  // Specific subdomain saved should not match root or sister domain
  assert.equal(matchHostname('auth.example.com', 'example.com'), false);
  assert.equal(matchHostname('auth.example.com', 'billing.example.com'), false);

  // Bare TLDs must never match all domains
  assert.equal(matchHostname('com', 'google.com'), false);
  assert.equal(matchHostname('org', 'wikipedia.org'), false);

  // Single label domains require exact match unless blobbed
  assert.equal(matchHostname('localhost', 'localhost'), true);
  assert.equal(matchHostname('localhost', 'app.localhost'), false);
  assert.equal(matchHostname('*.localhost', 'app.localhost'), true);
});

test('Save, retrieve, and verify encrypted at rest', async () => {
  const plainPass = 'MyP@ssw0rd!#$';
  const totpSecret = 'JBSWY3DPEHPK3PXP';

  const entry = await saveCredential({
    hostname: 'https://login.github.com',
    username: 'octocat',
    password: plainPass,
    totpSecret: 'jbsw y3dp ehpk 3pxp' // test space normalization
  });

  assert.ok(entry.id);
  assert.equal(entry.hostname, 'login.github.com');
  assert.equal(entry.username, 'octocat');
  assert.equal(entry.hasTotp, true);

  // Retrieve matching credentials for github.com
  const matches = await getCredentials('login.github.com');
  assert.equal(matches.length, 1);
  assert.equal(matches[0].password, plainPass);
  assert.equal(matches[0].totpSecret, totpSecret);

  // Non-matching host retrieves empty array
  const noMatches = await getCredentials('gitlab.com');
  assert.equal(noMatches.length, 0);
});

test('Save validation requires at least 1 of username, password, or TOTP secret', async () => {
  await assert.rejects(
    async () => await saveCredential({ hostname: '', password: '123' }),
    /Valid hostname is required/
  );

  await assert.rejects(
    async () => await saveCredential({ hostname: 'example.com' }),
    /At least one of username, password, or TOTP secret is required/
  );

  await assert.rejects(
    async () => await saveCredential({
      hostname: 'example.com',
      username: '  ',
      password: '',
      totpSecret: ''
    }),
    /At least one of username, password, or TOTP secret is required/
  );

  await assert.rejects(
    async () => await saveCredential({
      hostname: 'example.com',
      password: '123',
      totpSecret: 'INVALID-BASE32-888'
    }),
    /Invalid TOTP Base32 secret/
  );

  // Username only succeeds
  const userOnly = await saveCredential({ hostname: 'user-only.com', username: 'alice' });
  assert.equal(userOnly.username, 'alice');
  assert.equal(userOnly.hasPassword, false);
  assert.equal(userOnly.hasTotp, false);

  // Password only succeeds
  const passOnly = await saveCredential({ hostname: 'pass-only.com', password: 'secret-pass' });
  assert.equal(passOnly.username, '');
  assert.equal(passOnly.hasPassword, true);
  assert.equal(passOnly.hasTotp, false);

  // TOTP only succeeds
  const totpOnly = await saveCredential({ hostname: 'totp-only.com', totpSecret: 'JBSWY3DPEHPK3PXP' });
  assert.equal(totpOnly.username, '');
  assert.equal(totpOnly.hasPassword, false);
  assert.equal(totpOnly.hasTotp, true);
});

test('Delete credential', async () => {
  const saved = await saveCredential({
    hostname: 'example.com',
    username: 'alice',
    password: 'password123'
  });

  const listBefore = await getCredentials();
  assert.equal(listBefore.length, 1);

  const deleted = await deleteCredential(saved.id);
  assert.equal(deleted, true);

  const listAfter = await getCredentials();
  assert.equal(listAfter.length, 0);

  // Deleting again returns false
  const deleteAgain = await deleteCredential(saved.id);
  assert.equal(deleteAgain, false);
});

test('whole-vault read returns every entry, freshest last inserted first in result', async () => {
  await saveCredential({
    hostname: 'site1.com',
    username: 'user1',
    password: 'superSecretPassword1'
  });
  await saveCredential({
    hostname: 'site2.com',
    username: 'user2',
    password: 'superSecretPassword2'
  });

  const list = await getCredentials();
  assert.equal(list.length, 2);
  assert.deepEqual(list.map(c => c.hostname).sort(), ['site1.com', 'site2.com']);

  // An empty hostname must not mean "give me everything"
  assert.deepEqual(await getCredentials(''), []);
});

test('Key loss with a non-empty vault fails loudly instead of minting a new key', async () => {
  await saveCredential({
    hostname: 'site1.com',
    username: 'user1',
    password: 'superSecretPassword1'
  });

  // Simulate losing the key (IndexedDB cleared) while the vault survives
  _resetKeyCache();

  await assert.rejects(async () => await getCredentials(), /Vault key missing/);
  await assert.rejects(
    async () => await saveCredential({ hostname: 'site2.com', password: 'x' }),
    /Vault key missing/
  );
});

test('Saving existing username and hostname updates in place', async () => {
  await saveCredential({
    hostname: 'myapp.com',
    username: 'admin',
    password: 'old-password-123'
  });

  const list1 = await getCredentials();
  assert.equal(list1.length, 1);

  // Update password for same username and host
  await saveCredential({
    hostname: 'myapp.com',
    username: 'admin',
    password: 'new-password-456'
  });

  const list2 = await getCredentials();
  assert.equal(list2.length, 1, 'Should update existing entry rather than duplicating');

  const matches = await getCredentials('myapp.com');
  assert.equal(matches.length, 1);
  assert.equal(matches[0].password, 'new-password-456');
});

test('Concurrent saves do not lose an entry', async () => {
  await Promise.all([
    saveCredential({ hostname: 'a.com', username: 'u1', password: 'p1' }),
    saveCredential({ hostname: 'b.com', username: 'u2', password: 'p2' }),
    saveCredential({ hostname: 'c.com', username: 'u3', password: 'p3' })
  ]);

  const list = await getCredentials();
  assert.equal(list.length, 3);
});

test('Concurrent getMasterKey calls do not race', async () => {
  _resetKeyCache();
  const [k1, k2, k3] = await Promise.all([
    getMasterKey(),
    getMasterKey(),
    getMasterKey()
  ]);
  assert.equal(k1, k2);
  assert.equal(k2, k3);
});

test('Rejects wildcard-only hostnames on save', async () => {
  await assert.rejects(
    async () => await saveCredential({ hostname: '*', password: 'pw' }),
    /Valid hostname is required/
  );
  await assert.rejects(
    async () => await saveCredential({ hostname: '*.**', password: 'pw' }),
    /Valid hostname is required/
  );
});

test('Updating existing entry preserves omitted password or TOTP', async () => {
  await saveCredential({
    hostname: 'example.com',
    username: 'alice',
    password: 'initial-password'
  });

  // Add TOTP without re-typing password
  await saveCredential({
    hostname: 'example.com',
    username: 'alice',
    totpSecret: 'JBSWY3DPEHPK3PXP'
  });

  const afterTotp = await getCredentials('example.com');
  assert.equal(afterTotp.length, 1);
  assert.equal(afterTotp[0].password, 'initial-password');
  assert.equal(afterTotp[0].totpSecret, 'JBSWY3DPEHPK3PXP');

  // Update password without re-typing TOTP
  await saveCredential({
    hostname: 'example.com',
    username: 'alice',
    password: 'rotated-password'
  });

  const afterPw = await getCredentials('example.com');
  assert.equal(afterPw.length, 1);
  assert.equal(afterPw[0].password, 'rotated-password');
  assert.equal(afterPw[0].totpSecret, 'JBSWY3DPEHPK3PXP');
});

test('getMasterKey fails when IndexedDB persistence fails', async () => {
  _resetKeyCache();
  const prevIdb = globalThis.indexedDB;
  globalThis.indexedDB = {
    open() {
      const req = {};
      queueMicrotask(() => req.onerror?.());
      return req;
    }
  };

  try {
    await assert.rejects(async () => await getMasterKey(), /Failed to persist vault key/);
    // Must not cache an unpersisted key in memory
    await assert.rejects(async () => await getMasterKey(), /Failed to persist vault key/);
  } finally {
    globalThis.indexedDB = prevIdb;
    _resetKeyCache();
  }
});

test('Corrupted entries surface decryptError instead of vanishing silently', async () => {
  await saveCredential({ hostname: 'bad.com', username: 'bob', password: 'secret' });

  // Corrupt the ciphertext so the AES-GCM auth tag no longer verifies.
  const raw = fakeLocal.get('_bp_vault');
  raw[0].passwordEnc = raw[0].passwordEnc.slice(0, -2) + 'AA';
  fakeLocal.set('_bp_vault', raw);

  const list = await getCredentials();
  assert.equal(list.length, 1);
  assert.equal(list[0].decryptError, true);
  assert.equal(list[0].password, null);
});

test('Reorder swaps one storage slot and respects both ends', async () => {
  await saveCredential({ hostname: 'a.com', username: 'a', password: 'pa' });
  await saveCredential({ hostname: 'b.com', username: 'b', password: 'pb' });
  await saveCredential({ hostname: 'c.com', username: 'c', password: 'pc' });

  // Storage is oldest→newest (a, b, c); reads are freshest-first.
  const initial = await getCredentials();
  assert.deepEqual(initial.map(c => c.username), ['c', 'b', 'a']);
  const idOf = (username) => initial.find(c => c.username === username).id;

  // 'up' moves toward index 0, i.e. older in storage (popup.js flips the UI
  // arrow direction because the list is rendered in reverse).
  assert.equal(await reorderCredential(idOf('b'), 'up'), true);
  assert.deepEqual((await getCredentials()).map(c => c.username), ['c', 'a', 'b']);

  assert.equal(await reorderCredential(idOf('b'), 'down'), true);
  assert.deepEqual((await getCredentials()).map(c => c.username), ['c', 'b', 'a']);

  // Bounds: 'a' is first and 'c' is last in storage order.
  assert.equal(await reorderCredential(idOf('a'), 'up'), false);
  assert.equal(await reorderCredential(idOf('c'), 'down'), false);

  // Unknown id and unknown direction are rejected, not silently ignored.
  assert.equal(await reorderCredential('no-such-id', 'up'), false);
  assert.equal(await reorderCredential(idOf('a'), 'sideways'), false);
  assert.equal(await reorderCredential('', 'up'), false);

  // The rejected calls must not have moved anything.
  assert.deepEqual((await getCredentials()).map(c => c.username), ['c', 'b', 'a']);
});

test('Rejects hostname patterns with too many wildcards', async () => {
  await assert.rejects(
    async () => await saveCredential({ hostname: 'a*a*a*a*.com', password: 'pw' }),
    /at most 3 wildcards/
  );

  // Patterns within the cap still work
  const ok = await saveCredential({ hostname: 'app-*.svc-*.internal', password: 'pw' });
  assert.ok(ok.id);

  // Matching also refuses the pathological pattern, so an entry saved by an
  // older build cannot hang a page either.
  assert.equal(matchHostname('a*a*a*a*.com', 'aaaa.com'), false);
});

test('firstOnly returns just the freshest usable match', async () => {
  await saveCredential({ hostname: 'example.com', username: 'old', password: 'old-pass' });
  await saveCredential({ hostname: 'example.com', username: 'new', password: 'new-pass' });

  const all = await getCredentials('example.com');
  assert.equal(all.length, 2);

  const first = await getCredentials('example.com', { firstOnly: true });
  assert.equal(first.length, 1);
  assert.equal(first[0].username, 'new'); // freshest entry wins
  assert.equal(first[0].password, 'new-pass');

  // A corrupt freshest entry must not make the lookup give up on the rest.
  const raw = fakeLocal.get('_bp_vault');
  raw[1].passwordEnc = raw[1].passwordEnc.slice(0, -2) + 'AA'; // newest entry
  fakeLocal.set('_bp_vault', raw);

  const afterCorrupt = await getCredentials('example.com', { firstOnly: true });
  assert.equal(afterCorrupt.some(item => item.decryptError), true);
  assert.equal(afterCorrupt.find(item => !item.decryptError).username, 'old');
});
