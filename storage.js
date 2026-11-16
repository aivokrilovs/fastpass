/**
 * FastPass - Storage & Vault Manager
 * AES-256-GCM encrypted credential vault with hostname matching
 */

import {
  generateMasterKey,
  encrypt,
  decrypt,
  normalizeBase32,
  isValidBase32
} from './crypto.js';

const STORAGE_VAULT_KEY = '_bp_vault';

// Cap '*' count per pattern to prevent exponential regex backtracking on non-matching hosts.
const MAX_WILDCARDS = 3;

let cachedMasterKey = null;
let masterKeyPromise = null;
let vaultLock = Promise.resolve();

function storageLocal() {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) {
    throw new Error('chrome.storage.local is unavailable.');
  }
  return chrome.storage.local;
}

async function getRawVault() {
  const res = await storageLocal().get([STORAGE_VAULT_KEY]);
  return Array.isArray(res[STORAGE_VAULT_KEY]) ? res[STORAGE_VAULT_KEY] : [];
}

function saveRawVault(items) {
  return storageLocal().set({ [STORAGE_VAULT_KEY]: items });
}

// Serialize read-modify-write vault mutations so concurrent writes don't clobber each other.
function withVaultLock(fn) {
  const run = vaultLock.then(fn, fn);
  vaultLock = run.catch(() => {});
  return run;
}

function normalizeSinglePattern(pat) {
  if (!pat || typeof pat !== 'string') return '';
  const s = pat.trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, '')
    .split(/[/?#]/)[0]
    .replace(/:\d+$/, '');
  return s.startsWith('www.') && !s.includes('*') ? s.slice(4) : s;
}

export function normalizeHostname(input) {
  if (!input || typeof input !== 'string') return '';
  const tokens = input.split(',').map(normalizeSinglePattern).filter(Boolean);
  return [...new Set(tokens)].join(', ');
}

function isWildcardOnlyPattern(pattern) {
  return !pattern || !pattern.replace(/[*.\s-]/g, '');
}

function wildcardCount(pattern) {
  return pattern.split('*').length - 1;
}

function wildcardToLabelRegex(str) {
  return str
    .split('*')
    .map(part => part.replace(/[.+?^${}()|[\]\\/]/g, '\\$&'))
    .join('[a-z0-9-]*');
}

function singlePatternMatches(pattern, target) {
  const p = normalizeSinglePattern(pattern);
  const t = normalizeSinglePattern(target);
  if (!p || !t) return false;
  if (p === t) return true;
  if (!p.includes('*')) return false;
  if (isWildcardOnlyPattern(p) || wildcardCount(p) > MAX_WILDCARDS) return false;

  if (p.startsWith('*.')) {
    const base = p.slice(2);
    if (!base || isWildcardOnlyPattern(base)) return false;
    if (!base.includes('*') && t === base) return true;
    return new RegExp('^(?:[a-z0-9.-]+\\.)?' + wildcardToLabelRegex(base) + '$').test(t);
  }
  return new RegExp('^' + wildcardToLabelRegex(p) + '$').test(t);
}

export function matchHostname(savedHost, targetHost) {
  const target = normalizeSinglePattern(targetHost);
  if (!savedHost || !target) return false;
  return savedHost.split(',').some(pat => singlePatternMatches(pat, target));
}

// Keep non-extractable CryptoKey in IndexedDB, separate from chrome.storage.local ciphertext.
function idbKey(mode, run, fallback) {
  if (typeof indexedDB === 'undefined') return Promise.resolve(fallback);
  return new Promise((resolve) => {
    const openReq = indexedDB.open('credential-vault', 1);
    openReq.onupgradeneeded = () => {
      const db = openReq.result;
      if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys');
    };
    openReq.onerror = () => resolve(fallback);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const tx = db.transaction('keys', mode);
        tx.oncomplete = tx.onerror = tx.onabort = () => db.close();
        const req = run(tx.objectStore('keys'));
        req.onsuccess = () => resolve(mode === 'readonly' ? (req.result || null) : true);
        req.onerror = () => resolve(fallback);
      } catch {
        db.close();
        resolve(fallback);
      }
    };
  });
}

export async function getMasterKey() {
  if (cachedMasterKey) return cachedMasterKey;
  if (masterKeyPromise) return masterKeyPromise;

  masterKeyPromise = (async () => {
    try {
      const key = await idbKey('readonly', s => s.get('masterKey'), null);
      if (key) {
        cachedMasterKey = key;
        return key;
      }

      // Never mint a fresh key over an existing vault; that would make old entries unreadable.
      if ((await getRawVault()).length > 0) {
        throw new Error('Vault key missing — vault cannot be unlocked. Existing entries are unreadable.');
      }

      const newKey = await generateMasterKey();
      if (typeof indexedDB !== 'undefined') {
        const saved = await idbKey('readwrite', s => s.put(newKey, 'masterKey'), false);
        if (!saved) throw new Error('Failed to persist vault key in IndexedDB.');
      }
      cachedMasterKey = newKey;
      return newKey;
    } finally {
      masterKeyPromise = null;
    }
  })();

  return masterKeyPromise;
}

export async function saveCredential({ hostname, username, password, totpSecret }) {
  const normHost = normalizeHostname(hostname);
  const hostPatterns = normHost ? normHost.split(',').map(s => s.trim()).filter(Boolean) : [];
  if (hostPatterns.length === 0 || hostPatterns.some(isWildcardOnlyPattern)) {
    throw new Error('Valid hostname is required');
  }
  if (hostPatterns.some(p => wildcardCount(p) > MAX_WILDCARDS)) {
    throw new Error(`Hostname pattern may contain at most ${MAX_WILDCARDS} wildcards`);
  }

  const cleanUsername = (username || '').trim();
  const cleanPassword = password ? String(password) : null;

  let cleanTotpSecret = null;
  if (totpSecret && totpSecret.trim()) {
    cleanTotpSecret = normalizeBase32(totpSecret);
    if (!isValidBase32(cleanTotpSecret)) {
      throw new Error('Invalid TOTP Base32 secret. Characters must be A-Z and 2-7.');
    }
  }

  if (!cleanUsername && !cleanPassword && !cleanTotpSecret) {
    throw new Error('At least one of username, password, or TOTP secret is required');
  }

  const masterKey = await getMasterKey();

  return withVaultLock(async () => {
    const items = await getRawVault();
    const existingIdx = items.findIndex(
      item => item.hostname === normHost && item.username === cleanUsername
    );

    const entry = existingIdx !== -1
      ? items.splice(existingIdx, 1)[0]
      : {
          id: Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 9),
          hostname: normHost,
          username: cleanUsername,
          passwordEnc: null,
          passwordIv: null,
          totpEnc: null,
          totpIv: null
        };

    // Encrypt only what was supplied; omitted secrets keep their stored value.
    if (cleanPassword) {
      const enc = await encrypt(cleanPassword, masterKey);
      entry.passwordEnc = enc.ciphertext;
      entry.passwordIv = enc.iv;
    }
    if (cleanTotpSecret) {
      const enc = await encrypt(cleanTotpSecret, masterKey);
      entry.totpEnc = enc.ciphertext;
      entry.totpIv = enc.iv;
    }

    items.push(entry);
    await saveRawVault(items);

    return {
      id: entry.id,
      hostname: entry.hostname,
      username: entry.username,
      hasPassword: !!entry.passwordEnc,
      hasTotp: !!entry.totpEnc
    };
  });
}

export async function reorderCredential(id, direction) {
  if (!id || (direction !== 'up' && direction !== 'down')) return false;
  return withVaultLock(async () => {
    const items = await getRawVault();
    const idx = items.findIndex(item => item.id === id);
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (idx === -1 || swapIdx < 0 || swapIdx >= items.length) return false;
    [items[idx], items[swapIdx]] = [items[swapIdx], items[idx]];
    await saveRawVault(items);
    return true;
  });
}

export async function deleteCredential(id) {
  if (!id) return false;
  return withVaultLock(async () => {
    const items = await getRawVault();
    const filtered = items.filter(item => item.id !== id);
    if (filtered.length === items.length) return false;
    await saveRawVault(filtered);
    return true;
  });
}

// Returns freshest-first. firstOnly skips undecryptable entries and stops at the first usable one.
export async function getCredentials(targetHost = null, { includePasswords = true, firstOnly = false } = {}) {
  const normTarget = targetHost === null ? null : normalizeHostname(targetHost);
  if (normTarget === '') return [];

  const items = await getRawVault();
  const matches = normTarget === null
    ? items
    : items.filter(item => matchHostname(item.hostname, normTarget));
  if (matches.length === 0) return [];

  const masterKey = await getMasterKey();
  const decrypted = [];

  for (let i = matches.length - 1; i >= 0; i--) {
    const item = matches[i];
    try {
      const password = includePasswords && item.passwordEnc && item.passwordIv
        ? await decrypt(item.passwordEnc, item.passwordIv, masterKey)
        : null;
      const totpSecret = item.totpEnc && item.totpIv
        ? await decrypt(item.totpEnc, item.totpIv, masterKey)
        : null;

      decrypted.push({
        id: item.id,
        hostname: item.hostname,
        username: item.username,
        password,
        totpSecret,
        decryptError: false
      });

      if (firstOnly) break;
    } catch (e) {
      console.error(`Failed to decrypt credential for ${item.hostname}:`, e);
      if (firstOnly) continue; // keep looking for an entry that does decrypt
      decrypted.push({
        id: item.id,
        hostname: item.hostname,
        username: item.username,
        password: null,
        totpSecret: null,
        decryptError: true
      });
    }
  }

  return decrypted;
}

// Test seam: clears in-memory key cache without touching storage.
export function _resetKeyCache() {
  cachedMasterKey = null;
  masterKeyPromise = null;
}
