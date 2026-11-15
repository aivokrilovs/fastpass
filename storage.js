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

// In-memory key cache and in-flight init promise
let cachedMasterKey = null;
let masterKeyPromise = null;

function getStorage() {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) {
    throw new Error('chrome.storage.local is unavailable.');
  }
  return {
    async get(key) {
      const result = await chrome.storage.local.get([key]);
      return result[key];
    },
    async set(key, value) {
      await chrome.storage.local.set({ [key]: value });
    }
  };
}

/**
 * Normalize a single hostname or glob pattern.
 * Strips protocols, paths, query strings, ports, and 'www.' prefix (when not part of a glob).
 */
function normalizeSinglePattern(pat) {
  if (!pat || typeof pat !== 'string') return '';
  let str = pat.trim().toLowerCase();
  str = str.replace(/^[a-z]+:\/\//i, '');
  str = str.split('/')[0].split('?')[0].split('#')[0];
  str = str.replace(/:\d+$/, '');
  if (str.startsWith('www.') && !str.includes('*')) {
    str = str.slice(4);
  }
  return str;
}

/**
 * Normalize hostname(s) for consistent comparison and storage.
 * Supports comma-separated list of domains / globs.
 */
export function normalizeHostname(input) {
  if (!input || typeof input !== 'string') return '';
  const tokens = input.split(',').map(normalizeSinglePattern).filter(Boolean);
  return Array.from(new Set(tokens)).join(', ');
}

function isWildcardOnlyPattern(pattern) {
  return !pattern || !pattern.replace(/[*.\s-]/g, '');
}

// Every '*' becomes a `[a-z0-9-]*` group, and a hostname that does not match
// can make those groups backtrack exponentially (freezing the page that runs
// the content script). Real patterns need one or two ('*.example.com',
// 'app-*.internal'), so the cap sits well below the problem size.
const MAX_WILDCARDS = 3;

function wildcardCount(pattern) {
  return (pattern.match(/\*/g) || []).length;
}

function escapeRegex(str) {
  return str.replace(/[.+?^${}()|[\]\\/]/g, '\\$&');
}

function wildcardToLabelRegex(str) {
  return str.split('*').map(escapeRegex).join('[a-z0-9-]*');
}

/**
 * Check if a single pattern (exact or glob) matches a target hostname.
 */
function singlePatternMatches(pattern, target) {
  if (!pattern || !target) return false;
  const p = normalizeSinglePattern(pattern);
  const t = normalizeSinglePattern(target);
  if (!p || !t) return false;

  // Exact match (also handles www. stripped by normalizeSinglePattern)
  if (p === t) return true;

  // Explicit blobbing with wildcard *
  if (p.includes('*')) {
    if (isWildcardOnlyPattern(p)) return false;
    if (wildcardCount(p) > MAX_WILDCARDS) return false; // never run a pathological regex
    if (p.startsWith('*.')) {
      const base = p.slice(2);
      if (!base || isWildcardOnlyPattern(base)) return false;
      // *.example.com matches example.com and any subdomain of example.com
      if (!base.includes('*') && t === base) return true;
      const re = new RegExp('^(?:[a-z0-9.-]+\\.)?' + wildcardToLabelRegex(base) + '$');
      return re.test(t);
    }
    const re = new RegExp('^' + wildcardToLabelRegex(p) + '$');
    return re.test(t);
  }

  return false;
}

/**
 * Match a saved hostname (or comma-separated list of hostnames / globs)
 * against a target page hostname.
 * Supports explicit blobbing (e.g. *.example.com,example.co.uk).
 * Prevents spoofing (e.g. badexample.com or example.com.attacker.com).
 */
export function matchHostname(savedHost, targetHost) {
  if (!savedHost || !targetHost) return false;
  const target = normalizeSinglePattern(targetHost);
  if (!target) return false;

  const patterns = savedHost.split(',').map(s => s.trim()).filter(Boolean);
  for (const pat of patterns) {
    if (singlePatternMatches(pat, target)) return true;
  }
  return false;
}

/**
 * IndexedDB Key Storage Helper
 * Keeps CryptoKey in browser IndexedDB (separate from chrome.storage.local)
 */
function openKeyDB() {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null);
  return new Promise((resolve) => {
    const req = indexedDB.open('credential-vault', 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
}

async function withKeyStore(mode, runRequest, fallback) {
  const db = await openKeyDB();
  if (!db) return fallback;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction('keys', mode);
      tx.oncomplete = () => db.close();
      tx.onerror = () => db.close();
      tx.onabort = () => db.close();
      const req = runRequest(tx.objectStore('keys'));
      req.onsuccess = () => resolve(mode === 'readonly' ? (req.result || null) : true);
      req.onerror = () => resolve(fallback);
    } catch {
      db.close();
      resolve(fallback);
    }
  });
}

function loadKeyFromIDB() {
  return withKeyStore('readonly', (store) => store.get('masterKey'), null);
}

function saveKeyToIDB(cryptoKey) {
  return withKeyStore('readwrite', (store) => store.put(cryptoKey, 'masterKey'), false);
}

/**
 * Get or initialize master AES-256-GCM encryption key.
 * The key lives only in IndexedDB as a non-extractable CryptoKey. It is never
 * copied into chrome.storage.local: a plaintext key next to the ciphertext
 * would make the encryption pointless.
 * Uses mutex promise to avoid race conditions during concurrent first launch.
 */
export async function getMasterKey() {
  if (cachedMasterKey) return cachedMasterKey;
  if (masterKeyPromise) return masterKeyPromise;

  masterKeyPromise = (async () => {
    try {
      // 1. Try loading from IndexedDB
      const key = await loadKeyFromIDB();
      if (key) {
        cachedMasterKey = key;
        return cachedMasterKey;
      }

      // 2. No key found. Minting a new one is only safe when nothing is stored
      // yet — otherwise every existing entry would become permanently
      // undecryptable, and the new key would overwrite the only way back.
      const existing = await getRawVault();
      if (existing.length > 0) {
        throw new Error('Vault key missing — vault cannot be unlocked. Existing entries are unreadable.');
      }

      // 3. Generate new master key and persist it when IndexedDB is available
      const newKey = await generateMasterKey();
      if (typeof indexedDB !== 'undefined') {
        const saved = await saveKeyToIDB(newKey);
        if (!saved) {
          throw new Error('Failed to persist vault key in IndexedDB.');
        }
      }
      cachedMasterKey = newKey;
      return cachedMasterKey;
    } finally {
      masterKeyPromise = null;
    }
  })();

  return masterKeyPromise;
}

/**
 * Retrieve raw vault entries from storage.
 */
async function getRawVault() {
  const storage = getStorage();
  const raw = await storage.get(STORAGE_VAULT_KEY);
  return Array.isArray(raw) ? raw : [];
}

/**
 * Persist raw vault entries to storage.
 */
async function saveRawVault(items) {
  const storage = getStorage();
  await storage.set(STORAGE_VAULT_KEY, items);
}

/**
 * Serialize vault mutations. Every write is read-modify-write, so two
 * concurrent messages would otherwise both write from a stale copy and one
 * change would be silently lost.
 */
let vaultLock = Promise.resolve();
function withVaultLock(fn) {
  const run = vaultLock.then(fn, fn);
  vaultLock = run.catch(() => {});
  return run;
}

/**
 * Add or update a credential in the encrypted vault.
 */
export async function saveCredential({ hostname, username, password, totpSecret }) {
  const normHost = normalizeHostname(hostname);
  const hostPatterns = normHost ? normHost.split(',').map((s) => s.trim()).filter(Boolean) : [];
  if (hostPatterns.length === 0 || hostPatterns.some(isWildcardOnlyPattern)) {
    throw new Error('Valid hostname is required');
  }
  if (hostPatterns.some((p) => wildcardCount(p) > MAX_WILDCARDS)) {
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
  let encPassword = null;
  if (cleanPassword) {
    encPassword = await encrypt(cleanPassword, masterKey);
  }

  let encTotp = null;
  if (cleanTotpSecret) {
    encTotp = await encrypt(cleanTotpSecret, masterKey);
  }

  return withVaultLock(async () => {
    const items = await getRawVault();

    const existingIndex = items.findIndex(
      item => item.hostname === normHost && item.username === cleanUsername
    );

    let resultEntry;
    if (existingIndex !== -1) {
      // Pull entry out, update it, push to end (newest = last)
      resultEntry = items.splice(existingIndex, 1)[0];
      if (encPassword) {
        resultEntry.passwordEnc = encPassword.ciphertext;
        resultEntry.passwordIv = encPassword.iv;
      }
      if (encTotp) {
        resultEntry.totpEnc = encTotp.ciphertext;
        resultEntry.totpIv = encTotp.iv;
      }
      items.push(resultEntry);
    } else {
      // Add new credential entry (already appended = newest last)
      const id = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 9);
      resultEntry = {
        id,
        hostname: normHost,
        username: cleanUsername,
        passwordEnc: encPassword ? encPassword.ciphertext : null,
        passwordIv: encPassword ? encPassword.iv : null,
        totpEnc: encTotp ? encTotp.ciphertext : null,
        totpIv: encTotp ? encTotp.iv : null
      };
      items.push(resultEntry);
    }

    await saveRawVault(items);

    return {
      id: resultEntry.id,
      hostname: resultEntry.hostname,
      username: resultEntry.username,
      hasPassword: !!resultEntry.passwordEnc,
      hasTotp: !!resultEntry.totpEnc
    };
  });
}

/**
 * Reorder a credential up or down by one position in the vault array.
 * direction: 'up' | 'down'
 */
export async function reorderCredential(id, direction) {
  if (!id || (direction !== 'up' && direction !== 'down')) return false;
  return withVaultLock(async () => {
    const items = await getRawVault();
    const idx = items.findIndex(item => item.id === id);
    if (idx === -1) return false;
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= items.length) return false;
    [items[idx], items[swapIdx]] = [items[swapIdx], items[idx]];
    await saveRawVault(items);
    return true;
  });
}

/**
 * Delete a credential by ID.
 */
export async function deleteCredential(id) {
  if (!id) return false;
  return withVaultLock(async () => {
    const items = await getRawVault();
    const filtered = items.filter(item => item.id !== id);
    if (filtered.length === items.length) {
      return false; // Not found
    }
    await saveRawVault(filtered);
    return true;
  });
}

/**
 * Get decrypted credentials. With a target host: only the entries matching that
 * hostname. Without one: the whole vault (management view). Sorted freshest first.
 * firstOnly stops at the first entry that decrypts cleanly, so callers that
 * need a single credential (autofill) skip the remaining AES-GCM decrypts.
 */
export async function getCredentials(targetHost = null, { includePasswords = true, firstOnly = false } = {}) {
  const normTarget = targetHost === null ? null : normalizeHostname(targetHost);
  if (normTarget === '') return [];

  const items = await getRawVault();
  const matches = normTarget === null
    ? items
    : items.filter(item => matchHostname(item.hostname, normTarget));
  if (matches.length === 0) return [];

  const masterKey = await getMasterKey();
  const decryptedList = [];

  // Array is ordered oldest→newest; iterate in reverse for freshest-first
  for (const item of [...matches].reverse()) {
    try {
      let password = null;
      if (includePasswords && item.passwordEnc && item.passwordIv) {
        password = await decrypt(item.passwordEnc, item.passwordIv, masterKey);
      }
      let totpSecret = null;
      if (item.totpEnc && item.totpIv) {
        totpSecret = await decrypt(item.totpEnc, item.totpIv, masterKey);
      }

      decryptedList.push({
        id: item.id,
        hostname: item.hostname,
        username: item.username,
        password,
        totpSecret,
        decryptError: false
      });

      // firstOnly stops only on a usable entry — the catch below lets the scan
      // continue past an entry that failed to decrypt.
      if (firstOnly) break;
    } catch (e) {
      console.error(`Failed to decrypt credential for ${item.hostname}:`, e);
      decryptedList.push({
        id: item.id,
        hostname: item.hostname,
        username: item.username,
        password: null,
        totpSecret: null,
        decryptError: true
      });
    }
  }

  return decryptedList;
}

// Test seam: drops the in-memory master-key cache. The vault lives in
// chrome.storage.local, so a test that wants "vault survived, key is gone"
// calls this without touching its fake storage.
export function _resetKeyCache() {
  cachedMasterKey = null;
  masterKeyPromise = null;
}
