/**
 * storage.js talks to chrome.storage.local and nothing else. Node has no
 * `chrome`, so tests install this in-memory stand-in instead of the module
 * shipping a test-only fallback store.
 *
 * Returns the backing Map so a test can inspect or corrupt raw vault entries.
 */
export function installFakeChromeStorage(extra = {}) {
  const local = new Map();
  globalThis.chrome = {
    ...extra,
    storage: {
      local: {
        async get([key]) {
          return { [key]: local.get(key) };
        },
        async set(obj) {
          for (const [k, v] of Object.entries(obj)) local.set(k, v);
        }
      }
    }
  };
  return local;
}
