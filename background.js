/**
 * FastPass - Service Worker (Background Script)
 * Access control, credential lookup, and TOTP generation.
 */

import {
  saveCredential,
  deleteCredential,
  reorderCredential,
  getCredentials
} from './storage.js';

import {
  generateTOTP,
  getTOTPSecondsRemaining
} from './crypto.js';

// Keep in sync with content.js and manifest.json (content scripts cannot import modules).
const LOCAL_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\])$/;

// Top-level HTTPS or localhost HTTP only.
export function getVerifiedSenderHost(sender) {
  if (!sender || sender.frameId !== 0 || !sender.url) return null;
  try {
    const { protocol, hostname } = new URL(sender.url);
    if (protocol === 'https:') return hostname;
    if (protocol === 'http:' && LOCAL_HOST_RE.test(hostname)) return hostname;
    return null;
  } catch {
    return null;
  }
}

// Vault management actions are restricted to this extension's own pages.
export function isExtensionPage(sender) {
  const senderUrl = sender?.url || '';
  return sender?.id === chrome.runtime.id && senderUrl.startsWith(chrome.runtime.getURL(''));
}

async function safeGenerateTOTP(secret) {
  try {
    return await generateTOTP(secret);
  } catch (err) {
    console.error('Failed to generate TOTP code:', err);
    return null;
  }
}

const ACTIONS = {
  async GET_AUTOFILL(_payload, sender) {
    const senderHost = getVerifiedSenderHost(sender);
    if (!senderHost) return { success: false, reason: 'Invalid or unauthorized sender' };

    const matches = await getCredentials(senderHost, { firstOnly: true });
    const primary = matches[0];
    if (!primary) return { success: false, reason: 'No matching credentials' };

    const totpCode = primary.totpSecret ? await safeGenerateTOTP(primary.totpSecret) : null;
    // Never expose the raw TOTP secret to page content scripts.
    return {
      success: true,
      credential: { username: primary.username, password: primary.password, totpCode }
    };
  },

  async LIST_ALL() {
    const items = await getCredentials();
    const credentials = [];
    for (const item of items) {
      const canTotp = !item.decryptError && !!item.totpSecret;
      const totpCode = canTotp ? await safeGenerateTOTP(item.totpSecret) : null;
      credentials.push({
        id: item.id,
        hostname: item.hostname,
        username: item.username,
        password: item.password,
        hasPassword: !!item.password,
        hasTotp: !!item.totpSecret,
        totpSecret: item.decryptError ? null : (item.totpSecret || null),
        decryptError: !!item.decryptError,
        totpCode,
        totpRemaining: totpCode !== null ? getTOTPSecondsRemaining() : null
      });
    }
    return { success: true, credentials };
  },

  async REFRESH_TOTP() {
    const items = await getCredentials(null, { includePasswords: false });
    const codes = [];
    for (const item of items) {
      if (item.decryptError || !item.totpSecret) continue;
      const totpCode = await safeGenerateTOTP(item.totpSecret);
      if (totpCode !== null) {
        codes.push({ id: item.id, totpCode, totpRemaining: getTOTPSecondsRemaining() });
      }
    }
    return { success: true, codes };
  },

  async ADD_CREDENTIAL(payload) {
    const entry = await saveCredential(payload || {});
    return { success: true, entry };
  },

  async REORDER_CREDENTIAL(payload) {
    return { success: await reorderCredential(payload?.id, payload?.direction) };
  },

  async DELETE_CREDENTIAL(payload) {
    return { success: await deleteCredential(payload?.id) };
  }
};

export function handleMessage(message, sender, sendResponse) {
  const { action, payload } = message || {};
  const handler = Object.hasOwn(ACTIONS, action) ? ACTIONS[action] : null;
  if (!handler) return false;

  (async () => {
    try {
      if (action !== 'GET_AUTOFILL' && !isExtensionPage(sender)) {
        sendResponse({ success: false, error: 'Unauthorized sender' });
        return;
      }
      sendResponse(await handler(payload, sender));
    } catch (err) {
      if (action === 'GET_AUTOFILL') console.error('Error during autofill lookup:', err);
      sendResponse({ success: false, error: err.message });
    }
  })();
  return true;
}

if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener(handleMessage);
}

if (typeof chrome !== 'undefined' && chrome.action?.onClicked) {
  chrome.action.onClicked.addListener(async (activeTab) => {
    const url = chrome.runtime.getURL('popup.html');
    const tabs = await chrome.tabs.query({ url });
    if (tabs.length > 0) {
      await chrome.tabs.update(tabs[0].id, { active: true });
      return;
    }
    await chrome.tabs.create({
      url: 'popup.html',
      index: activeTab ? activeTab.index + 1 : undefined
    });
  });
}
