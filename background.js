/**
 * FastPass - Service Worker (Background Script)
 * Manages secure communication, credential access control, and TOTP generation.
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

// Keep in sync with the check in content.js (and the `matches` list in
// manifest.json): content scripts are not modules, so this cannot be shared.
const LOCAL_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\])$/;

// Verify and extract origin hostname from sender URL (top-level HTTPS or localhost HTTP only)
export function getVerifiedSenderHost(sender) {
  if (!sender || sender.frameId !== 0 || !sender.url) {
    return null;
  }

  try {
    const parsed = new URL(sender.url);
    if (parsed.protocol === 'https:') {
      return parsed.hostname;
    }
    if (parsed.protocol === 'http:' && LOCAL_HOST_RE.test(parsed.hostname)) {
      return parsed.hostname;
    }
    return null;
  } catch {
    return null;
  }
}

// Vault management actions are only ever allowed from this extension's own
// pages (the popup tab). Without this, any future content script or page
// context that can reach the message channel could read the whole vault.
export function isExtensionPage(sender) {
  const senderUrl = sender?.url || '';
  return sender?.id === chrome.runtime.id && senderUrl.startsWith(chrome.runtime.getURL(''));
}

// Runtime message handler
export function handleMessage(message, sender, sendResponse) {
  const { action, payload } = message || {};

  // 1. AUTOFILL REQUEST FROM CONTENT SCRIPT
  if (action === 'GET_AUTOFILL') {
    (async () => {
      try {
        const senderHost = getVerifiedSenderHost(sender);
        if (!senderHost) {
          sendResponse({ success: false, reason: 'Invalid or unauthorized sender' });
          return;
        }

        // Strictly look up credentials matching the sender's verified hostname.
        // One entry is all autofill needs, so stop at the first that decrypts.
        const matches = await getCredentials(senderHost, { firstOnly: true });
        const primary = matches.find(item => !item.decryptError);
        if (!primary) {
          sendResponse({ success: false, reason: 'No matching credentials' });
          return;
        }

        let totpCode = null;

        // Generate dynamic 6-digit TOTP code on the fly if TOTP is configured
        if (primary.totpSecret) {
          try {
            totpCode = await generateTOTP(primary.totpSecret);
          } catch (err) {
            console.error('Failed to generate TOTP code:', err);
          }
        }

        // Return credentials to content script (totp secret itself is never sent to content script)
        sendResponse({
          success: true,
          credential: {
            username: primary.username,
            password: primary.password,
            totpCode
          }
        });
      } catch (err) {
        console.error('Error during autofill lookup:', err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true; // Keep message channel open for async response
  }

  // 2. LIST ALL SAVED CREDENTIALS (POPUP / TAB)
  if (action === 'LIST_ALL') {
    (async () => {
      try {
        if (!isExtensionPage(sender)) {
          sendResponse({ success: false, error: 'Unauthorized sender' });
          return;
        }
        const items = await getCredentials();
        const results = [];
        for (const item of items) {
          let totpCode = null;
          let totpRemaining = null;
          if (!item.decryptError && item.totpSecret) {
            try {
              totpCode = await generateTOTP(item.totpSecret);
              totpRemaining = getTOTPSecondsRemaining();
            } catch {}
          }
          results.push({
            id: item.id,
            hostname: item.hostname,
            username: item.username,
            password: item.password,
            hasPassword: !!item.password,
            hasTotp: !!item.totpSecret,
            totpSecret: item.decryptError ? null : (item.totpSecret || null),
            decryptError: !!item.decryptError,
            totpCode,
            totpRemaining
          });
        }
        sendResponse({ success: true, credentials: results });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // 3. REFRESH LIVE TOTP CODES ONLY (never decrypts or returns passwords)
  if (action === 'REFRESH_TOTP') {
    (async () => {
      try {
        if (!isExtensionPage(sender)) {
          sendResponse({ success: false, error: 'Unauthorized sender' });
          return;
        }
        const items = await getCredentials(null, { includePasswords: false });
        const codes = [];
        for (const item of items) {
          if (item.decryptError || !item.totpSecret) continue;
          try {
            codes.push({
              id: item.id,
              totpCode: await generateTOTP(item.totpSecret),
              totpRemaining: getTOTPSecondsRemaining()
            });
          } catch {}
        }
        sendResponse({ success: true, codes });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // 4. ADD NEW CREDENTIAL (POPUP)
  if (action === 'ADD_CREDENTIAL') {
    (async () => {
      try {
        if (!isExtensionPage(sender)) {
          sendResponse({ success: false, error: 'Unauthorized sender' });
          return;
        }
        const { hostname, username, password, totpSecret } = payload || {};
        const entry = await saveCredential({
          hostname,
          username,
          password,
          totpSecret
        });
        sendResponse({ success: true, entry });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // 5. REORDER CREDENTIAL (POPUP)
  if (action === 'REORDER_CREDENTIAL') {
    (async () => {
      try {
        if (!isExtensionPage(sender)) {
          sendResponse({ success: false, error: 'Unauthorized sender' });
          return;
        }
        const { id, direction } = payload || {};
        const ok = await reorderCredential(id, direction);
        sendResponse({ success: ok });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // 6. DELETE CREDENTIAL (POPUP)
  if (action === 'DELETE_CREDENTIAL') {
    (async () => {
      try {
        if (!isExtensionPage(sender)) {
          sendResponse({ success: false, error: 'Unauthorized sender' });
          return;
        }
        const { id } = payload || {};
        const ok = await deleteCredential(id);
        sendResponse({ success: ok });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  return false;
}

if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener(handleMessage);
}

// Open UI as a new tab
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
