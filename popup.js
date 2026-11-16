/**
 * FastPass - Extension Tab Controller
 * Minimal interface for managing passwords and TOTP codes.
 */

import { generateRandomPassword, getTOTPSecondsRemaining } from './crypto.js';

const TOTP_WINDOW_MS = 30000;

const form = document.getElementById('add-form');
const domainInput = document.getElementById('domain-input');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const totpInput = document.getElementById('totp-input');
const togglePassBtn = document.getElementById('toggle-form-pass-btn');
const genPassBtn = document.getElementById('gen-pass-btn');
const statusMsg = document.getElementById('status-msg');
const savedTitle = document.getElementById('saved-title');
const list = document.getElementById('credentials-list');
const exportArea = document.getElementById('export-area');
const exportBtn = document.getElementById('export-btn');
const importBtn = document.getElementById('import-btn');
const importGoBtn = document.getElementById('import-go-btn');
const importGoRow = document.getElementById('import-go-row');

let credentials = [];
let backupMode = null; // null | 'export' | 'import'
let totpInterval = null;
let statusTimer = null;
let pendingDeleteId = null;
let deleteTimer = null;

// --- helpers ----------------------------------------------------------------

function send(action, payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action, payload }, (response) => {
      resolve(chrome.runtime.lastError
        ? { success: false, error: chrome.runtime.lastError.message }
        : response || { success: false });
    });
  });
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (m) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}

function showStatus(message, isError = false) {
  clearTimeout(statusTimer);
  statusMsg.textContent = message;
  statusMsg.className = isError ? 'status-error' : 'status-success';
  statusMsg.style.display = 'block';
  statusTimer = setTimeout(() => { statusMsg.style.display = 'none'; }, 3500);
}

async function copyToClipboard(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const label = button.textContent;
    button.textContent = 'Copied!';
    button.disabled = true;
    setTimeout(() => {
      button.textContent = label;
      button.disabled = false;
    }, 1500);
  } catch (err) {
    console.error('Clipboard copy failed:', err);
  }
}

function formatTotpCode(code) {
  return code && code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : (code || '------');
}

const currentWindow = () => Math.floor(Date.now() / TOTP_WINDOW_MS);

function cardNode(id) {
  return list.querySelector(`.cred-wrap[data-id="${CSS.escape(id)}"] .card`);
}

// --- rendering --------------------------------------------------------------

function cardHtml(cred, index, total) {
  const passwordRow = cred.decryptError
    ? '<span class="value danger">Decryption failed</span>'
    : cred.password
      ? `<span class="value pass-display" data-hidden="true">••••••••</span>
         <button type="button" class="btn" data-act="toggle-pass">Show</button>
         <button type="button" class="btn" data-act="copy-pass">Copy</button>`
      : '<span class="value muted">(none)</span>';

  const totpBox = cred.hasTotp && !cred.decryptError
    ? `<div class="totp-box">
         <div>
           <span class="totp-label">TOTP Code</span>
           <div class="totp-code">${formatTotpCode(cred.totpCode)}</div>
         </div>
         <div class="pass-row">
           <span class="totp-timer">${cred.totpRemaining || 30}s</span>
           <button type="button" class="btn" data-act="show-secret">Secret</button>
           <button type="button" class="btn" data-act="copy-totp">Copy TOTP</button>
         </div>
       </div>
       <div class="totp-secret-row" hidden></div>`
    : '';

  const arrows = `
    <div class="arrows">
      ${index > 0 ? '<span class="arrow" data-act="up" title="Move up">▲</span>' : ''}
      ${index < total - 1 ? '<span class="arrow" data-act="down" title="Move down">▼</span>' : ''}
    </div>`;

  return `
    <div class="cred-wrap" data-id="${escapeHtml(cred.id)}">
      <div class="card">
        <div class="card-row">
          <span class="label">Domain</span>
          <span class="value strong">${escapeHtml(cred.hostname)}</span>
        </div>
        <div class="card-row">
          <span class="label">Username</span>
          <span class="value">${escapeHtml(cred.username || '(none)')}</span>
        </div>
        <div class="card-row">
          <span class="label">Password</span>
          <div class="pass-row">${passwordRow}</div>
        </div>
        ${totpBox}
        <div class="card-row card-actions">
          <button type="button" class="btn btn-danger" data-act="delete">Delete</button>
        </div>
      </div>
      ${arrows}
    </div>`;
}

function render() {
  savedTitle.textContent = `Saved Passwords (${credentials.length})`;
  if (credentials.length === 0) {
    list.innerHTML = '<div class="empty-state">No saved passwords</div>';
    return;
  }
  list.innerHTML = credentials.map((cred, i) => cardHtml(cred, i, credentials.length)).join('');
  resetDeleteButtons();
}

// --- list interactions (one delegated listener for all cards) ----------------

function resetDeleteButtons() {
  clearTimeout(deleteTimer);
  pendingDeleteId = null;
  for (const btn of list.querySelectorAll('[data-act="delete"]')) {
    btn.textContent = 'Delete';
    btn.classList.remove('armed');
  }
}

async function deleteCredential(id) {
  resetDeleteButtons();
  const res = await send('DELETE_CREDENTIAL', { id });
  if (!res.success) {
    showStatus(res.error || 'Failed to delete credential.', true);
    return;
  }
  await load();
  showStatus('Credential deleted.');
}

function armDelete(button, id) {
  if (pendingDeleteId === id) {
    deleteCredential(id);
    return;
  }
  resetDeleteButtons();
  pendingDeleteId = id;
  button.textContent = 'Confirm?';
  button.classList.add('armed');
  deleteTimer = setTimeout(resetDeleteButtons, 3000);
}

async function reorder(id, uiDirection) {
  // Storage order is oldest→newest while the list renders newest-first.
  const direction = uiDirection === 'up' ? 'down' : 'up';
  const res = await send('REORDER_CREDENTIAL', { id, direction });
  if (res.success) await load();
}

function toggleSecret(button, cred) {
  const row = cardNode(cred.id)?.querySelector('.totp-secret-row');
  if (!row) return;
  const visible = !row.hidden;
  row.hidden = visible;
  row.textContent = visible ? '' : (cred.totpSecret || '');
  button.textContent = visible ? 'Secret' : 'Hide';
}

list.addEventListener('click', (e) => {
  const target = e.target.closest('[data-act]');
  const wrap = target && target.closest('.cred-wrap');
  const cred = wrap && credentials.find(c => c.id === wrap.dataset.id);
  if (!cred) return;
  const card = wrap.querySelector('.card');

  switch (target.dataset.act) {
    case 'up':
    case 'down':
      reorder(cred.id, target.dataset.act);
      break;
    case 'delete':
      armDelete(target, cred.id);
      break;
    case 'toggle-pass': {
      const display = card.querySelector('.pass-display');
      const hidden = display.dataset.hidden === 'true';
      display.dataset.hidden = String(!hidden);
      display.textContent = hidden ? cred.password : '••••••••';
      target.textContent = hidden ? 'Hide' : 'Show';
      break;
    }
    case 'copy-pass':
      copyToClipboard(cred.password, target);
      break;
    case 'copy-totp':
      copyToClipboard((cred.totpCode || '').replace(/\s+/g, ''), target);
      break;
    case 'show-secret':
      toggleSecret(target, cred);
      break;
  }
});

// --- TOTP live updates ------------------------------------------------------

async function refreshTotpCodes() {
  const res = await send('REFRESH_TOTP');
  if (!res.success) return;
  const windowStart = currentWindow();
  for (const { id, totpCode } of res.codes) {
    const cred = credentials.find(c => c.id === id);
    if (!cred) continue;
    cred.totpCode = totpCode;
    cred.totpWindow = windowStart;
    const codeEl = cardNode(id)?.querySelector('.totp-code');
    if (codeEl) codeEl.textContent = formatTotpCode(totpCode);
  }
}

function startTotpUpdater() {
  clearInterval(totpInterval);
  totpInterval = null;

  if (!credentials.some(c => c.hasTotp)) return;

  totpInterval = setInterval(() => {
    const remaining = getTOTPSecondsRemaining();
    for (const el of list.querySelectorAll('.totp-timer')) el.textContent = `${remaining}s`;

    // Also catches a backgrounded tab that missed the rollover entirely.
    const windowStart = currentWindow();
    const rolled = credentials.some(c => c.hasTotp && c.totpWindow !== windowStart);
    if (remaining === 30 || rolled) refreshTotpCodes();
  }, 1000);
}

// --- loading ----------------------------------------------------------------

async function load() {
  const res = await send('LIST_ALL');
  if (!res.success) {
    const msg = res.error || 'Failed to load saved credentials.';
    list.innerHTML = `<div class="empty-state">${escapeHtml(msg)}</div>`;
    showStatus(msg, true);
    return;
  }
  const windowStart = currentWindow();
  credentials = res.credentials.map(c => ({ ...c, totpWindow: windowStart }));
  render();
  startTotpUpdater();
}

// --- add form ---------------------------------------------------------------

function setPasswordVisible(visible) {
  passwordInput.type = visible ? 'text' : 'password';
  togglePassBtn.textContent = visible ? 'Hide' : 'Show';
}

togglePassBtn.addEventListener('click', () => setPasswordVisible(passwordInput.type === 'password'));

genPassBtn.addEventListener('click', () => {
  passwordInput.value = generateRandomPassword(20);
  setPasswordVisible(true);
});

function clearForm() {
  form.reset();
  setPasswordVisible(false);
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const payload = {
    hostname: domainInput.value.trim(),
    username: usernameInput.value.trim(),
    password: passwordInput.value,
    totpSecret: totpInput.value.trim()
  };

  if (!payload.hostname) return showStatus('Domain is required', true);
  if (!payload.username && !payload.password && !payload.totpSecret) {
    return showStatus('At least one of username, password, or TOTP secret is required', true);
  }

  const res = await send('ADD_CREDENTIAL', payload);
  if (!res.success) return showStatus(res.error || 'Failed to save credential', true);

  clearForm();
  showStatus('Credential saved securely!');
  await load();
});

// --- backup (export / import) -----------------------------------------------

function setBackupMode(mode) {
  if (backupMode === mode) mode = null;
  backupMode = mode;

  exportArea.hidden = mode === null;
  importGoRow.hidden = mode !== 'import';
  exportBtn.textContent = mode === 'export' ? 'Close' : 'Export';
  importBtn.textContent = mode === 'import' ? 'Close' : 'Import';

  if (mode === 'export') {
    const dump = credentials.map(({ hostname, username, password, totpSecret }) =>
      ({ hostname, username, password, totpSecret }));
    exportArea.value = JSON.stringify(dump, null, 2);
    exportArea.readOnly = true;
    exportArea.select();
  } else if (mode === 'import') {
    exportArea.value = '';
    exportArea.readOnly = false;
    exportArea.focus();
  }
}

async function importVault() {
  let parsed;
  try {
    parsed = JSON.parse(exportArea.value);
  } catch {
    return showStatus('Import failed: invalid JSON.', true);
  }
  if (!Array.isArray(parsed)) return showStatus('Import failed: expected a JSON array.', true);

  const entries = parsed.filter(e => e && typeof e === 'object');
  if (entries.length === 0) return showStatus('Import failed: no entries found.', true);

  importGoBtn.disabled = true;
  let ok = 0;
  for (const entry of entries) {
    const res = await send('ADD_CREDENTIAL', entry);
    if (res.success) ok++;
  }
  importGoBtn.disabled = false;

  const failed = entries.length - ok;
  await load();
  if (failed === 0) setBackupMode('import'); // toggle the box back closed
  showStatus(`Imported ${ok} credential(s)${failed ? `, ${failed} failed` : ''}.`, failed > 0);
}

exportBtn.addEventListener('click', () => setBackupMode('export'));
importBtn.addEventListener('click', () => setBackupMode('import'));
importGoBtn.addEventListener('click', importVault);

window.addEventListener('unload', () => clearInterval(totpInterval));

load();
