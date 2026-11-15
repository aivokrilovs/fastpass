# FastPass

Minimal zero-click password and TOTP autofill extension for Chromium based browsers.

![demo](https://files.fatbox.moe/iy5z3b.gif)

## Features
- **0-click autofill:** Automatically detects and fills username, password, and 2FA OTP input fields on matching domains immediately upon page load or dynamic form render (SPAs, React modals)
- **Globbing:** Comma seperated domain matching with wildcard support (e.g. exam\*ple.com,\*.example.com)
- **TOTP support:** Accepts user Base32 keys, auto-fills 6-digit codes into 2FA fields, and displays live codes with countdown timers in the popup
- **Secure-ish storage:**
  - No master password (per 0-click requirement)
  - All passwords and TOTP secrets encrypted with AES-256-GCM
  - Master key is a non-extractable `CryptoKey` stored in IndexedDB
  - Autofill only runs on https pages and localhost
  - Websites cannot access extension storage or trigger cross-domain lookups
  - Background service worker verifies `sender.url`, and vault management actions are restricted to the extension's own pages
  - Isolated content script execution; no `externally_connectable` or `web_accessible_resources`
  - Top-level frame restriction protects against invisible iframe clickjacking
- **Minimal GUI** for adding, viewing, copying, and deleting credentials
- **<100KiB** ignoring tests/extension metadata

## Installation
1. Open your browser and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in upper right)
3. Click **Load unpacked**
4. Select the directory containing `manifest.json`
