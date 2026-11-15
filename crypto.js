/**
 * FastPass - Cryptography & TOTP Engine
 * Standard Web Crypto API (AES-GCM-256, HMAC-SHA1 RFC 6238)
 */

// Base64 helpers
export function bytesToBase64(bytes) {
  let bin = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

// Generate random AES-256-GCM master key.
// Non-extractable: the browser will never hand the key out as raw bytes, so it
// cannot be copied into plaintext storage alongside the vault.
export async function generateMasterKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt plaintext string using AES-GCM-256
export async function encrypt(plainText, cryptoKey) {
  if (plainText === null || plainText === undefined) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    encoded
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(cipherBuffer)),
    iv: bytesToBase64(iv)
  };
}

// Decrypt ciphertext using AES-GCM-256
export async function decrypt(ciphertextB64, ivB64, cryptoKey) {
  if (!ciphertextB64 || !ivB64) return null;
  const iv = base64ToBytes(ivB64);
  const cipherBytes = base64ToBytes(ciphertextB64);
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    cipherBytes
  );
  return new TextDecoder().decode(decryptedBuffer);
}

// Normalize Base32 input (remove spaces, hyphens, lowercase)
export function normalizeBase32(str) {
  if (!str || typeof str !== 'string') return '';
  return str.toUpperCase().replace(/[\s\-_=]/g, '');
}

// Validate Base32 string (RFC 4648: A-Z, 2-7)
export function isValidBase32(str) {
  const clean = normalizeBase32(str);
  if (!clean || clean.length === 0) return false;
  return /^[A-Z2-7]+$/.test(clean);
}

// Decode RFC 4648 Base32 string into Uint8Array
export function base32Decode(str) {
  const clean = normalizeBase32(str);
  if (!clean || clean.length === 0) {
    throw new Error('Base32 secret cannot be empty');
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: "${clean[i]}". Valid characters are A-Z and 2-7.`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

// Generate RFC 6238 TOTP 6-digit code
export async function generateTOTP(secretB32, timestamp = Date.now(), digits = 6, period = 30) {
  const keyBytes = base32Decode(secretB32);
  const epoch = Math.floor(timestamp / 1000);
  const counter = Math.floor(epoch / period);

  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // Big-endian 64-bit integer
  view.setBigUint64(0, BigInt(counter));

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
  const hmac = new Uint8Array(sig);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const modulo = Math.pow(10, digits);
  return (binary % modulo).toString().padStart(digits, '0');
}

// Remaining seconds in current TOTP 30s window (1 to 30)
export function getTOTPSecondsRemaining(period = 30) {
  const epoch = Math.floor(Date.now() / 1000);
  return period - (epoch % period);
}

// Generate strong random password (rejection sampling: no modulo bias)
export function generateRandomPassword(length = 20) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  const limit = 256 - (256 % charset.length); // bytes >= limit are discarded
  let result = '';
  while (result.length < length) {
    const randomBytes = crypto.getRandomValues(new Uint8Array(length - result.length));
    for (const byte of randomBytes) {
      if (byte < limit) result += charset[byte % charset.length];
    }
  }
  return result;
}
