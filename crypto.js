/**
 * FastPass - Cryptography & TOTP Engine
 * Web Crypto API: AES-256-GCM and HMAC-SHA1 TOTP (RFC 6238)
 */

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Non-extractable AES-256-GCM key: raw bytes cannot be exported alongside ciphertext.
export function generateMasterKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(plainText, cryptoKey) {
  if (plainText == null) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoded);
  return {
    ciphertext: bytesToBase64(new Uint8Array(cipher)),
    iv: bytesToBase64(iv)
  };
}

export async function decrypt(ciphertextB64, ivB64, cryptoKey) {
  if (!ciphertextB64 || !ivB64) return null;
  const iv = base64ToBytes(ivB64);
  const cipher = base64ToBytes(ciphertextB64);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, cipher);
  return new TextDecoder().decode(plain);
}

export function normalizeBase32(str) {
  return typeof str === 'string' ? str.toUpperCase().replace(/[\s\-_=]/g, '') : '';
}

export function isValidBase32(str) {
  return /^[A-Z2-7]+$/.test(normalizeBase32(str));
}

export function base32Decode(str) {
  const clean = normalizeBase32(str);
  if (!clean) throw new Error('Base32 secret cannot be empty');

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const output = [];
  let bits = 0;
  let value = 0;

  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: "${ch}". Valid characters are A-Z and 2-7.`);
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

export async function generateTOTP(secretB32, timestamp = Date.now(), digits = 6, period = 30) {
  const keyBytes = base32Decode(secretB32);
  const counter = Math.floor(Math.floor(timestamp / 1000) / period);

  const counterBuf = new ArrayBuffer(8);
  new DataView(counterBuf).setBigUint64(0, BigInt(counter));

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, counterBuf));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % (10 ** digits)).padStart(digits, '0');
}

export function getTOTPSecondsRemaining(period = 30) {
  return period - (Math.floor(Date.now() / 1000) % period);
}

// Rejection sampling avoids modulo bias across the charset.
export function generateRandomPassword(length = 20) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  const limit = 256 - (256 % charset.length);
  let result = '';
  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length - result.length));
    for (const byte of bytes) {
      if (byte < limit) result += charset[byte % charset.length];
    }
  }
  return result;
}
