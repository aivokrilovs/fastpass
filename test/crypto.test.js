import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateMasterKey,
  encrypt,
  decrypt,
  normalizeBase32,
  isValidBase32,
  base32Decode,
  generateTOTP,
  getTOTPSecondsRemaining,
  generateRandomPassword
} from '../crypto.js';

test('Base32 normalization and validation', () => {
  assert.equal(normalizeBase32('jbsw y3dp-ehpk_3pxp==='), 'JBSWY3DPEHPK3PXP');
  assert.equal(isValidBase32('JBSWY3DPEHPK3PXP'), true);
  assert.equal(isValidBase32('jbsw y3dp ehpk 3pxp'), true);
  assert.equal(isValidBase32('INVALID890'), false);
  assert.equal(isValidBase32(''), false);
});

test('Base32 decoding throws on invalid characters', () => {
  assert.throws(() => base32Decode('JBSWY3D8'), /Invalid Base32 character: "8"/);
  assert.throws(() => base32Decode(''), /Base32 secret cannot be empty/);
});

test('TOTP RFC 6238 official test vectors (HMAC-SHA1, 30s period)', async () => {
  // Secret: ASCII "12345678901234567890" -> Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
  const secretB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  const testVectors = [
    { timeSec: 59, expected: '287082' },
    { timeSec: 1111111109, expected: '081804' },
    { timeSec: 1111111111, expected: '050471' },
    { timeSec: 1234567890, expected: '005924' },
    { timeSec: 2000000000, expected: '279037' }
  ];

  for (const { timeSec, expected } of testVectors) {
    const code = await generateTOTP(secretB32, timeSec * 1000);
    assert.equal(code, expected, `Failed for timestamp ${timeSec}`);
  }
});

test('AES-GCM encryption and decryption round-trip', async () => {
  const key = await generateMasterKey();

  const plain = 'correct-horse-battery-staple-!@#$%^';
  const enc = await encrypt(plain, key);
  assert.notEqual(enc.ciphertext, plain);
  assert.ok(enc.iv);

  const dec = await decrypt(enc.ciphertext, enc.iv, key);
  assert.equal(dec, plain);
});

test('Master key is not extractable (cannot be exported as raw bytes)', async () => {
  const key = await generateMasterKey();
  assert.equal(key.extractable, false);
  await assert.rejects(async () => await crypto.subtle.exportKey('raw', key));
});

test('AES-GCM decryption fails with tampered ciphertext', async () => {
  const key = await generateMasterKey();
  const enc = await encrypt('sensitive data', key);

  // Tamper with ciphertext by altering last character
  const tamperedCipher = enc.ciphertext.slice(0, -2) + 'AA';
  await assert.rejects(
    async () => await decrypt(tamperedCipher, enc.iv, key)
  );
});

test('Random password generator', () => {
  const p1 = generateRandomPassword(20);
  const p2 = generateRandomPassword(20);
  assert.equal(p1.length, 20);
  assert.equal(p2.length, 20);
  assert.notEqual(p1, p2);
  // Rejection sampling must still cover the whole alphabet, including its tail
  const long = generateRandomPassword(4000);
  for (const ch of '|;:,.<>?') {
    assert.ok(long.includes(ch), `alphabet character ${ch} never generated`);
  }
});

test('TOTP seconds remaining returns value between 1 and 30', () => {
  const rem = getTOTPSecondsRemaining(30);
  assert.ok(rem >= 1 && rem <= 30);
});
