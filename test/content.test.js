import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// content.js runs as a browser IIFE with no exports, so these are structural
// checks on the source. They exist to stop one specific regression coming back:
// the cheap "is there anything to fill here?" gate in executeAutofill being
// narrower than the fields the script actually fills. A 2FA-only page has no
// password input, so a password-only gate silently disables TOTP autofill.
const source = readFileSync(new URL('../content.js', import.meta.url), 'utf8');

test('autofill gate covers every field the finders fill', () => {
  const otp = source.match(/const OTP_SELECTOR = (\[[\s\S]*?\]);/);
  const username = source.match(/const USERNAME_SELECTOR = (\[[\s\S]*?\]);/);
  const gate = source.match(/const FILLABLE_SELECTOR = (.*);/);

  assert.ok(otp, 'OTP_SELECTOR must exist');
  assert.ok(username, 'USERNAME_SELECTOR must exist');
  assert.ok(gate, 'FILLABLE_SELECTOR must exist');

  // Gate must be assembled from the shared lists, not a hand-written subset
  assert.match(gate[1], /input\[type="password"\]/);
  assert.match(gate[1], /\.\.\.OTP_SELECTOR/);
  assert.match(gate[1], /\.\.\.USERNAME_SELECTOR/);

  // And every finder must query those same lists
  assert.match(source, /findTotpInput[\s\S]{0,120}OTP_SELECTOR\.join/);
});

test('early exit in executeAutofill uses the shared gate', () => {
  const body = source.match(/function executeAutofill\(\) \{[\s\S]*?\n  \}/)[0];
  assert.match(body, /if \(!document\.querySelector\(FILLABLE_SELECTOR\)\) return;/);
  // Guard against a literal selector list creeping back in
  assert.doesNotMatch(body, /querySelector\('input\[type=/);
});

test('filled and user-edited state are never written to the DOM', () => {
  // A data-* attribute on the input is readable by the page's own JavaScript
  assert.doesNotMatch(source, /dataset\.bpFilled/);
  assert.doesNotMatch(source, /dataset\.bpUserEdited/);
  assert.match(source, /const filledValues = new WeakMap\(\)/);
  assert.match(source, /const userEdited = new WeakSet\(\)/);
});

test('step-1 username autofill excludes OTP fields via shared filter', () => {
  assert.match(source, /function isOtpField\(input\) \{\s*return !!input && input\.matches\(OTP_SELECTOR\.join\(','\)\);/);
  assert.match(source, /function isFillableUsername\(input\) \{[\s\S]*?!isOtpField\(input\)/);
  assert.match(source, /else if \(username\) \{[\s\S]*?\.filter\(isFillableUsername\)/);
});

test('TOTP observer watches DOM reveal, not just insertion', () => {
  const observeCall = source.match(/observer\.observe\(document\.body, \{[\s\S]*?\}\);/)[0];
  // 2FA panels are often pre-rendered and revealed via class/style changes
  assert.match(observeCall, /attributeFilter: \['style', 'class', 'hidden'\]/);
});

test('stale TOTP codes are refreshed instead of filled', () => {
  assert.match(source, /function isTotpStale\(\)/);
  assert.match(source, /if \(cachedCredential\.totpCode && isTotpStale\(\)\)/);
});
