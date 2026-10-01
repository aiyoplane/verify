// Basic tests for @aiyoplane/verify.
// Run with: node --test test/

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  verify,
  ReceiptFormatError,
  ReceiptSignatureError,
  ReceiptExpiredError,
  UnsupportedVersionError,
} from '../src/index.js';

const HMAC_SECRET = 'test-secret-do-not-use-in-production';

function base64UrlEncode(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function makeV1Receipt(claims, secret = HMAC_SECRET) {
  const payloadJson = JSON.stringify(claims);
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(payloadJson));
  const key = await webcrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await webcrypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = base64UrlEncode(new Uint8Array(sig));
  return `v1.${payloadB64}.${sigB64}`;
}

const NOW = Math.floor(Date.now() / 1000);
const VALID_CLAIMS = {
  iid: 'intent_test_001',
  mid: 'mrch_test',
  iat: NOW,
  exp: NOW + 300,
};

test('verify returns valid=true for a well-formed v1 receipt', async () => {
  const receipt = await makeV1Receipt(VALID_CLAIMS);
  const result = await verify(receipt, { hmacSecret: HMAC_SECRET });
  assert.equal(result.valid, true);
  assert.equal(result.version, 'v1');
  assert.equal(result.claims.iid, 'intent_test_001');
});

test('verify throws ReceiptFormatError for a non-string receipt', async () => {
  await assert.rejects(() => verify(null, { hmacSecret: HMAC_SECRET }), ReceiptFormatError);
});

test('verify throws ReceiptFormatError for a receipt missing parts', async () => {
  await assert.rejects(() => verify('v1.onlyonepart', { hmacSecret: HMAC_SECRET }), ReceiptFormatError);
});

test('verify throws UnsupportedVersionError for an unknown version', async () => {
  await assert.rejects(() => verify('v9.abc.def', { hmacSecret: HMAC_SECRET }), UnsupportedVersionError);
});

test('verify throws ReceiptSignatureError when v1 signature is wrong', async () => {
  const receipt = await makeV1Receipt(VALID_CLAIMS);
  // Tamper with the signature segment.
  const parts = receipt.split('.');
  const tampered = `${parts[0]}.${parts[1]}.${base64UrlEncode(new Uint8Array(32))}`;
  await assert.rejects(() => verify(tampered, { hmacSecret: HMAC_SECRET }), ReceiptSignatureError);
});

test('verify throws ReceiptSignatureError when v1 is verified with wrong secret', async () => {
  const receipt = await makeV1Receipt(VALID_CLAIMS);
  await assert.rejects(() => verify(receipt, { hmacSecret: 'wrong-secret' }), ReceiptSignatureError);
});

test('verify throws ReceiptExpiredError when receipt has expired', async () => {
  const expired = { ...VALID_CLAIMS, iat: NOW - 600, exp: NOW - 300 };
  const receipt = await makeV1Receipt(expired);
  await assert.rejects(() => verify(receipt, { hmacSecret: HMAC_SECRET }), ReceiptExpiredError);
});

test('verify honors clock skew tolerance', async () => {
  const expired = { ...VALID_CLAIMS, iat: NOW - 60, exp: NOW - 10 };
  const receipt = await makeV1Receipt(expired);
  // With generous skew tolerance, should still pass.
  const result = await verify(receipt, { hmacSecret: HMAC_SECRET, clockSkewSeconds: 60 });
  assert.equal(result.valid, true);
});

test('verify throws ReceiptSignatureError when v1 has no hmacSecret', async () => {
  const receipt = await makeV1Receipt(VALID_CLAIMS);
  await assert.rejects(() => verify(receipt), ReceiptSignatureError);
});

test('verify throws ReceiptFormatError when payload is missing required claims', async () => {
  const incomplete = { iid: 'intent_test', mid: 'mrch_test' };
  const receipt = await makeV1Receipt(incomplete);
  await assert.rejects(() => verify(receipt, { hmacSecret: HMAC_SECRET }), ReceiptFormatError);
});
