// @aiyoplane/verify — receipt verification core.
//
// Verifies Aiyo execution receipts in the v2 format:
//   v2.<base64url(payload_json)>.<base64url(ed25519_signature)>
//
// The payload is a JSON object with the claims:
//   { iid, cid, mid, exp, iat }
//     iid — intent ID (the specific action that was authorized)
//     cid — context ID (correlation across a broader flow, if applicable)
//     mid — merchant ID (which merchant's policy this decision was under)
//     exp — expiration timestamp (unix seconds); receipt is invalid after this
//     iat — issued-at timestamp (unix seconds)
//
// The signature is Ed25519, produced by Aiyo's active signing key. The public
// key is fetched from Aiyo's published JWKS (see jwks.js). Verification is
// entirely offline once the JWKS is cached — no round-trip to Aiyo at verify
// time.
//
// v1 receipts (HMAC-SHA256) are supported for local development and testing
// only, and require an explicit shared secret.

import { webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  ReceiptFormatError,
  ReceiptSignatureError,
  ReceiptExpiredError,
  UnsupportedVersionError,
} from './errors.js';
import { resolveKey, DEFAULT_JWKS_URL } from './jwks.js';

const crypto = webcrypto || globalThis.crypto;

// Recognised receipt version prefixes.
const V2 = 'v2';
const V1 = 'v1';

/**
 * Verify an Aiyo execution receipt.
 *
 * @param {string} receipt - The receipt string, prefixed with its version (e.g. "v2.…").
 * @param {object} [options]
 * @param {string} [options.jwksUrl] - Override the default JWKS URL.
 * @param {string} [options.hmacSecret] - Required for v1 HMAC receipts (local dev only).
 * @param {Date|number} [options.now] - Override the current time for expiration checks (testing).
 * @param {number} [options.clockSkewSeconds] - Tolerance for clock skew. Default 30 seconds.
 * @param {function} [options.fetchImpl] - Custom fetch implementation.
 * @returns {Promise<{valid: true, version: string, claims: object}>}
 * @throws {ReceiptFormatError|ReceiptSignatureError|ReceiptExpiredError|UnsupportedVersionError}
 */
export async function verify(receipt, options = {}) {
  return await verifyReceipt(receipt, options);
}

// Alias, kept because some integrators prefer the more explicit name.
export async function verifyReceipt(receipt, options = {}) {
  if (typeof receipt !== 'string' || receipt.length === 0) {
    throw new ReceiptFormatError('Receipt must be a non-empty string');
  }

  const parts = receipt.split('.');
  if (parts.length !== 3) {
    throw new ReceiptFormatError(`Receipt must have 3 dot-separated parts, got ${parts.length}`);
  }

  const [version, payloadB64, signatureB64] = parts;

  if (version === V2) {
    return await verifyV2(payloadB64, signatureB64, options);
  }
  if (version === V1) {
    return await verifyV1(payloadB64, signatureB64, options);
  }
  throw new UnsupportedVersionError(`Unsupported receipt version prefix "${version}". Expected "${V2}" or "${V1}".`);
}

// -----------------------------------------------------------------------------
// v2: Ed25519 with JWKS
// -----------------------------------------------------------------------------

async function verifyV2(payloadB64, signatureB64, options) {
  const payloadBytes = base64UrlDecode(payloadB64);
  const signatureBytes = base64UrlDecode(signatureB64);

  let claims;
  try {
    claims = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch (cause) {
    throw new ReceiptFormatError('v2 payload is not valid JSON', { cause });
  }

  validateClaims(claims);
  assertNotExpired(claims, options);

  // In v2, the signing key is identified either via a `kid` in the payload
  // (preferred, forward-compatible) or by using the JWKS's first Ed25519 key
  // as a default (permitted only if there is exactly one active Ed25519 key).
  const kid = typeof claims.kid === 'string' ? claims.kid : undefined;
  const jwksUrl = options.jwksUrl || DEFAULT_JWKS_URL;

  let jwk;
  if (kid) {
    jwk = await resolveKey(kid, jwksUrl, { fetchImpl: options.fetchImpl });
  } else {
    jwk = await resolveDefaultKey(jwksUrl, options);
  }

  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new ReceiptSignatureError(`Expected Ed25519 (OKP/Ed25519) key, got kty="${jwk.kty}" crv="${jwk.crv}"`);
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', x: jwk.x, ext: true },
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  // The signed payload is the raw bytes of the base64url-encoded payload as they
  // appear in the receipt string. Some implementations sign the decoded JSON
  // bytes; Aiyo's v2 spec signs the encoded segment for JWS-style compatibility.
  const signedBytes = new TextEncoder().encode(payloadB64);

  const ok = await crypto.subtle.verify('Ed25519', publicKey, signatureBytes, signedBytes);
  if (!ok) {
    throw new ReceiptSignatureError('v2 Ed25519 signature verification failed');
  }

  return { valid: true, version: V2, claims };
}

async function resolveDefaultKey(jwksUrl, options) {
  const { fetchJwks } = await import('./jwks.js');
  const keys = await fetchJwks(jwksUrl, { fetchImpl: options.fetchImpl });
  const ed25519Keys = Array.from(keys.values()).filter(
    (k) => k && k.kty === 'OKP' && k.crv === 'Ed25519',
  );
  if (ed25519Keys.length === 0) {
    throw new ReceiptSignatureError('No Ed25519 keys found in JWKS');
  }
  if (ed25519Keys.length > 1) {
    throw new ReceiptSignatureError(
      'JWKS contains multiple Ed25519 keys and receipt has no `kid` claim. Cannot pick a default.',
    );
  }
  return ed25519Keys[0];
}

// -----------------------------------------------------------------------------
// v1: HMAC-SHA256 (local development only)
// -----------------------------------------------------------------------------

async function verifyV1(payloadB64, signatureB64, options) {
  const payloadBytes = base64UrlDecode(payloadB64);
  const providedSignature = base64UrlDecode(signatureB64);

  let claims;
  try {
    claims = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch (cause) {
    throw new ReceiptFormatError('v1 payload is not valid JSON', { cause });
  }

  validateClaims(claims);
  assertNotExpired(claims, options);

  if (typeof options.hmacSecret !== 'string' || options.hmacSecret.length === 0) {
    throw new ReceiptSignatureError(
      'v1 receipts require options.hmacSecret. v1 is for local development only; production receipts should be v2 (Ed25519 + JWKS).',
    );
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(options.hmacSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  const signedBytes = new TextEncoder().encode(payloadB64);

  const ok = await crypto.subtle.verify('HMAC', key, providedSignature, signedBytes);
  if (!ok) {
    throw new ReceiptSignatureError('v1 HMAC-SHA256 signature verification failed');
  }

  return { valid: true, version: V1, claims };
}

// -----------------------------------------------------------------------------
// Claim + expiration validation
// -----------------------------------------------------------------------------

function validateClaims(claims) {
  if (!claims || typeof claims !== 'object') {
    throw new ReceiptFormatError('Receipt payload must be a JSON object');
  }
  for (const field of ['iid', 'mid', 'exp', 'iat']) {
    if (!(field in claims)) {
      throw new ReceiptFormatError(`Receipt payload missing required claim "${field}"`);
    }
  }
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) {
    throw new ReceiptFormatError('Claim "exp" must be a finite number (unix seconds)');
  }
  if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
    throw new ReceiptFormatError('Claim "iat" must be a finite number (unix seconds)');
  }
}

function assertNotExpired(claims, options) {
  const now = options.now
    ? (options.now instanceof Date ? options.now.getTime() : options.now)
    : Date.now();
  const skewMs = (options.clockSkewSeconds ?? 30) * 1000;
  const expiresMs = claims.exp * 1000;
  if (now > expiresMs + skewMs) {
    throw new ReceiptExpiredError(
      `Receipt expired at ${new Date(expiresMs).toISOString()} (now is ${new Date(now).toISOString()})`,
    );
  }
}

// -----------------------------------------------------------------------------
// base64url helpers
// -----------------------------------------------------------------------------

function base64UrlDecode(s) {
  if (typeof s !== 'string') {
    throw new ReceiptFormatError('Expected base64url-encoded string');
  }
  // Convert base64url to base64
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  try {
    return new Uint8Array(Buffer.from(padded, 'base64'));
  } catch (cause) {
    throw new ReceiptFormatError('Failed to base64url-decode receipt segment', { cause });
  }
}
