// JWKS fetch + in-memory cache.
//
// Aiyo publishes its Ed25519 public keys at a standard JWKS URL. This module:
//   1. Fetches the JWKS on first use.
//   2. Caches keys in-memory (respecting Cache-Control headers where present).
//   3. Refreshes on demand if verification fails against the current cache
//      (which handles key rotation gracefully).
//
// The default JWKS URL points at Aiyo's production endpoint but is overridable
// for testing or for verifying receipts issued by a self-hosted Aiyo instance.

import { JwksFetchError, UnknownKeyError } from './errors.js';

export const DEFAULT_JWKS_URL = 'https://api.aiyoplane.com/.well-known/aiyo-jwks.json';

// In-memory JWKS cache keyed by URL.
// Structure: Map<url, { keys: Map<kid, key>, fetchedAt: ms, ttl: ms }>
const CACHE = new Map();

// Default TTL when the server doesn't set a Cache-Control max-age.
const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Fetch the JWKS from the given URL (or the Aiyo default) and cache it.
 * If the URL is already cached and not expired, returns the cached copy.
 * Pass { forceRefresh: true } to bypass the cache.
 */
export async function fetchJwks(url = DEFAULT_JWKS_URL, { forceRefresh = false, fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new JwksFetchError('No fetch implementation available. Use Node >= 18 or pass a fetchImpl.');
  }

  const now = Date.now();
  const cached = CACHE.get(url);
  if (!forceRefresh && cached && (now - cached.fetchedAt) < cached.ttl) {
    return cached.keys;
  }

  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers: { 'Accept': 'application/jwk-set+json, application/json' },
    });
  } catch (cause) {
    throw new JwksFetchError(`Failed to fetch JWKS from ${url}: ${cause.message}`, { cause });
  }

  if (!response.ok) {
    throw new JwksFetchError(`JWKS fetch returned HTTP ${response.status} from ${url}`);
  }

  let body;
  try {
    body = await response.json();
  } catch (cause) {
    throw new JwksFetchError(`JWKS response was not valid JSON: ${cause.message}`, { cause });
  }

  if (!body || !Array.isArray(body.keys)) {
    throw new JwksFetchError('JWKS response missing required "keys" array');
  }

  // Build a { kid -> jwk } map for O(1) lookup by key ID.
  const keyMap = new Map();
  for (const jwk of body.keys) {
    if (jwk && typeof jwk.kid === 'string') {
      keyMap.set(jwk.kid, jwk);
    }
  }

  // Respect the server's Cache-Control max-age if present.
  const cacheControl = response.headers?.get?.('cache-control') || '';
  const maxAgeMatch = /max-age=(\d+)/i.exec(cacheControl);
  const ttl = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) * 1000 : DEFAULT_TTL_MS;

  CACHE.set(url, { keys: keyMap, fetchedAt: now, ttl });
  return keyMap;
}

/**
 * Resolve a specific key by kid. Fetches the JWKS if not cached, and refreshes
 * the cache once if the requested kid is not present (handles key rotation).
 */
export async function resolveKey(kid, url = DEFAULT_JWKS_URL, opts = {}) {
  let keys = await fetchJwks(url, opts);
  if (!keys.has(kid)) {
    // Key rotation may have added a new kid we don't have cached. Refresh once.
    keys = await fetchJwks(url, { ...opts, forceRefresh: true });
  }
  const jwk = keys.get(kid);
  if (!jwk) {
    throw new UnknownKeyError(`No JWK found for kid="${kid}" in ${url}`);
  }
  return jwk;
}

/**
 * Clear the in-memory JWKS cache. Useful in tests, or to force a fresh fetch
 * on the next verification.
 */
export function clearJwksCache(url) {
  if (url) {
    CACHE.delete(url);
  } else {
    CACHE.clear();
  }
}
