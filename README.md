# @aiyoplane/verify

**Offline Ed25519 verifier for Aiyo execution receipts.**

Aiyo issues cryptographically-signed **execution receipts** at the moment it authorizes a consequential action. Every receipt is verifiable offline against Aiyo's published JWKS — no round-trip to Aiyo required at verification time, no Aiyo-side infrastructure needed. This package is that verifier.

Aiyoplane, Inc. · Apache 2.0 licensed · [aiyoplane.com](https://aiyoplane.com)

---

## Install

The fastest way to verify a receipt is with `npx` — no install required:

```sh
npx @aiyoplane/verify path/to/receipt.txt
```

To install globally as `aiyo-verify`:

```sh
npm install -g @aiyoplane/verify
```

To use programmatically in a Node project:

```sh
npm install @aiyoplane/verify
```

Requires Node.js 18 or newer.

---

## Command-line usage

```sh
# Verify a receipt from a file
npx @aiyoplane/verify receipt.txt

# Verify a receipt passed inline
npx @aiyoplane/verify --receipt "v2.eyJpaWQiOiJpbnRlbnRfMTIz...Q.MEQCIH...IDA"

# Read from stdin
cat receipt.txt | npx @aiyoplane/verify -

# Emit JSON for machine consumption
npx @aiyoplane/verify --json receipt.txt

# Override the JWKS URL (e.g., for self-hosted Aiyo)
npx @aiyoplane/verify --jwks-url https://api.example.com/.well-known/aiyo-jwks.json receipt.txt
```

**Exit codes:**
- `0` — receipt verified successfully
- `1` — receipt invalid (bad signature, expired, malformed, unknown key)
- `2` — usage error (missing input, unrecognized flag, etc.)

**Example output (human-readable):**

```
✓ Valid receipt (v2)
  intent_id:   intent_abc123
  context_id:  ctx_xyz789
  merchant_id: mrch_aiyoplane
  issued_at:   2026-09-28T14:22:31.000Z
  expires_at:  2026-09-28T14:27:31.000Z
```

**Example output (`--json`):**

```json
{
  "valid": true,
  "version": "v2",
  "claims": {
    "iid": "intent_abc123",
    "cid": "ctx_xyz789",
    "mid": "mrch_aiyoplane",
    "iat": 1727533351,
    "exp": 1727533651
  }
}
```

---

## Programmatic usage

```js
import { verify } from '@aiyoplane/verify';

const receipt = 'v2.eyJpaWQiOiJpbnRlbnRfMTIz...Q.MEQCIH...IDA';

try {
  const { claims } = await verify(receipt);
  console.log(`Authorized action ${claims.iid} for merchant ${claims.mid}`);
  console.log(`Receipt valid until ${new Date(claims.exp * 1000).toISOString()}`);
} catch (err) {
  console.error(`Receipt failed verification: ${err.message} (${err.code})`);
}
```

### Options

```js
await verify(receipt, {
  // Override the JWKS URL (default: https://api.aiyoplane.com/.well-known/aiyo-jwks.json)
  jwksUrl: 'https://api.example.com/.well-known/aiyo-jwks.json',

  // Required for v1 HMAC receipts (local development only)
  hmacSecret: process.env.AIYO_HMAC_SECRET,

  // Override "now" for expiration checks (useful in tests)
  now: new Date('2026-09-28T14:24:00Z'),

  // Clock skew tolerance in seconds (default: 30)
  clockSkewSeconds: 60,

  // Provide a custom fetch (useful for behind-a-proxy or in tests)
  fetchImpl: myFetch,
});
```

### Typed errors

Every verification failure throws a typed error. Handle specific failure modes distinctly:

```js
import {
  verify,
  ReceiptFormatError,
  ReceiptSignatureError,
  ReceiptExpiredError,
  JwksFetchError,
  UnknownKeyError,
  UnsupportedVersionError,
} from '@aiyoplane/verify';

try {
  await verify(receipt);
} catch (err) {
  if (err instanceof ReceiptExpiredError) {
    // Receipt was validly signed but has expired
  } else if (err instanceof ReceiptSignatureError) {
    // Signature did not verify — possible tampering or key mismatch
  } else if (err instanceof JwksFetchError) {
    // Could not reach the JWKS endpoint — treat as a transient failure and retry
  } else {
    // Everything else — malformed receipt, unknown kid, unsupported version
  }
}
```

---

## Receipt format

Aiyo receipts are strings of the form:

```
v2.<base64url(payload_json)>.<base64url(ed25519_signature)>
```

The payload is a JSON object with these required claims:

| Claim | Type | Meaning |
|---|---|---|
| `iid` | string | Intent ID — the specific action this receipt authorized |
| `mid` | string | Merchant ID — whose policy this decision was under |
| `exp` | number | Expiration timestamp (unix seconds) |
| `iat` | number | Issued-at timestamp (unix seconds) |
| `cid` | string | Context ID — correlation across a broader flow (optional) |
| `kid` | string | Key ID — which JWKS key was used to sign (optional; JWKS default used if absent) |

The signature is Ed25519 over the base64url-encoded payload segment (JWS-style compact signing).

The v1 format (`v1.…`) uses HMAC-SHA256 with a shared secret and is intended for local development / in-process use only. Production receipts should always be v2.

---

## JWKS

The default JWKS URL is:

```
https://api.aiyoplane.com/.well-known/aiyo-jwks.json
```

This URL serves the current Aiyo signing key(s) as a standard [RFC 7517 JWK Set](https://datatracker.ietf.org/doc/html/rfc7517). Keys are cached in-memory (respecting `Cache-Control: max-age` where present, defaulting to 10 minutes). If a receipt references a `kid` not in the cache, the JWKS is automatically refreshed once — handling key rotation gracefully.

To verify receipts issued by a self-hosted Aiyo instance, pass `--jwks-url` (CLI) or `jwksUrl` (programmatic).

To force a fresh JWKS fetch in a long-running process:

```js
import { clearJwksCache, fetchJwks } from '@aiyoplane/verify';

clearJwksCache();
await fetchJwks(); // Refetches from the default URL
```

---

## Why offline verification matters

Third parties — auditors, downstream systems, merchants' own compliance tooling — can verify Aiyo receipts without depending on Aiyo being available at verification time. The receipt is a **portable, independently-verifiable artifact**. That's the property that makes Aiyo's authorization decision durable across systems, and it's the property this package makes trivial to use.

For the broader architectural context, see the [DMARC precedent post](https://aiyoplane.com/blog/aiyo-dmarc-precedent) and the [MCP-authz reference implementation](https://github.com/aiyoplane/mcp-authz).

---

## About Aiyo

Aiyo is the settlement-verified Economic Execution Authorization plane for autonomous systems. Its Runtime Decision Point verifies that settlement actually occurred on a real rail, evaluates merchant policy, and issues a portable authorization artifact that unlocks the action a payment — or any qualifying condition — was supposed to enable. **Verify First. Execute Second.**

[aiyoplane.com](https://aiyoplane.com)

---

## License

Apache License 2.0 © 2026 Aiyoplane, Inc. — see `LICENSE` and `NOTICE`.
