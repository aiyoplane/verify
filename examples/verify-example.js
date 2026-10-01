// Example: verify an Aiyo execution receipt programmatically.
//
// Run with: node examples/verify-example.js
//
// This example uses a v1 (HMAC) receipt so it works entirely offline without
// requiring a real JWKS endpoint. Production receipts (v2/Ed25519) work the
// same way but fetch the public key from Aiyo's JWKS URL automatically.

import { webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { verify } from '../src/index.js';

const HMAC_SECRET = 'local-development-secret';

// Build a v1 receipt inline so the example is self-contained.
async function makeExampleReceipt() {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iid: 'intent_example_001',
    cid: 'ctx_example',
    mid: 'mrch_example',
    iat: now,
    exp: now + 300, // 5 minutes
  };
  const payloadJson = JSON.stringify(claims);
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(payloadJson));

  const key = await webcrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(HMAC_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await webcrypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = base64UrlEncode(new Uint8Array(sig));

  return `v1.${payloadB64}.${sigB64}`;
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function main() {
  const receipt = await makeExampleReceipt();
  console.log('Verifying example receipt:');
  console.log(`  ${receipt.slice(0, 40)}...`);
  console.log();

  const result = await verify(receipt, { hmacSecret: HMAC_SECRET });
  console.log('✓ Receipt verified');
  console.log(`  version:     ${result.version}`);
  console.log(`  intent_id:   ${result.claims.iid}`);
  console.log(`  context_id:  ${result.claims.cid}`);
  console.log(`  merchant_id: ${result.claims.mid}`);
  console.log(`  issued_at:   ${new Date(result.claims.iat * 1000).toISOString()}`);
  console.log(`  expires_at:  ${new Date(result.claims.exp * 1000).toISOString()}`);
}

main().catch((err) => {
  console.error(`✗ ${err.message}`);
  process.exit(1);
});
