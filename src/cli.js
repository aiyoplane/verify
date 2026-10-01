#!/usr/bin/env node
// CLI entry point for @aiyoplane/verify.
//
// Usage:
//   npx @aiyoplane/verify <receipt-file>
//   npx @aiyoplane/verify --receipt "<receipt-string>"
//   cat receipt.txt | npx @aiyoplane/verify -
//
// Options:
//   --jwks-url <url>        Override the default JWKS URL
//   --hmac-secret <secret>  Required for v1 HMAC receipts (local dev only)
//   --json                  Emit machine-readable JSON output (default: human-readable)
//   --help                  Show help
//   --version               Show version
//
// Exit codes:
//   0 — receipt verified
//   1 — receipt invalid (bad signature, expired, malformed, unknown key)
//   2 — usage error

import { readFile } from 'node:fs/promises';
import { verifyReceipt } from './verify.js';
import { AiyoVerifyError } from './errors.js';

const HELP = `@aiyoplane/verify — Offline Ed25519 verifier for Aiyo execution receipts

Usage:
  npx @aiyoplane/verify <receipt-file>
  npx @aiyoplane/verify --receipt "<receipt-string>"
  cat receipt.txt | npx @aiyoplane/verify -

Options:
  --jwks-url <url>        Override the default JWKS URL
                          Default: https://api.aiyoplane.com/.well-known/aiyo-jwks.json
  --hmac-secret <secret>  Required for v1 HMAC receipts (local development only)
  --json                  Emit machine-readable JSON output
  --help                  Show this help
  --version               Show version

Exit codes:
  0  Receipt verified successfully
  1  Receipt invalid (bad signature, expired, malformed, unknown key)
  2  Usage error
`;

async function main(argv) {
  const args = parseArgs(argv);

  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }

  if (args.version) {
    const pkg = await loadPackageJson();
    process.stdout.write(`${pkg.version}\n`);
    return 0;
  }

  let receipt;
  try {
    receipt = await readReceipt(args);
  } catch (err) {
    return usageError(err.message);
  }

  try {
    const result = await verifyReceipt(receipt, {
      jwksUrl: args.jwksUrl,
      hmacSecret: args.hmacSecret,
    });
    if (args.json) {
      process.stdout.write(JSON.stringify({ valid: true, version: result.version, claims: result.claims }, null, 2) + '\n');
    } else {
      process.stdout.write(`✓ Valid receipt (${result.version})\n`);
      process.stdout.write(`  intent_id:   ${result.claims.iid}\n`);
      if (result.claims.cid) process.stdout.write(`  context_id:  ${result.claims.cid}\n`);
      process.stdout.write(`  merchant_id: ${result.claims.mid}\n`);
      process.stdout.write(`  issued_at:   ${new Date(result.claims.iat * 1000).toISOString()}\n`);
      process.stdout.write(`  expires_at:  ${new Date(result.claims.exp * 1000).toISOString()}\n`);
    }
    return 0;
  } catch (err) {
    if (args.json) {
      const body = { valid: false, error: err.message };
      if (err instanceof AiyoVerifyError && err.code) body.code = err.code;
      process.stderr.write(JSON.stringify(body, null, 2) + '\n');
    } else {
      process.stderr.write(`✗ Verification failed: ${err.message}\n`);
      if (err instanceof AiyoVerifyError && err.code) {
        process.stderr.write(`  (${err.code})\n`);
      }
    }
    return 1;
  }
}

function parseArgs(argv) {
  const args = { positional: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--version' || a === '-v') args.version = true;
    else if (a === '--json') args.json = true;
    else if (a === '--jwks-url') args.jwksUrl = argv[++i];
    else if (a === '--hmac-secret') args.hmacSecret = argv[++i];
    else if (a === '--receipt') args.receipt = argv[++i];
    else args.positional.push(a);
  }
  return args;
}

async function readReceipt(args) {
  if (args.receipt) return args.receipt.trim();
  const first = args.positional[0];
  if (first === '-') {
    return (await readStdin()).trim();
  }
  if (first) {
    const content = await readFile(first, 'utf8');
    return content.trim();
  }
  throw new Error('No receipt provided. Pass a filename, use --receipt "<string>", or pipe via stdin ("-").');
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function loadPackageJson() {
  const url = new URL('../package.json', import.meta.url);
  const content = await readFile(url, 'utf8');
  return JSON.parse(content);
}

function usageError(message) {
  process.stderr.write(`Error: ${message}\n\n${HELP}`);
  return 2;
}

main(process.argv).then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`Unexpected error: ${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  },
);
