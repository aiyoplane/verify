// Typed errors for @aiyoplane/verify.
// Every verification failure throws one of these — never a generic Error.
// This lets integrators handle specific failure modes distinctly.

export class AiyoVerifyError extends Error {
  constructor(message, { code, cause } = {}) {
    super(message);
    this.name = 'AiyoVerifyError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

export class ReceiptFormatError extends AiyoVerifyError {
  constructor(message, opts) {
    super(message, { code: 'RECEIPT_FORMAT', ...opts });
    this.name = 'ReceiptFormatError';
  }
}

export class ReceiptSignatureError extends AiyoVerifyError {
  constructor(message, opts) {
    super(message, { code: 'SIGNATURE_INVALID', ...opts });
    this.name = 'ReceiptSignatureError';
  }
}

export class ReceiptExpiredError extends AiyoVerifyError {
  constructor(message, opts) {
    super(message, { code: 'RECEIPT_EXPIRED', ...opts });
    this.name = 'ReceiptExpiredError';
  }
}

export class JwksFetchError extends AiyoVerifyError {
  constructor(message, opts) {
    super(message, { code: 'JWKS_FETCH', ...opts });
    this.name = 'JwksFetchError';
  }
}

export class UnknownKeyError extends AiyoVerifyError {
  constructor(message, opts) {
    super(message, { code: 'UNKNOWN_KEY', ...opts });
    this.name = 'UnknownKeyError';
  }
}

export class UnsupportedVersionError extends AiyoVerifyError {
  constructor(message, opts) {
    super(message, { code: 'UNSUPPORTED_VERSION', ...opts });
    this.name = 'UnsupportedVersionError';
  }
}
