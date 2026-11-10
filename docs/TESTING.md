# Testing

## Unit & Vector Tests (`test/index.test.ts`)
This file contains deterministic tests covering:
- **RFC 8291**: Full encryption/decryption cycles and intermediate HKDF derivations (IKM, CEK, NONCE) using the section 5 and Appendix A test vector constants.
- **RFC 8292**: VAPID JWT header, payload serialization (aud, exp, sub order), and ECDSA P-256 signature verification.
- **RFC 8030**: HTTP header validation (TTL, Urgency, Topic), HTTP status code mapping (201, 404, 410, 413, 429, 500, network error), and ensuring telemetry events sanitize all sensitive material.
- **Bounds**: Validations for input sizes, key lengths, and endpoint host allow lists.

## CI Conformance (`test/push.conformance.test.ts`)
This suite runs only in CI (`FABRICA_CI=1`) using Playwright to launch Chromium and Firefox. It tests end-to-end delivery of decrypted payloads to real browser-generated subscriptions.