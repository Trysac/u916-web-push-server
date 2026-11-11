# Use platform WebCrypto and standard fetch with zero runtime dependencies

Status: accepted (generated, pending human review)

## Context

Web Push servers require P-256 ECDH key agreement, HKDF-SHA-256 key derivation, AES-128-GCM authenticated encryption (RFC 8291), P-256 ECDSA JWT signing (RFC 8292), and HTTPS POST delivery (RFC 8030). Existing packages pull in legacy Node crypto helpers and third-party JWT libraries.

## Decision

Implement all cryptographic operations directly on `globalThis.crypto.subtle` and HTTP delivery on standard `fetch` (injectable for testing), with zero runtime dependencies and Playwright scoped strictly as a dev dependency for CI conformance testing.

## Consequences

The library runs unchanged on Node.js 22+ and modern WebCrypto runtimes with no supply-chain exposure at runtime, enforces curve validation via WebCrypto key imports, and proves correctness against RFC 8291 and RFC 8292 test vectors.
