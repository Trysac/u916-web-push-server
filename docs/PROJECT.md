# Project Record

## Objective
To provide a secure, standard-compliant Web Push sender for Node.js 22+ and WebCrypto-compatible runtimes that avoids legacy cryptographic dependencies.

## Scope
- RFC 8030: Generic Event Delivery Using HTTP Push (delivery, headers, status mapping).
- RFC 8188: Encrypted Content-Encoding for HTTP (single-record framing).
- RFC 8291: Message Encryption for Web Push (ECDH/HKDF derivation).
- RFC 8292: Voluntary Application Server Identification (VAPID) for Web Push (ES256 authorization).
- Type definitions for push subscriptions, VAPID authentication, and delivery options.

## Out of Scope
- Legacy `aesgcm` encoding.
- Multiple-record payloads.
- Legacy FCM/GCM-specific key formats.
- Message queues or retry management beyond mapping `Retry-After` headers.
- Persistence or storage of subscription records.
- Browser-side client subscription logic (reserved for CI conformance tests only).

## Factory run u916 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | google/gemini-4-argon | yes | 7149 | 26782 | 0 | 0 | 0.5642 |
| 2026-11-10 | fix-1 | google/gemini-3.8-flash | no | 372927 | 3858 | 0 | 747699 | 0.3502 |
| 2026-11-10 | fix-2 | google/gemini-3.8-flash | no | 402948 | 3341 | 0 | 824620 | 0.3766 |
| 2026-11-10 | fix-3 | google/gemini-3.8-flash | no | 392880 | 998 | 0 | 663728 | 0.3482 |
| 2026-11-10 | fix-4 | google/gemini-3.8-flash | no | 547227 | 2679 | 0 | 803977 | 0.4808 |
| 2026-11-10 | docs | google/gemini-3.1-flash-lite | no | 27115 | 1462 | 0 | 0 | 0.0090 |

Total: $2.1290. Prices: vertex line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
