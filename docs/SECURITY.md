# Security & Threat Model

## Defended Threats
- **SSRF**: `sendNotification` enforces the `https:` scheme, rejects credentials in URLs, and validates hostnames against an allow list (default: `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `web.push.apple.com`, `.notify.windows.com`).
- **Invalid-Curve & Point Attacks**: All P-256 public keys (VAPID, subscription, header) are validated as 65-byte uncompressed points and imported via WebCrypto, which verifies curve alignment (RFC 8291, Section 7).
- **Secret/Payload Leakage**: `WebPushError` truncates messages to 200 characters and omits cryptographic keys, tokens, auth secrets, and payloads. Telemetry events (`onEvent`) only emit `type`, `status`, `endpointHost`, and `errorCode`.
- **VAPID Token Expiry**: `createVapidAuthorization` enforces `expiresInSeconds <= 86_400` (24 hours) as per RFC 8292.
- **Unbounded Inputs**: Plaintext payloads are capped at 3,993 bytes to ensure the encrypted record fits within 4,096 bytes (RFC 8291, Section 4).

## Not Defended
- **DNS Rebinding**: Hostname validation occurs after DNS resolution; systems with untrusted resolvers require network egress controls.
- **At-Rest Security**: Applications must secure private keys and subscription data independently.
- **Push Service Metadata**: Push services inherently observe destination, payload size, TTL, Urgency, and Topic.