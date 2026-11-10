# @trysac/web-push-server

Servers that send browser notifications must encrypt every payload, sign a VAPID token, and correctly map HTTP errors for cleanup. Getting the crypto derivation or record padding wrong leads to silently dropped messages, and common alternatives rely on legacy dependencies. This utility implements RFC 8291, RFC 8292, and RFC 8030 using standard WebCrypto (globalThis.crypto.subtle) and fetch, with zero runtime dependencies.

## Installation

```bash
npm install @trysac/web-push-server
```

## Usage

```ts
import { generateVapidKeys, sendNotification } from "@trysac/web-push-server";

const keys = await generateVapidKeys();
const sub = {
  endpoint: "https://fcm.googleapis.com/fcm/send/example",
  keys: { p256dh: "<base64url>", auth: "<base64url>" },
};
await sendNotification(sub, "Hello!", { vapid: { subject: "mailto:me@example.com", keys } });
```

## API Summary

- **Crypto**: `encryptPayload`, `decryptPayload`, `deriveWebPushKeys`.
- **VAPID**: `generateVapidKeys`, `createVapidAuthorization`.
- **Delivery**: `sendNotification`.
- **Error Handling**: `WebPushError` handles 404/410 (`subscription_gone`), 413 (`payload_too_large`), 429 (`rate_limited`), and 5xx (`push_service_error`) status codes.

## Why not `web-push`?

Popular alternatives require legacy Node.js cryptographic libraries and third-party JWT dependencies. This utility is built on platform-native WebCrypto, maintains zero runtime dependencies, and verifies its implementation directly against the RFC 8291 and RFC 8292 published test vectors.

## Security

[Security & Threat Model](docs/SECURITY.md)