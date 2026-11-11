# Architecture

`@trysac/web-push-server` is structured around four focused modules re-exported through `src/index.ts`:

1. **`src/errors.ts`**: Defines `WebPushError` and `WebPushErrorCode`. Enforces a 200-character message limit and strips newlines so no cryptographic material, tokens, or payloads ever appear in error messages.
2. **`src/base64url.ts`**: Unpadded base64url encoding and strict decoding (tolerating optional `=` padding while verifying canonical trailing bits).
3. **`src/crypto.ts`**: Implements RFC 8291 (`aes128gcm`) and RFC 8188 single-record framing:
   - ECDH P-256 shared secret derivation.
   - HKDF-SHA-256 extraction and expansion (`WebPush: info\0`, `Content-Encoding: aes128gcm\0`, `Content-Encoding: nonce\0`).
   - AES-128-GCM encryption and decryption with 86-byte header (`salt || rs=4096 || idlen=65 || as_public`).
4. **`src/vapid.ts`**: Implements RFC 8292 ES256 JWT generation (`{"typ":"JWT","alg":"ES256"}` and claims ordered `aud`, `exp`, `sub`) and `vapid t=<jwt>, k=<publicKey>` formatting.
5. **`src/send.ts`**: Implements RFC 8030 delivery over `fetch`, SSRF endpoint host allow-listing, header validation (`TTL`, `Urgency`, `Topic`), HTTP status mapping, and sanitized `onEvent` telemetry.
