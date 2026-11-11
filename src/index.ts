/**
 * `@trysac/web-push-server` — Web Push sender built on WebCrypto.
 *
 * Implements RFC 8291 (`aes128gcm` message encryption), RFC 8292 (VAPID ES256
 * authorization), and RFC 8030 (HTTP delivery and error mapping) with zero
 * runtime dependencies.
 */

export {
  DEFAULT_MAX_PAYLOAD_BYTES,
  type DerivedKeyMaterial,
  decryptPayload,
  deriveWebPushKeys,
  type EncryptPayloadOptions,
  encryptPayload,
  type KeyPair,
  type ReceiverKeys,
  type Subscription,
} from "./crypto.js";
export {
  WebPushError,
  type WebPushErrorCode,
  type WebPushErrorOptions,
} from "./errors.js";
export {
  DEFAULT_ENDPOINT_HOSTS,
  DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS,
  type PushUrgency,
  type SendNotificationOptions,
  type SendNotificationResult,
  sendNotification,
  type WebPushEvent,
} from "./send.js";
export {
  type CreateVapidAuthorizationOptions,
  createVapidAuthorization,
  DEFAULT_VAPID_EXPIRES_IN_SECONDS,
  generateVapidKeys,
  MAX_VAPID_EXPIRES_IN_SECONDS,
} from "./vapid.js";
