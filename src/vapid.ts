import { base64UrlEncode, toArrayBuffer } from "./base64url.js";
import {
  decodePrivateKeyBytes,
  decodePublicKeyBytes,
  generateP256KeyPair,
  importPrivateKey,
  importPublicKey,
  type KeyPair,
} from "./crypto.js";
import { WebPushError } from "./errors.js";

/**
 * Options for {@link createVapidAuthorization}.
 */
export interface CreateVapidAuthorizationOptions {
  /**
   * Origin of the push resource (for example `https://fcm.googleapis.com`).
   */
  readonly audience: string;
  /**
   * Application server contact URI (`mailto:` or `https:`).
   */
  readonly subject: string;
  /**
   * Application server VAPID P-256 key pair.
   */
  readonly keys: KeyPair;
  /**
   * Token lifetime in seconds from `clock()`. Defaults to `43_200` (12 hours). Maximum is `86_400` (24 hours).
   */
  readonly expiresInSeconds?: number;
  /**
   * Clock returning current Unix epoch time in milliseconds. Defaults to `Date.now`.
   */
  readonly clock?: () => number;
}

export const DEFAULT_VAPID_EXPIRES_IN_SECONDS = 43_200;
export const MAX_VAPID_EXPIRES_IN_SECONDS = 86_400;
const MAX_URI_LENGTH = 2_048;

const textEncoder = new TextEncoder();
// Fixed JWT header segment for {"typ":"JWT","alg":"ES256"}
const JWT_HEADER_SEGMENT = base64UrlEncode(textEncoder.encode('{"typ":"JWT","alg":"ES256"}'));

/**
 * Generates a fresh P-256 VAPID key pair.
 *
 * @returns A promise resolving to `{ publicKey, privateKey }` in unpadded base64url format.
 */
export async function generateVapidKeys(): Promise<KeyPair> {
  const { keyPair } = await generateP256KeyPair("ECDSA");
  return keyPair;
}

function validateAudience(audience: string): string {
  if (typeof audience !== "string" || audience.length === 0 || audience.length > MAX_URI_LENGTH) {
    throw new WebPushError("invalid_vapid", "VAPID audience must be a non-empty origin string");
  }
  let parsed: URL;
  try {
    parsed = new URL(audience);
  } catch (err) {
    throw new WebPushError("invalid_vapid", "VAPID audience is not a valid URL", { cause: err });
  }
  if (parsed.protocol !== "https:") {
    throw new WebPushError("invalid_vapid", "VAPID audience must use https: scheme");
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== "/" ||
    audience !== parsed.origin
  ) {
    throw new WebPushError(
      "invalid_vapid",
      "VAPID audience must be an origin without path or query",
    );
  }
  return parsed.origin;
}

function validateSubject(subject: string): string {
  if (typeof subject !== "string" || subject.length === 0 || subject.length > MAX_URI_LENGTH) {
    throw new WebPushError("invalid_vapid", "VAPID subject must be a non-empty URI");
  }
  if (!subject.startsWith("mailto:") && !subject.startsWith("https:")) {
    throw new WebPushError("invalid_vapid", "VAPID subject must start with mailto: or https:");
  }
  let parsed: URL;
  try {
    parsed = new URL(subject);
  } catch (err) {
    throw new WebPushError("invalid_vapid", "VAPID subject is not a valid URI", { cause: err });
  }
  if (parsed.protocol === "mailto:") {
    if (parsed.pathname.trim().length === 0 || !parsed.pathname.includes("@")) {
      throw new WebPushError(
        "invalid_vapid",
        "VAPID mailto: subject must contain an email address",
      );
    }
  } else if (parsed.protocol === "https:") {
    if (parsed.hostname.length === 0) {
      throw new WebPushError("invalid_vapid", "VAPID https: subject must contain a hostname");
    }
  }
  return subject;
}

/**
 * Creates an RFC 8292 `vapid` HTTP `Authorization` header value (`vapid t=<jwt>, k=<publicKey>`).
 *
 * @param opts - Audience, subject, VAPID key pair, optional expiration offset, and optional clock.
 * @returns Complete `Authorization` header string.
 * @throws {WebPushError} With code `'invalid_vapid'` if any option or key is invalid.
 */
export async function createVapidAuthorization(
  opts: CreateVapidAuthorizationOptions,
): Promise<string> {
  if (opts === null || typeof opts !== "object") {
    throw new WebPushError("invalid_vapid", "VAPID options object is required");
  }

  const aud = validateAudience(opts.audience);
  const sub = validateSubject(opts.subject);

  const expiresInSeconds = opts.expiresInSeconds ?? DEFAULT_VAPID_EXPIRES_IN_SECONDS;
  if (
    typeof expiresInSeconds !== "number" ||
    !Number.isInteger(expiresInSeconds) ||
    expiresInSeconds <= 0 ||
    expiresInSeconds > MAX_VAPID_EXPIRES_IN_SECONDS
  ) {
    throw new WebPushError(
      "invalid_vapid",
      `VAPID expiresInSeconds must be a positive integer at most ${MAX_VAPID_EXPIRES_IN_SECONDS}`,
    );
  }

  const clock = opts.clock ?? Date.now;
  if (typeof clock !== "function") {
    throw new WebPushError("invalid_vapid", "VAPID clock must be a function");
  }
  const nowMs = clock();
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs) || nowMs < 0) {
    throw new WebPushError("invalid_vapid", "VAPID clock returned an invalid timestamp");
  }
  const exp = Math.floor(nowMs / 1000) + expiresInSeconds;

  if (
    opts.keys === null ||
    typeof opts.keys !== "object" ||
    typeof opts.keys.publicKey !== "string" ||
    typeof opts.keys.privateKey !== "string"
  ) {
    throw new WebPushError("invalid_vapid", "VAPID keys must include publicKey and privateKey");
  }

  const publicBytes = decodePublicKeyBytes(opts.keys.publicKey, "invalid_vapid", "VAPID publicKey");
  const privateBytes = decodePrivateKeyBytes(
    opts.keys.privateKey,
    "invalid_vapid",
    "VAPID privateKey",
  );

  const publicKeyCrypto = await importPublicKey(publicBytes, "ECDSA", ["verify"], "invalid_vapid");
  const privateKeyCrypto = await importPrivateKey(
    publicBytes,
    privateBytes,
    "ECDSA",
    ["sign"],
    "invalid_vapid",
  );

  // Serialise claims in exact order: aud, exp, sub
  const payloadJson = `{"aud":${JSON.stringify(aud)},"exp":${exp},"sub":${JSON.stringify(sub)}}`;
  const payloadSegment = base64UrlEncode(textEncoder.encode(payloadJson));
  const signingInput = `${JWT_HEADER_SEGMENT}.${payloadSegment}`;
  const signingInputBytes = textEncoder.encode(signingInput);

  let signatureBuffer: ArrayBuffer;
  try {
    signatureBuffer = await globalThis.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKeyCrypto,
      toArrayBuffer(signingInputBytes),
    );
  } catch (err) {
    throw new WebPushError("invalid_vapid", "Failed to sign VAPID JWT", { cause: err });
  }

  // Verify that the private scalar matches the public point
  const verified = await globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKeyCrypto,
    signatureBuffer,
    toArrayBuffer(signingInputBytes),
  );
  if (!verified) {
    throw new WebPushError("invalid_vapid", "VAPID publicKey and privateKey do not match");
  }

  const signatureSegment = base64UrlEncode(new Uint8Array(signatureBuffer));
  const jwt = `${signingInput}.${signatureSegment}`;
  const canonicalPublicKey = base64UrlEncode(publicBytes);

  return `vapid t=${jwt}, k=${canonicalPublicKey}`;
}
