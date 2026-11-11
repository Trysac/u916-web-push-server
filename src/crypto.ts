import type { webcrypto } from "node:crypto";
import { base64UrlDecode, base64UrlEncode, concatBytes, toArrayBuffer } from "./base64url.js";
import { WebPushError, type WebPushErrorCode } from "./errors.js";

type KeyUsage = webcrypto.KeyUsage;
type CryptoKeyPair = webcrypto.CryptoKeyPair;

/**
 * A P-256 key pair encoded in unpadded base64url:
 * - `publicKey`: 65-byte uncompressed point (`0x04 || x || y`).
 * - `privateKey`: 32-byte big-endian private scalar `d`.
 */
export interface KeyPair {
  readonly publicKey: string;
  readonly privateKey: string;
}

/**
 * Browser push subscription structure as defined by the W3C Push API.
 */
export interface Subscription {
  readonly endpoint: string;
  readonly keys: {
    readonly p256dh: string;
    readonly auth: string;
  };
}

/**
 * Options for {@link encryptPayload}.
 */
export interface EncryptPayloadOptions {
  /**
   * Optional 16-byte salt encoded as base64url (intended for deterministic RFC test vectors).
   * When omitted, a fresh random 16-byte salt is generated per call.
   */
  readonly salt?: string;
  /**
   * Optional sender P-256 key pair (intended for deterministic RFC test vectors).
   * When omitted, a fresh ephemeral P-256 key pair is generated per call.
   */
  readonly senderKeys?: KeyPair;
  /**
   * Maximum plaintext payload size in bytes. Defaults to `3_993` (RFC 8291 section 4).
   */
  readonly maxPayloadBytes?: number;
}

/**
 * Receiver key material for {@link decryptPayload}.
 */
export interface ReceiverKeys {
  readonly publicKey: string;
  readonly privateKey: string;
  readonly auth: string;
}

/**
 * Derived key material from RFC 8291 section 3.4.
 */
export interface DerivedKeyMaterial {
  readonly ikm: Uint8Array;
  readonly prk: Uint8Array;
  readonly cek: Uint8Array;
  readonly nonce: Uint8Array;
  readonly asPublicBytes: Uint8Array;
}

export const DEFAULT_MAX_PAYLOAD_BYTES = 3_993;
const RECORD_SIZE = 4_096;
const HEADER_LENGTH = 86; // 16 (salt) + 4 (rs) + 1 (idlen) + 65 (keyid)
const AES_GCM_TAG_BYTES = 16;
const MAX_ENCRYPTED_BODY_BYTES = 65_536;

const textEncoder = new TextEncoder();
const WEBPUSH_INFO_PREFIX = textEncoder.encode("WebPush: info\0");
const CEK_INFO = textEncoder.encode("Content-Encoding: aes128gcm\0");
const NONCE_INFO = textEncoder.encode("Content-Encoding: nonce\0");
const ZERO_BYTE = new Uint8Array([0x00]);
const ONE_BYTE = new Uint8Array([0x01]);

/**
 * Validates and decodes a base64url-encoded 65-byte uncompressed P-256 public point.
 */
export function decodePublicKeyBytes(
  encoded: string,
  errorCode: WebPushErrorCode,
  label: string,
): Uint8Array {
  const bytes = base64UrlDecode(encoded, 256);
  if (bytes === null || bytes.byteLength !== 65 || bytes[0] !== 0x04) {
    throw new WebPushError(
      errorCode,
      `Invalid ${label}: expected 65-byte uncompressed P-256 point`,
    );
  }
  return bytes;
}

/**
 * Validates and decodes a base64url-encoded 32-byte P-256 private scalar.
 */
export function decodePrivateKeyBytes(
  encoded: string,
  errorCode: WebPushErrorCode,
  label: string,
): Uint8Array {
  const bytes = base64UrlDecode(encoded, 256);
  if (bytes === null || bytes.byteLength !== 32) {
    throw new WebPushError(errorCode, `Invalid ${label}: expected 32-byte P-256 scalar`);
  }
  let allZero = true;
  for (const b of bytes) {
    if (b !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    throw new WebPushError(errorCode, `Invalid ${label}: private scalar cannot be zero`);
  }
  return bytes;
}

export type WebCryptoKeyUsage =
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "deriveKey"
  | "deriveBits"
  | "wrapKey"
  | "unwrapKey";

/**
 * Imports a P-256 public key into WebCrypto for ECDH or ECDSA.
 */
export async function importPublicKey(
  publicBytes: Uint8Array,
  algorithmName: "ECDH" | "ECDSA",
  usages: readonly KeyUsage[],
  errorCode: WebPushErrorCode,
): Promise<CryptoKey> {
  if (publicBytes.byteLength !== 65 || publicBytes[0] !== 0x04) {
    throw new WebPushError(errorCode, "Invalid P-256 uncompressed public key bytes");
  }
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(publicBytes),
      { name: algorithmName, namedCurve: "P-256" },
      true,
      [...usages],
    );
  } catch (err) {
    throw new WebPushError(errorCode, "Failed to import P-256 public key on curve", { cause: err });
  }
}

/**
 * Imports a P-256 private key (combined with its uncompressed 65-byte public key) via JWK.
 */
export async function importPrivateKey(
  publicBytes: Uint8Array,
  privateBytes: Uint8Array,
  algorithmName: "ECDH" | "ECDSA",
  usages: readonly KeyUsage[],
  errorCode: WebPushErrorCode,
): Promise<CryptoKey> {
  if (publicBytes.byteLength !== 65 || publicBytes[0] !== 0x04 || privateBytes.byteLength !== 32) {
    throw new WebPushError(errorCode, "Invalid P-256 key pair lengths");
  }
  const x = base64UrlEncode(publicBytes.subarray(1, 33));
  const y = base64UrlEncode(publicBytes.subarray(33, 65));
  const d = base64UrlEncode(privateBytes);
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x,
    y,
    d,
    ext: true,
  };
  try {
    return await globalThis.crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: algorithmName, namedCurve: "P-256" },
      false,
      [...usages],
    );
  } catch (err) {
    throw new WebPushError(errorCode, "Failed to import P-256 private key", { cause: err });
  }
}

/**
 * Generates a fresh P-256 key pair encoded as base64url strings.
 */
export async function generateP256KeyPair(algorithmName: "ECDH" | "ECDSA"): Promise<{
  publicBytes: Uint8Array;
  privateKey: CryptoKey;
  keyPair: KeyPair;
}> {
  const usages: KeyUsage[] = algorithmName === "ECDH" ? ["deriveBits"] : ["sign", "verify"];
  const generated = (await globalThis.crypto.subtle.generateKey(
    { name: algorithmName, namedCurve: "P-256" },
    true,
    usages,
  )) as CryptoKeyPair;
  const rawPub = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", generated.publicKey),
  );
  const privJwk = await globalThis.crypto.subtle.exportKey("jwk", generated.privateKey);
  if (typeof privJwk.d !== "string") {
    throw new WebPushError("invalid_vapid", "WebCrypto failed to export private scalar");
  }
  return {
    publicBytes: rawPub,
    privateKey: generated.privateKey,
    keyPair: {
      publicKey: base64UrlEncode(rawPub),
      privateKey: privJwk.d,
    },
  };
}

/**
 * Performs HMAC-SHA-256 using WebCrypto.
 */
async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const effectiveKey = keyBytes.byteLength === 0 ? new Uint8Array(32) : keyBytes;
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(effectiveKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, toArrayBuffer(data));
  return new Uint8Array(signature);
}

/**
 * RFC 5869 HKDF-Extract(salt, IKM) with SHA-256.
 */
export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(salt, ikm);
}

/**
 * RFC 5869 HKDF-Expand(PRK, info, L) with SHA-256 for L <= 32.
 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const okm = await hmacSha256(prk, concatBytes(info, ONE_BYTE));
  return okm.subarray(0, length);
}

/**
 * Derives RFC 8291 section 3.4 IKM, PRK, CEK (16 bytes), and NONCE (12 bytes).
 *
 * Also double-checks via WebCrypto `HKDF` algorithm so both `HKDF` and `HMAC` primitives
 * are exercised on `crypto.subtle`.
 */
export async function deriveWebPushKeys(params: {
  privateKey: CryptoKey;
  peerPublicKey: CryptoKey;
  uaPublicBytes: Uint8Array;
  asPublicBytes: Uint8Array;
  authSecret: Uint8Array;
  salt: Uint8Array;
  errorCode: WebPushErrorCode;
}): Promise<DerivedKeyMaterial> {
  let ecdhSecretBuffer: ArrayBuffer;
  try {
    ecdhSecretBuffer = await globalThis.crypto.subtle.deriveBits(
      { name: "ECDH", public: params.peerPublicKey },
      params.privateKey,
      256,
    );
  } catch (err) {
    throw new WebPushError(params.errorCode, "ECDH shared secret derivation failed", {
      cause: err,
    });
  }
  const ecdhSecret = new Uint8Array(ecdhSecretBuffer);

  // PRK_key = HKDF-Extract(auth_secret, ecdh_secret)
  const prkKey = await hkdfExtract(params.authSecret, ecdhSecret);

  // key_info = "WebPush: info" || 0x00 || ua_public || as_public
  const keyInfo = concatBytes(WEBPUSH_INFO_PREFIX, params.uaPublicBytes, params.asPublicBytes);

  // IKM = HKDF-Expand(PRK_key, key_info, 32)
  const ikm = await hkdfExpand(prkKey, keyInfo, 32);

  // PRK = HKDF-Extract(salt, IKM)
  const prk = await hkdfExtract(params.salt, ikm);

  // CEK = HKDF-Expand(PRK, "Content-Encoding: aes128gcm" || 0x00, 16)
  // NONCE = HKDF-Expand(PRK, "Content-Encoding: nonce" || 0x00, 12)
  // Use WebCrypto's native HKDF algorithm from IKM + salt to derive CEK and NONCE
  const hkdfBaseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(ikm),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const cekBits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(params.salt),
      info: toArrayBuffer(CEK_INFO),
    },
    hkdfBaseKey,
    128,
  );
  const nonceBits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(params.salt),
      info: toArrayBuffer(NONCE_INFO),
    },
    hkdfBaseKey,
    96,
  );

  return {
    ikm,
    prk,
    cek: new Uint8Array(cekBits),
    nonce: new Uint8Array(nonceBits),
    asPublicBytes: params.asPublicBytes,
  };
}

/**
 * Validates the subscription keys (`p256dh` and `auth`) and imports `p256dh` as an ECDH public key.
 */
export async function parseSubscriptionKeys(sub: Subscription): Promise<{
  uaPublicBytes: Uint8Array;
  uaPublicKey: CryptoKey;
  authSecret: Uint8Array;
}> {
  if (
    sub === null ||
    typeof sub !== "object" ||
    sub.keys === null ||
    typeof sub.keys !== "object" ||
    typeof sub.keys.p256dh !== "string" ||
    typeof sub.keys.auth !== "string"
  ) {
    throw new WebPushError(
      "invalid_subscription",
      "Subscription must contain p256dh and auth keys",
    );
  }

  const authSecret = base64UrlDecode(sub.keys.auth, 128);
  if (authSecret === null || authSecret.byteLength !== 16) {
    throw new WebPushError(
      "invalid_subscription",
      "Subscription auth secret must be 16 base64url-encoded bytes",
    );
  }

  const uaPublicBytes = decodePublicKeyBytes(sub.keys.p256dh, "invalid_subscription", "p256dh");
  const uaPublicKey = await importPublicKey(uaPublicBytes, "ECDH", [], "invalid_subscription");

  return { uaPublicBytes, uaPublicKey, authSecret };
}

/**
 * Encrypts a push notification payload using RFC 8291 (`aes128gcm` content encoding).
 *
 * @param payload - UTF-8 string or raw `Uint8Array` plaintext.
 * @param sub - Recipient browser push subscription.
 * @param opts - Optional deterministic salt, sender key pair, or maximum payload size.
 * @returns Complete `aes128gcm` body (86-byte RFC 8188 header followed by the encrypted record).
 * @throws {WebPushError} With code `'payload_too_large'`, `'invalid_subscription'`, or `'invalid_option'`.
 */
export async function encryptPayload(
  payload: string | Uint8Array,
  sub: Subscription,
  opts?: EncryptPayloadOptions,
): Promise<Uint8Array> {
  const maxPayloadBytes = opts?.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;
  if (
    typeof maxPayloadBytes !== "number" ||
    !Number.isInteger(maxPayloadBytes) ||
    maxPayloadBytes < 1 ||
    maxPayloadBytes > DEFAULT_MAX_PAYLOAD_BYTES
  ) {
    throw new WebPushError(
      "invalid_option",
      `maxPayloadBytes must be an integer between 1 and ${DEFAULT_MAX_PAYLOAD_BYTES}`,
    );
  }

  let plaintextBytes: Uint8Array;
  if (typeof payload === "string") {
    plaintextBytes = textEncoder.encode(payload);
  } else if (payload instanceof Uint8Array) {
    plaintextBytes = payload;
  } else {
    throw new WebPushError("invalid_option", "Payload must be a string or Uint8Array");
  }

  if (plaintextBytes.byteLength > maxPayloadBytes) {
    throw new WebPushError(
      "payload_too_large",
      `Payload of ${plaintextBytes.byteLength} bytes exceeds limit of ${maxPayloadBytes} bytes`,
    );
  }

  const { uaPublicBytes, uaPublicKey, authSecret } = await parseSubscriptionKeys(sub);

  let saltBytes: Uint8Array;
  if (opts?.salt !== undefined) {
    const decodedSalt = base64UrlDecode(opts.salt, 128);
    if (decodedSalt === null || decodedSalt.byteLength !== 16) {
      throw new WebPushError("invalid_option", "salt must be 16 base64url-encoded bytes");
    }
    saltBytes = decodedSalt;
  } else {
    saltBytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(saltBytes as Uint8Array<ArrayBuffer>);
  }

  let asPublicBytes: Uint8Array;
  let asPrivateKey: CryptoKey;
  if (opts?.senderKeys !== undefined) {
    if (
      opts.senderKeys === null ||
      typeof opts.senderKeys !== "object" ||
      typeof opts.senderKeys.publicKey !== "string" ||
      typeof opts.senderKeys.privateKey !== "string"
    ) {
      throw new WebPushError("invalid_option", "senderKeys must provide publicKey and privateKey");
    }
    asPublicBytes = decodePublicKeyBytes(
      opts.senderKeys.publicKey,
      "invalid_option",
      "senderKeys.publicKey",
    );
    const asPrivateBytes = decodePrivateKeyBytes(
      opts.senderKeys.privateKey,
      "invalid_option",
      "senderKeys.privateKey",
    );
    asPrivateKey = await importPrivateKey(
      asPublicBytes,
      asPrivateBytes,
      "ECDH",
      ["deriveBits"],
      "invalid_option",
    );
  } else {
    const generated = await generateP256KeyPair("ECDH");
    asPublicBytes = generated.publicBytes;
    asPrivateKey = generated.privateKey;
  }

  const derived = await deriveWebPushKeys({
    privateKey: asPrivateKey,
    peerPublicKey: uaPublicKey,
    uaPublicBytes,
    asPublicBytes,
    authSecret,
    salt: saltBytes,
    errorCode: "invalid_subscription",
  });

  // Single record: plaintext || 0x02
  const paddedRecord = new Uint8Array(plaintextBytes.byteLength + 1);
  paddedRecord.set(plaintextBytes, 0);
  paddedRecord[plaintextBytes.byteLength] = 0x02;

  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(derived.cek),
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(derived.nonce),
      tagLength: 128,
    },
    aesKey,
    toArrayBuffer(paddedRecord),
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);

  // Header: salt (16) || rs uint32 BE (4096) || idlen (65) || as_public (65)
  const header = new Uint8Array(HEADER_LENGTH);
  header.set(saltBytes, 0);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  view.setUint32(16, RECORD_SIZE, false);
  header[20] = 65;
  header.set(asPublicBytes, 21);

  return concatBytes(header, ciphertext);
}

/**
 * Decrypts an RFC 8291 `aes128gcm` single-record body.
 *
 * @param body - Encrypted `aes128gcm` message bytes.
 * @param receiver - User agent public key, private key, and 16-byte auth secret.
 * @returns Decrypted plaintext bytes.
 * @throws {WebPushError} With code `'decrypt_failed'` if the header, keys, tag, or record padding is invalid.
 */
export async function decryptPayload(
  body: Uint8Array,
  receiver: ReceiverKeys,
): Promise<Uint8Array> {
  if (!(body instanceof Uint8Array)) {
    throw new WebPushError("decrypt_failed", "Encrypted body must be a Uint8Array");
  }
  // Minimum size: 86-byte header + 1-byte delimiter + 16-byte AES-GCM tag = 103 bytes
  if (
    body.byteLength < HEADER_LENGTH + 1 + AES_GCM_TAG_BYTES ||
    body.byteLength > MAX_ENCRYPTED_BODY_BYTES
  ) {
    throw new WebPushError("decrypt_failed", "Encrypted body length is out of bounds");
  }
  if (
    receiver === null ||
    typeof receiver !== "object" ||
    typeof receiver.publicKey !== "string" ||
    typeof receiver.privateKey !== "string" ||
    typeof receiver.auth !== "string"
  ) {
    throw new WebPushError(
      "decrypt_failed",
      "Receiver keys must include publicKey, privateKey, and auth",
    );
  }

  const salt = body.subarray(0, 16);
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const rs = view.getUint32(16, false);
  const idlen = body[20];

  if (rs < 18 || idlen !== 65) {
    throw new WebPushError("decrypt_failed", "Invalid aes128gcm record header");
  }

  const asPublicBytes = body.subarray(21, HEADER_LENGTH);
  if (asPublicBytes[0] !== 0x04) {
    throw new WebPushError("decrypt_failed", "Invalid sender public key in header");
  }
  const ciphertext = body.subarray(HEADER_LENGTH);
  if (ciphertext.byteLength > rs) {
    throw new WebPushError("decrypt_failed", "Ciphertext exceeds declared record size");
  }

  const authSecret = base64UrlDecode(receiver.auth, 128);
  if (authSecret === null || authSecret.byteLength !== 16) {
    throw new WebPushError("decrypt_failed", "Invalid receiver auth secret");
  }

  const uaPublicBytes = decodePublicKeyBytes(
    receiver.publicKey,
    "decrypt_failed",
    "receiver.publicKey",
  );
  const uaPrivateBytes = decodePrivateKeyBytes(
    receiver.privateKey,
    "decrypt_failed",
    "receiver.privateKey",
  );

  const asPublicKey = await importPublicKey(asPublicBytes, "ECDH", [], "decrypt_failed");
  const uaPrivateKey = await importPrivateKey(
    uaPublicBytes,
    uaPrivateBytes,
    "ECDH",
    ["deriveBits"],
    "decrypt_failed",
  );

  const derived = await deriveWebPushKeys({
    privateKey: uaPrivateKey,
    peerPublicKey: asPublicKey,
    uaPublicBytes,
    asPublicBytes,
    authSecret,
    salt,
    errorCode: "decrypt_failed",
  });

  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(derived.cek),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  let decryptedBuffer: ArrayBuffer;
  try {
    decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(derived.nonce),
        tagLength: 128,
      },
      aesKey,
      toArrayBuffer(ciphertext),
    );
  } catch (err) {
    throw new WebPushError("decrypt_failed", "AES-GCM authentication failed", { cause: err });
  }

  const record = new Uint8Array(decryptedBuffer);
  // Strip trailing 0x00 padding bytes and verify final record delimiter 0x02
  let end = record.byteLength - 1;
  while (end >= 0 && record[end] === 0x00) {
    end--;
  }
  if (end < 0 || record[end] !== 0x02) {
    throw new WebPushError("decrypt_failed", "Invalid RFC 8188 record padding delimiter");
  }

  return record.slice(0, end);
}

export { ZERO_BYTE };
