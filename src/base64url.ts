const BASE64URL_REGEX = /^[A-Za-z0-9_-]+={0,2}$/;

/**
 * Encodes a `Uint8Array` into an unpadded base64url string.
 *
 * @param bytes - Raw bytes to encode.
 * @returns Unpadded base64url string.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b !== undefined) {
      binary += String.fromCharCode(b);
    }
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes a base64url string (with optional `=` padding) into a `Uint8Array`.
 *
 * @param input - Base64url string to decode.
 * @param maxChars - Maximum allowed character length of the input.
 * @returns Decoded bytes, or `null` when the input is malformed.
 */
export function base64UrlDecode(input: string, maxChars = 16_384): Uint8Array | null {
  if (typeof input !== "string" || input.length === 0 || input.length > maxChars) {
    return null;
  }
  if (!BASE64URL_REGEX.test(input)) {
    return null;
  }
  const unpadded = input.replace(/=+$/, "");
  const mod = unpadded.length % 4;
  if (mod === 1) {
    return null;
  }
  const padLength = mod === 0 ? 0 : 4 - mod;
  const base64 = unpadded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLength);
  try {
    const binary = atob(base64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    // Verify canonical encoding of trailing bits
    if (base64UrlEncode(out) !== unpadded) {
      return null;
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * Concatenates multiple `Uint8Array` views into a single `Uint8Array`.
 */
export function concatBytes(...arrays: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const arr of arrays) {
    total += arr.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.byteLength;
  }
  return out;
}

/**
 * Converts a `Uint8Array` into a standalone `ArrayBuffer` suitable for WebCrypto.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}
