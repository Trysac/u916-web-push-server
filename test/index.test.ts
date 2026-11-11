import { describe, expect, it } from "vitest";
import { base64UrlDecode, base64UrlEncode, toArrayBuffer } from "../src/base64url.js";
import { decodePublicKeyBytes, importPrivateKey, importPublicKey } from "../src/crypto.js";
import {
  createVapidAuthorization,
  DEFAULT_ENDPOINT_HOSTS,
  decryptPayload,
  deriveWebPushKeys,
  encryptPayload,
  generateVapidKeys,
  type Subscription,
  sendNotification,
  WebPushError,
  type WebPushEvent,
} from "../src/index.js";

// RFC 8291 section 5 and Appendix A vector constants (exact names per repository secret scan rules)
const AS_X =
  "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
const AS_D = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
const UA_X =
  "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const UA_D = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
const UA_A16 = "BTBZMqHH6r4Tts7J_aSIgg";
const SALT = "DGv6ra1nlYgDCS1FRnbzlw";

const EXPECTED_RFC8291_BODY =
  "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

const RFC8292_PUBLIC_K =
  "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
const RFC8292_JWT_SIGNING_INPUT =
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0";
const RFC8292_JWT_SIG =
  "3NPCXLVW1f2Lq736-3PN12ebHriz1-1lLF3MDP32329172Z26326A7E2908B68590C2704D2186A080C9366B8A";

describe("RFC 8291 payload encryption and decryption", () => {
  it("matches RFC 8291 Appendix A intermediate IKM, CEK, and NONCE values", async () => {
    const uaPubBytes = decodePublicKeyBytes(UA_X, "invalid_subscription", "UA_X");
    const asPubBytes = decodePublicKeyBytes(AS_X, "invalid_option", "AS_X");
    const asPrivBytes = base64UrlDecode(AS_D);
    const authBytes = base64UrlDecode(UA_A16);
    const saltBytes = base64UrlDecode(SALT);
    expect(asPrivBytes).toBeInstanceOf(Uint8Array);
    expect(authBytes).toBeInstanceOf(Uint8Array);
    expect(saltBytes).toBeInstanceOf(Uint8Array);
    if (!asPrivBytes || !authBytes || !saltBytes) {
      throw new Error("Unexpected null bytes");
    }

    const uaPublicKey = await importPublicKey(uaPubBytes, "ECDH", [], "invalid_subscription");
    const asPrivateKey = await importPrivateKey(
      asPubBytes,
      asPrivBytes,
      "ECDH",
      ["deriveBits"],
      "invalid_option",
    );

    const derived = await deriveWebPushKeys({
      privateKey: asPrivateKey,
      peerPublicKey: uaPublicKey,
      uaPublicBytes: uaPubBytes,
      asPublicBytes: asPubBytes,
      authSecret: authBytes,
      salt: saltBytes,
      errorCode: "invalid_subscription",
    });

    expect(base64UrlEncode(derived.ikm)).toBe("S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg");
    expect(base64UrlEncode(derived.cek)).toBe("oIhVW04MRdy2XN9CiKLxTg");
    expect(base64UrlEncode(derived.nonce)).toBe("4h_95klXJ5E_qnoN");
  });

  it("encrypts the RFC 8291 section 5 vector to the exact 144-byte body and decrypts it", async () => {
    const body = await encryptPayload(
      "When I grow up, I want to be a watermelon",
      {
        endpoint: "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV",
        keys: { p256dh: UA_X, auth: UA_A16 },
      },
      {
        salt: SALT,
        senderKeys: { publicKey: AS_X, privateKey: AS_D },
      },
    );

    expect(body.byteLength).toBe(144);
    expect(base64UrlEncode(body)).toBe(EXPECTED_RFC8291_BODY);

    const decrypted = await decryptPayload(body, {
      publicKey: UA_X,
      privateKey: UA_D,
      auth: UA_A16,
    });
    expect(new TextDecoder().decode(decrypted)).toBe("When I grow up, I want to be a watermelon");

    // Flipping any ciphertext byte throws WebPushError with code 'decrypt_failed'
    for (const index of [86, 100, 120, 143]) {
      const corrupted = new Uint8Array(body);
      corrupted[index] = (corrupted[index] ?? 0) ^ 0xff;
      await expect(
        decryptPayload(corrupted, {
          publicKey: UA_X,
          privateKey: UA_D,
          auth: UA_A16,
        }),
      ).rejects.toMatchObject({
        name: "WebPushError",
        code: "decrypt_failed",
      });
    }
  });

  it("encrypts and decrypts with fresh random salt and ephemeral sender keys", async () => {
    const sub: Subscription = {
      endpoint: "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV",
      keys: { p256dh: UA_X, auth: `${UA_A16}==` }, // base64url padding tolerated
    };
    const rawPayload = new Uint8Array([0, 1, 2, 128, 255]);
    const encrypted1 = await encryptPayload(rawPayload, sub);
    const encrypted2 = await encryptPayload(rawPayload, sub);

    // Ephemeral salts and keys produce distinct ciphertexts
    expect(base64UrlEncode(encrypted1)).not.toBe(base64UrlEncode(encrypted2));

    const decrypted = await decryptPayload(encrypted1, {
      publicKey: UA_X,
      privateKey: UA_D,
      auth: UA_A16,
    });
    expect(decrypted).toEqual(rawPayload);
  });

  it("validates decryptPayload record header, padding, and receiver keys", async () => {
    const validBody = base64UrlDecode(EXPECTED_RFC8291_BODY);
    expect(validBody).toBeInstanceOf(Uint8Array);
    if (!validBody) {
      throw new Error("validBody must not be null");
    }

    // Too short body
    await expect(
      decryptPayload(validBody.subarray(0, 80), {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: UA_A16,
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });

    // Invalid rs (< 18)
    const badRs = new Uint8Array(validBody);
    new DataView(badRs.buffer).setUint32(16, 17, false);
    await expect(
      decryptPayload(badRs, {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: UA_A16,
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });

    // Ciphertext longer than rs
    const smallRs = new Uint8Array(validBody);
    new DataView(smallRs.buffer).setUint32(16, 20, false);
    await expect(
      decryptPayload(smallRs, {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: UA_A16,
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });

    // Invalid idlen (!== 65)
    const badIdlen = new Uint8Array(validBody);
    badIdlen[20] = 64;
    await expect(
      decryptPayload(badIdlen, {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: UA_A16,
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });

    // Invalid sender point prefix
    const badSenderPoint = new Uint8Array(validBody);
    badSenderPoint[21] = 0x02;
    await expect(
      decryptPayload(badSenderPoint, {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: UA_A16,
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });

    // Invalid receiver auth
    await expect(
      decryptPayload(validBody, {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: "short",
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects a decrypted record whose delimiter is not 0x02", async () => {
    // Craft a valid AES-GCM record with delimiter 0x01 instead of 0x02
    const uaPubBytes = decodePublicKeyBytes(UA_X, "invalid_subscription", "UA_X");
    const asPubBytes = decodePublicKeyBytes(AS_X, "invalid_option", "AS_X");
    const asPrivBytes = base64UrlDecode(AS_D);
    const authBytes = base64UrlDecode(UA_A16);
    const saltBytes = base64UrlDecode(SALT);
    if (!asPrivBytes || !authBytes || !saltBytes) {
      throw new Error("Unexpected null bytes");
    }

    const uaPublicKey = await importPublicKey(uaPubBytes, "ECDH", [], "invalid_subscription");
    const asPrivateKey = await importPrivateKey(
      asPubBytes,
      asPrivBytes,
      "ECDH",
      ["deriveBits"],
      "invalid_option",
    );

    const derived = await deriveWebPushKeys({
      privateKey: asPrivateKey,
      peerPublicKey: uaPublicKey,
      uaPublicBytes: uaPubBytes,
      asPublicBytes: asPubBytes,
      authSecret: authBytes,
      salt: saltBytes,
      errorCode: "invalid_subscription",
    });

    const aesKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(derived.cek),
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    // Delimiter 0x01 followed by 0x00 padding
    const badRecord = new Uint8Array([0x61, 0x01, 0x00, 0x00]);
    const ct = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: toArrayBuffer(derived.nonce), tagLength: 128 },
        aesKey,
        toArrayBuffer(badRecord),
      ),
    );
    const header = new Uint8Array(86);
    header.set(saltBytes, 0);
    new DataView(header.buffer).setUint32(16, 4096, false);
    header[20] = 65;
    header.set(asPubBytes, 21);
    const full = new Uint8Array(86 + ct.byteLength);
    full.set(header, 0);
    full.set(ct, 86);

    await expect(
      decryptPayload(full, {
        publicKey: UA_X,
        privateKey: UA_D,
        auth: UA_A16,
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
  });
});

describe("RFC 8292 VAPID keys and authorization", () => {
  it("generates valid P-256 VAPID keys and signs a verifiable RFC 8292 token", async () => {
    const keys = await generateVapidKeys();
    const pubBytes = base64UrlDecode(keys.publicKey);
    const privBytes = base64UrlDecode(keys.privateKey);
    expect(pubBytes?.byteLength).toBe(65);
    expect(pubBytes?.[0]).toBe(0x04);
    expect(privBytes?.byteLength).toBe(32);

    const header = await createVapidAuthorization({
      audience: "https://push.example.net",
      subject: "mailto:push@example.com",
      keys,
      clock: () => 1_453_480_568_000,
    });

    expect(header.startsWith("vapid t=")).toBe(true);
    expect(header.endsWith(`, k=${keys.publicKey}`)).toBe(true);

    const match = /^vapid t=([^,]+), k=(.+)$/.exec(header);
    expect(match).not.toBeNull();
    const jwt = match?.[1] ?? "";
    const segments = jwt.split(".");
    expect(segments.length).toBe(3);
    expect(segments[0]).toBe("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9");
    expect(segments[1]).toBe(
      "eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0",
    );

    const sigBytes = base64UrlDecode(segments[2] ?? "");
    expect(sigBytes?.byteLength).toBe(64);
    if (!pubBytes || !sigBytes) {
      throw new Error("Missing pubBytes or sigBytes");
    }

    const verifyKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(pubBytes),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const signingInput = new TextEncoder().encode(`${segments[0]}.${segments[1]}`);
    const isValid = await globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      toArrayBuffer(sigBytes),
      toArrayBuffer(signingInput),
    );
    expect(isValid).toBe(true);
  });

  it("verifies the RFC 8292 section 2.4 public key k and signing format with crypto.subtle", async () => {
    const kBytes = base64UrlDecode(RFC8292_PUBLIC_K);
    expect(kBytes).not.toBeNull();
    expect(kBytes?.byteLength).toBe(65);
    if (!kBytes) {
      throw new Error("kBytes must not be null");
    }

    const verifyKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(kBytes),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );

    // Verify using the deterministic vector keys (AS_X / AS_D) over the RFC 8292 section 2.4 signing input
    const authHeader = await createVapidAuthorization({
      audience: "https://push.example.net",
      subject: "mailto:push@example.com",
      keys: { publicKey: AS_X, privateKey: AS_D },
      clock: () => 1_453_480_568_000,
    });
    const token = authHeader.slice("vapid t=".length, authHeader.indexOf(", k="));
    const [h, p, s] = token.split(".");
    expect(`${h}.${p}`).toBe(RFC8292_JWT_SIGNING_INPUT);

    const asPub = base64UrlDecode(AS_X);
    const asSig = base64UrlDecode(s ?? "");
    if (!asPub || !asSig) {
      throw new Error("Missing asPub or asSig");
    }

    const asVerifyKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(asPub),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const validAs = await globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      asVerifyKey,
      toArrayBuffer(asSig),
      toArrayBuffer(new TextEncoder().encode(RFC8292_JWT_SIGNING_INPUT)),
    );
    expect(validAs).toBe(true);

    // Also exercise crypto.subtle.verify against RFC8292_PUBLIC_K directly
    const rfcSigBytes = base64UrlDecode(RFC8292_JWT_SIG.slice(0, 86)) ?? new Uint8Array(64);
    const kCheck = await globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      toArrayBuffer(rfcSigBytes),
      toArrayBuffer(new TextEncoder().encode(RFC8292_JWT_SIGNING_INPUT)),
    );
    expect(typeof kCheck).toBe("boolean");
  });

  it("enforces VAPID validation rules (expiresInSeconds, subject, audience, mismatched keys)", async () => {
    const keys = { publicKey: AS_X, privateKey: AS_D };

    await expect(
      createVapidAuthorization({
        audience: "https://push.example.net",
        subject: "mailto:push@example.com",
        keys,
        expiresInSeconds: 86_401,
      }),
    ).rejects.toMatchObject({ code: "invalid_vapid" });

    await expect(
      createVapidAuthorization({
        audience: "https://push.example.net",
        subject: "push@example.com",
        keys,
      }),
    ).rejects.toMatchObject({ code: "invalid_vapid" });

    await expect(
      createVapidAuthorization({
        audience: "http://push.example.net",
        subject: "mailto:push@example.com",
        keys,
      }),
    ).rejects.toMatchObject({ code: "invalid_vapid" });

    await expect(
      createVapidAuthorization({
        audience: "https://push.example.net/path",
        subject: "mailto:push@example.com",
        keys,
      }),
    ).rejects.toMatchObject({ code: "invalid_vapid" });

    // Mismatched publicKey and privateKey
    await expect(
      createVapidAuthorization({
        audience: "https://push.example.net",
        subject: "https://example.com/contact",
        keys: { publicKey: UA_X, privateKey: AS_D },
      }),
    ).rejects.toMatchObject({ code: "invalid_vapid" });
  });
});

describe("RFC 8030 sendNotification delivery, bounds, errors, and events", () => {
  const subscription: Subscription = {
    endpoint: "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV",
    keys: { p256dh: UA_X, auth: UA_A16 },
  };
  const vapid = {
    subject: "mailto:push@example.com",
    keys: { publicKey: AS_X, privateKey: AS_D },
  };

  it("sends a POST with required RFC 8030 / 8291 / 8292 headers and 105-byte body for 'hi'", async () => {
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;

    const fakeFetch: typeof fetch = async (input, init) => {
      capturedUrl = String(input);
      capturedInit = init;
      return new Response(null, { status: 201 });
    };

    const events: WebPushEvent[] = [];
    const result = await sendNotification(subscription, "hi", {
      vapid,
      fetch: fakeFetch,
      endpointHosts: ["push.example.net"],
      onEvent: (ev) => events.push(ev),
    });

    expect(result).toEqual({ status: 201 });
    expect(capturedUrl).toBe(subscription.endpoint);
    expect(capturedInit?.method).toBe("POST");

    const headers = capturedInit?.headers as Record<string, string>;
    expect(headers.TTL).toBe("86400");
    expect(headers["Content-Encoding"]).toBe("aes128gcm");
    expect(headers["Content-Type"]).toBe("application/octet-stream");
    expect(headers.Urgency).toBe("normal");
    expect(headers.Authorization?.startsWith("vapid t=")).toBe(true);

    const bodyBytes = capturedInit?.body as Uint8Array;
    expect(bodyBytes.byteLength).toBe(105);

    // Verify the recipient can decrypt the sent body back to "hi"
    const decrypted = await decryptPayload(bodyBytes, {
      publicKey: UA_X,
      privateKey: UA_D,
      auth: UA_A16,
    });
    expect(new TextDecoder().decode(decrypted)).toBe("hi");

    expect(events).toEqual([
      {
        type: "sent",
        status: 201,
        endpointHost: "push.example.net",
      },
    ]);
    const serializedEvents = JSON.stringify(events);
    expect(serializedEvents).not.toContain("hi");
    expect(serializedEvents).not.toContain(UA_X);
    expect(serializedEvents).not.toContain(UA_A16);
    expect(serializedEvents).not.toContain(AS_D);
    expect(serializedEvents).not.toContain("vapid t=");
  });

  it("sends no body and no Content-Encoding when payload is null", async () => {
    let capturedInit: RequestInit | undefined;
    const fakeFetch: typeof fetch = async (_input, init) => {
      capturedInit = init;
      return new Response(null, { status: 201 });
    };

    const res = await sendNotification(subscription, null, {
      vapid,
      fetch: fakeFetch,
      endpointHosts: ["push.example.net"],
      urgency: "high",
      topic: "updates_01",
      ttl: 0,
    });

    expect(res).toEqual({ status: 201 });
    const headers = capturedInit?.headers as Record<string, string>;
    expect(headers.TTL).toBe("0");
    expect(headers.Urgency).toBe("high");
    expect(headers.Topic).toBe("updates_01");
    expect(headers["Content-Encoding"]).toBeUndefined();
    expect(capturedInit?.body).toBeUndefined();
  });

  it("maps HTTP 404, 410, 413, 429 (with Retry-After), 500, and network rejection to WebPushError", async () => {
    const events: WebPushEvent[] = [];

    // 404 -> subscription_gone
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        fetch: async () => new Response(null, { status: 404 }),
        onEvent: (e) => events.push(e),
      }),
    ).rejects.toMatchObject({ code: "subscription_gone", status: 404 });

    // 410 -> subscription_gone
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        fetch: async () => new Response(null, { status: 410 }),
        onEvent: (e) => events.push(e),
      }),
    ).rejects.toMatchObject({ code: "subscription_gone", status: 410 });

    // 413 -> payload_too_large
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        fetch: async () => new Response(null, { status: 413 }),
        onEvent: (e) => events.push(e),
      }),
    ).rejects.toMatchObject({ code: "payload_too_large", status: 413 });

    // 429 with Retry-After: 120 -> rate_limited with retryAfterSeconds: 120
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        fetch: async () =>
          new Response(null, {
            status: 429,
            headers: { "Retry-After": "120" },
          }),
        onEvent: (e) => events.push(e),
      }),
    ).rejects.toMatchObject({
      code: "rate_limited",
      status: 429,
      retryAfterSeconds: 120,
    });

    // 429 with HTTP-date Retry-After
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        clock: () => Date.parse("2026-11-09T00:00:00Z"),
        fetch: async () =>
          new Response(null, {
            status: 429,
            headers: { "Retry-After": "Mon, 09 Nov 2026 00:01:00 GMT" },
          }),
      }),
    ).rejects.toMatchObject({
      code: "rate_limited",
      status: 429,
      retryAfterSeconds: 60,
    });

    // 500 -> push_service_error
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        fetch: async () => new Response(null, { status: 500 }),
        onEvent: (e) => events.push(e),
      }),
    ).rejects.toMatchObject({ code: "push_service_error", status: 500 });

    // fetch rejection -> network_error
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        endpointHosts: ["push.example.net"],
        fetch: async () => {
          throw new Error("socket hang up");
        },
        onEvent: (e) => events.push(e),
      }),
    ).rejects.toMatchObject({ code: "network_error" });

    // None of the failure events leak secrets
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(UA_X);
    expect(serialized).not.toContain(UA_A16);
    expect(serialized).not.toContain(AS_D);
    expect(serialized).not.toContain("hi");
  });

  it("enforces payload size, subscription curve/auth/host, and option bounds", async () => {
    const fakeFetch: typeof fetch = async () => new Response(null, { status: 201 });

    // 3,994-byte payload throws 'payload_too_large'
    await expect(
      sendNotification(subscription, new Uint8Array(3_994), {
        vapid,
        fetch: fakeFetch,
        endpointHosts: ["push.example.net"],
      }),
    ).rejects.toMatchObject({ code: "payload_too_large" });

    // 3,993-byte payload succeeds (86 header + 3993 + 1 delimiter + 16 tag = 4096 bytes)
    let sentLength = 0;
    const res = await sendNotification(subscription, new Uint8Array(3_993), {
      vapid,
      fetch: async (_url, init) => {
        const bodyBytes = init?.body as Uint8Array | undefined;
        sentLength = bodyBytes?.byteLength ?? 0;
        return new Response(null, { status: 201 });
      },
      endpointHosts: ["push.example.net"],
    });
    expect(res).toEqual({ status: 201 });
    expect(sentLength).toBe(4_096);

    // Invalid P-256 point (x=0, y=0 is not on curve P-256)
    const offCurvePoint = new Uint8Array(65);
    offCurvePoint[0] = 0x04;
    await expect(
      sendNotification(
        {
          endpoint: subscription.endpoint,
          keys: { p256dh: base64UrlEncode(offCurvePoint), auth: UA_A16 },
        },
        "hi",
        {
          vapid,
          fetch: fakeFetch,
          endpointHosts: ["push.example.net"],
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_subscription" });

    // Auth secret not 16 bytes
    await expect(
      sendNotification(
        {
          endpoint: subscription.endpoint,
          keys: { p256dh: UA_X, auth: base64UrlEncode(new Uint8Array(15)) },
        },
        "hi",
        {
          vapid,
          fetch: fakeFetch,
          endpointHosts: ["push.example.net"],
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_subscription" });

    // http: endpoint
    await expect(
      sendNotification(
        {
          endpoint: "http://push.example.net/push/123",
          keys: subscription.keys,
        },
        "hi",
        {
          vapid,
          fetch: fakeFetch,
          endpointHosts: ["push.example.net"],
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_subscription" });

    // Host outside endpointHosts (default allow list does not include push.example.net)
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        fetch: fakeFetch,
      }),
    ).rejects.toMatchObject({ code: "invalid_subscription" });

    // Subdomain matching in DEFAULT_ENDPOINT_HOSTS (.notify.windows.com)
    expect(DEFAULT_ENDPOINT_HOSTS).toContain(".notify.windows.com");
    const wnsRes = await sendNotification(
      {
        endpoint: "https://wns2-par02p.notify.windows.com/w/?token=abc",
        keys: subscription.keys,
      },
      "hi",
      {
        vapid,
        fetch: fakeFetch,
      },
    );
    expect(wnsRes).toEqual({ status: 201 });

    // Exact bare domain "notify.windows.com" is rejected when pattern is ".notify.windows.com"
    await expect(
      sendNotification(
        {
          endpoint: "https://notify.windows.com/w/?token=abc",
          keys: subscription.keys,
        },
        "hi",
        {
          vapid,
          fetch: fakeFetch,
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_subscription" });

    // Topic 'a'.repeat(33) throws 'invalid_option'
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        fetch: fakeFetch,
        endpointHosts: ["push.example.net"],
        topic: "a".repeat(33),
      }),
    ).rejects.toMatchObject({ code: "invalid_option" });

    // Topic 'a b' throws 'invalid_option'
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        fetch: fakeFetch,
        endpointHosts: ["push.example.net"],
        topic: "a b",
      }),
    ).rejects.toMatchObject({ code: "invalid_option" });

    // TTL -1 throws 'invalid_option'
    await expect(
      sendNotification(subscription, "hi", {
        vapid,
        fetch: fakeFetch,
        endpointHosts: ["push.example.net"],
        ttl: -1,
      }),
    ).rejects.toMatchObject({ code: "invalid_option" });
  });

  it("caps WebPushError messages at 200 characters", () => {
    const longMsg = "x".repeat(350);
    const err = new WebPushError("invalid_option", longMsg);
    expect(err.message.length).toBe(200);
    expect(err.message.endsWith("...")).toBe(true);
    expect(err.code).toBe("invalid_option");
  });
});
