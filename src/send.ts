import { toArrayBuffer } from "./base64url.js";
import {
  encryptPayload,
  type KeyPair,
  parseSubscriptionKeys,
  type Subscription,
} from "./crypto.js";
import { WebPushError } from "./errors.js";
import { createVapidAuthorization } from "./vapid.js";

/**
 * RFC 8030 section 5.3 message urgency levels.
 */
export type PushUrgency = "very-low" | "low" | "normal" | "high";

/**
 * Sanitized telemetry event emitted by {@link sendNotification}.
 *
 * Events never include the notification payload, cryptographic keys, auth secret, or VAPID token.
 */
export interface WebPushEvent {
  readonly type: "sent" | "failed";
  readonly status?: number;
  readonly endpointHost: string;
  readonly errorCode?: string;
}

/**
 * Options for {@link sendNotification}.
 */
export interface SendNotificationOptions {
  readonly vapid: {
    readonly subject: string;
    readonly keys: KeyPair;
  };
  readonly fetch?: typeof fetch;
  /**
   * Time-to-live in seconds. Non-negative integer up to `2_419_200` (28 days). Defaults to `86_400`.
   */
  readonly ttl?: number;
  /**
   * Delivery urgency header. Defaults to `'normal'`.
   */
  readonly urgency?: PushUrgency;
  /**
   * Optional message replacement topic: 1 to 32 base64url characters (`[A-Za-z0-9_-]`).
   */
  readonly topic?: string;
  /**
   * Allowed push service hostnames (exact host or leading-dot suffix such as `'.notify.windows.com'`).
   * Defaults to {@link DEFAULT_ENDPOINT_HOSTS}.
   */
  readonly endpointHosts?: readonly string[];
  /**
   * Clock returning Unix epoch milliseconds. Defaults to `Date.now`.
   */
  readonly clock?: () => number;
  /**
   * Optional observer callback invoked with sanitized telemetry.
   */
  readonly onEvent?: (event: WebPushEvent) => void;
}

/**
 * Result resolved by {@link sendNotification} on a 2xx response.
 */
export interface SendNotificationResult {
  readonly status: number;
}

/**
 * Default push service host allow list (vendor documentation, checked 2026-11-09).
 */
export const DEFAULT_ENDPOINT_HOSTS: readonly string[] = Object.freeze([
  "fcm.googleapis.com",
  "updates.push.services.mozilla.com",
  "web.push.apple.com",
  ".notify.windows.com",
]);

export const DEFAULT_TTL_SECONDS = 86_400;
export const MAX_TTL_SECONDS = 2_419_200;
const MAX_ENDPOINT_LENGTH = 4_096;
const TOPIC_REGEX = /^[A-Za-z0-9_-]{1,32}$/;
const VALID_URGENCIES = new Set<PushUrgency>(["very-low", "low", "normal", "high"]);

function isHostAllowed(hostname: string, allowList: readonly string[]): boolean {
  const normalizedHost = hostname.toLowerCase();
  for (const rawPattern of allowList) {
    if (typeof rawPattern !== "string" || rawPattern.length === 0) {
      continue;
    }
    const pattern = rawPattern.toLowerCase();
    if (pattern.startsWith(".")) {
      // Leading dot matches strictly subdomains (e.g. "wns2-par02p.notify.windows.com")
      if (normalizedHost.length > pattern.length && normalizedHost.endsWith(pattern)) {
        return true;
      }
    } else if (normalizedHost === pattern) {
      return true;
    }
  }
  return false;
}

function validateEndpoint(
  endpoint: string,
  allowList: readonly string[],
): { url: URL; origin: string; hostname: string } {
  if (
    typeof endpoint !== "string" ||
    endpoint.length === 0 ||
    endpoint.length > MAX_ENDPOINT_LENGTH
  ) {
    throw new WebPushError(
      "invalid_subscription",
      "Subscription endpoint must be a valid https URL",
    );
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch (err) {
    throw new WebPushError("invalid_subscription", "Subscription endpoint is not a valid URL", {
      cause: err,
    });
  }
  if (url.protocol !== "https:") {
    throw new WebPushError("invalid_subscription", "Subscription endpoint must use https: scheme");
  }
  if (url.username !== "" || url.password !== "") {
    throw new WebPushError(
      "invalid_subscription",
      "Subscription endpoint must not contain credentials",
    );
  }
  if (!isHostAllowed(url.hostname, allowList)) {
    throw new WebPushError(
      "invalid_subscription",
      `Subscription endpoint host is not in endpointHosts allow list`,
    );
  }
  return { url, origin: url.origin, hostname: url.hostname.toLowerCase() };
}

function parseRetryAfterSeconds(
  headerValue: string | null,
  clock: () => number,
): number | undefined {
  if (headerValue === null) {
    return undefined;
  }
  const trimmed = headerValue.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return undefined;
  }
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : undefined;
  }
  const parsedDateMs = Date.parse(trimmed);
  if (!Number.isNaN(parsedDateMs)) {
    const deltaSeconds = Math.ceil((parsedDateMs - clock()) / 1000);
    return Math.max(0, deltaSeconds);
  }
  return undefined;
}

function emitEvent(
  onEvent: ((event: WebPushEvent) => void) | undefined,
  event: WebPushEvent,
): void {
  if (typeof onEvent === "function") {
    onEvent(Object.freeze({ ...event }));
  }
}

/**
 * Encrypts (when `payload !== null`), signs a VAPID token, and delivers a Web Push notification
 * over HTTP POST per RFC 8030, RFC 8291, and RFC 8292.
 *
 * @param sub - Recipient browser push subscription.
 * @param payload - Notification payload (`string`, `Uint8Array`, or `null` for an empty trigger push).
 * @param opts - VAPID credentials, optional `fetch`, `ttl`, `urgency`, `topic`, `endpointHosts`, `clock`, and `onEvent`.
 * @returns `{ status }` when the push service responds with a 2xx status.
 * @throws {WebPushError} On validation failure, network error, or non-2xx push service status.
 */
export async function sendNotification(
  sub: Subscription,
  payload: string | Uint8Array | null,
  opts: SendNotificationOptions,
): Promise<SendNotificationResult> {
  if (sub === null || typeof sub !== "object") {
    throw new WebPushError("invalid_subscription", "Subscription must be an object");
  }
  if (
    opts === null ||
    typeof opts !== "object" ||
    opts.vapid === null ||
    typeof opts.vapid !== "object"
  ) {
    throw new WebPushError("invalid_vapid", "VAPID configuration is required");
  }

  const endpointHosts = opts.endpointHosts ?? DEFAULT_ENDPOINT_HOSTS;
  if (!Array.isArray(endpointHosts) || endpointHosts.length === 0) {
    throw new WebPushError(
      "invalid_option",
      "endpointHosts must be a non-empty array of host patterns",
    );
  }

  const { origin, hostname } = validateEndpoint(sub.endpoint, endpointHosts);

  // Always validate subscription keys even when payload is null
  await parseSubscriptionKeys(sub);

  const ttl = opts.ttl ?? DEFAULT_TTL_SECONDS;
  if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 0 || ttl > MAX_TTL_SECONDS) {
    throw new WebPushError(
      "invalid_option",
      `ttl must be an integer between 0 and ${MAX_TTL_SECONDS}`,
    );
  }

  const urgency: PushUrgency = opts.urgency ?? "normal";
  if (!VALID_URGENCIES.has(urgency)) {
    throw new WebPushError(
      "invalid_option",
      "urgency must be 'very-low', 'low', 'normal', or 'high'",
    );
  }

  if (opts.topic !== undefined) {
    if (typeof opts.topic !== "string" || !TOPIC_REGEX.test(opts.topic)) {
      throw new WebPushError(
        "invalid_option",
        "topic must be 1 to 32 base64url characters ([A-Za-z0-9_-])",
      );
    }
  }

  const clock = opts.clock ?? Date.now;
  const fetchFn = opts.fetch ?? globalThis.fetch;
  if (typeof fetchFn !== "function") {
    throw new WebPushError("invalid_option", "fetch implementation is not available");
  }

  const authorization = await createVapidAuthorization({
    audience: origin,
    subject: opts.vapid.subject,
    keys: opts.vapid.keys,
    clock,
  });

  const headers: Record<string, string> = {
    Authorization: authorization,
    TTL: String(ttl),
    Urgency: urgency,
  };
  if (opts.topic !== undefined) {
    headers.Topic = opts.topic;
  }

  let body: ArrayBuffer | undefined;
  if (payload !== null) {
    const encrypted = await encryptPayload(payload, sub);
    body = toArrayBuffer(encrypted);
    headers["Content-Encoding"] = "aes128gcm";
    headers["Content-Type"] = "application/octet-stream";
    headers["Content-Length"] = String(encrypted.byteLength);
  }

  let response: Response;
  try {
    const requestInit: RequestInit = {
      method: "POST",
      headers,
    };
    if (body !== undefined) {
      requestInit.body = new Uint8Array(body);
    }
    response = await fetchFn(sub.endpoint, requestInit);
  } catch (err) {
    emitEvent(opts.onEvent, {
      type: "failed",
      endpointHost: hostname,
      errorCode: "network_error",
    });
    throw new WebPushError("network_error", "Network error while contacting push service", {
      cause: err,
    });
  }

  const status = response.status;
  if (status >= 200 && status < 300) {
    emitEvent(opts.onEvent, {
      type: "sent",
      status,
      endpointHost: hostname,
    });
    return { status };
  }

  if (status === 404 || status === 410) {
    emitEvent(opts.onEvent, {
      type: "failed",
      status,
      endpointHost: hostname,
      errorCode: "subscription_gone",
    });
    throw new WebPushError(
      "subscription_gone",
      `Push subscription expired or gone (HTTP ${status})`,
      {
        status,
      },
    );
  }

  if (status === 413) {
    emitEvent(opts.onEvent, {
      type: "failed",
      status,
      endpointHost: hostname,
      errorCode: "payload_too_large",
    });
    throw new WebPushError(
      "payload_too_large",
      "Push service rejected payload as too large (HTTP 413)",
      {
        status,
      },
    );
  }

  if (status === 429) {
    const retryAfterSeconds = parseRetryAfterSeconds(
      response.headers?.get("Retry-After") ?? null,
      clock,
    );
    emitEvent(opts.onEvent, {
      type: "failed",
      status,
      endpointHost: hostname,
      errorCode: "rate_limited",
    });
    throw new WebPushError("rate_limited", "Push service rate limited request (HTTP 429)", {
      status,
      ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
    });
  }

  emitEvent(opts.onEvent, {
    type: "failed",
    status,
    endpointHost: hostname,
    errorCode: "push_service_error",
  });
  throw new WebPushError("push_service_error", `Push service returned HTTP ${status}`, {
    status,
  });
}
