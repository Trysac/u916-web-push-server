/**
 * Error codes produced by `@trysac/web-push-server`.
 */
export type WebPushErrorCode =
  | "invalid_subscription"
  | "invalid_vapid"
  | "invalid_option"
  | "payload_too_large"
  | "decrypt_failed"
  | "subscription_gone"
  | "rate_limited"
  | "push_service_error"
  | "network_error";

/**
 * Additional metadata attached to a {@link WebPushError}.
 */
export interface WebPushErrorOptions {
  readonly status?: number;
  readonly retryAfterSeconds?: number;
  readonly cause?: unknown;
}

const MAX_MESSAGE_LENGTH = 200;

function sanitizeMessage(message: string): string {
  const singleLine = message.replace(/[\r\n]+/g, " ").trim();
  if (singleLine.length <= MAX_MESSAGE_LENGTH) {
    return singleLine;
  }
  return `${singleLine.slice(0, MAX_MESSAGE_LENGTH - 3)}...`;
}

/**
 * Base error class thrown by all functions in `@trysac/web-push-server`.
 *
 * Error messages are capped at 200 characters and never include cryptographic
 * keys, VAPID tokens, auth secrets, or notification payloads.
 */
export class WebPushError extends Error {
  public readonly code: WebPushErrorCode;
  public readonly status?: number;
  public readonly retryAfterSeconds?: number;

  public constructor(code: WebPushErrorCode, message: string, options?: WebPushErrorOptions) {
    const safeMessage = sanitizeMessage(message);
    super(safeMessage, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "WebPushError";
    this.code = code;
    if (options?.status !== undefined) {
      this.status = options.status;
    }
    if (options?.retryAfterSeconds !== undefined) {
      this.retryAfterSeconds = options.retryAfterSeconds;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
