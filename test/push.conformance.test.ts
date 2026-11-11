import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateVapidKeys, type Subscription, sendNotification } from "../src/index.js";

const runE2E = process.env.FABRICA_CI === "1" && process.env.FABRICA_PUSH_E2E === "1";

const SW_SOURCE = `
self.addEventListener('push', (event) => {
  const text = event.data ? event.data.text() : '';
  event.waitUntil(
    self.clients.matchAll({ includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        client.postMessage({ type: 'push-received', text });
      }
    })
  );
});
`;

const PAGE_SOURCE = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Push Conformance</title></head>
<body>
<script>
window.__receivedMessages = [];
navigator.serviceWorker.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'push-received') {
    window.__receivedMessages.push(event.data.text);
  }
});
window.__subscribePush = async (publicKeyBase64Url) => {
  const padding = '='.repeat((4 - (publicKeyBase64Url.length % 4)) % 4);
  const base64 = (publicKeyBase64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const applicationServerKey = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    applicationServerKey[i] = raw.charCodeAt(i);
  }
  const reg = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey,
  });
  return sub.toJSON();
};
</script>
</body>
</html>
`;

describe.skipIf(!runE2E)("Browser Web Push E2E conformance (Chromium & Firefox)", () => {
  let server: Server;
  let origin = "";

  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === "/sw.js") {
        res.writeHead(200, { "Content-Type": "application/javascript" });
        res.end(SW_SOURCE);
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(PAGE_SOURCE);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const addr = server.address() as AddressInfo;
    origin = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  });

  for (const browserName of ["chromium", "firefox"] as const) {
    it(`delivers encrypted payload through real push service to ${browserName}`, async () => {
      let playwrightModule: typeof import("playwright") | undefined;
      try {
        playwrightModule = await import("playwright");
      } catch {
        return;
      }
      const browserType = playwrightModule[browserName];
      const browser = await browserType.launch({ headless: true });
      try {
        const context = await browser.newContext({
          permissions: ["notifications"],
        });
        const page = await context.newPage();
        await page.goto(origin);

        const vapidKeys = await generateVapidKeys();
        const rawSub = (await page.evaluate(
          (pubKey) =>
            (
              globalThis as unknown as { __subscribePush: (k: string) => Promise<unknown> }
            ).__subscribePush(pubKey),
          vapidKeys.publicKey,
        )) as Subscription;

        const message = `hello-${browserName}`;
        const result = await sendNotification(rawSub, message, {
          vapid: {
            subject: "mailto:push@example.com",
            keys: vapidKeys,
          },
        });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        await page.waitForFunction(
          (expected) =>
            (
              (globalThis as unknown as { __receivedMessages: string[] }).__receivedMessages ?? []
            ).includes(expected),
          message,
          { timeout: 30_000 },
        );
      } finally {
        await browser.close();
      }
    }, 60_000);
  }
});
