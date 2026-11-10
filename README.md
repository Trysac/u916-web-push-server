# web-push-server

[![npm version](https://img.shields.io/npm/v/@trysac/web-push-server.svg)](https://www.npmjs.com/package/@trysac/web-push-server)
[![license: MIT](https://img.shields.io/npm/l/@trysac/web-push-server.svg)](LICENSE)
[![CI](https://github.com/Trysac/u916-web-push-server/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u916-web-push-server/actions/workflows/ci.yml)

Web Push sender written on WebCrypto: RFC 8291 aes128gcm payload encryption, RFC 8292 VAPID ES256 tokens and RFC 8030 delivery with typed push service errors

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and why existing
packages do not solve it well. Keep it factual; link to an issue or decision record when there is one.

## Install

```sh
npm install @trysac/web-push-server
```

Requires Node.js 20 or newer. The package ships ES modules with TypeScript declarations.

## Usage

```ts
import { greet } from "@trysac/web-push-server";

// Build a greeting; surrounding whitespace is ignored.
const message = greet("  Ada ");
console.log(message); // "Hello, Ada!"

try {
  greet("   ");
} catch (error) {
  console.error((error as Error).message); // "name must not be empty"
}
```

## API

| Export | Signature | Description |
|---|---|---|
| `greet` | `(name: string) => string` | Placeholder API; replace it with the real one. |

## Development

```sh
npm install
npm run check   # lint, format, types, tests with coverage, docs, secrets
```

See [AGENTS.md](AGENTS.md) for the full command list and [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[MIT](LICENSE) © 2026 Miguel Gomez
