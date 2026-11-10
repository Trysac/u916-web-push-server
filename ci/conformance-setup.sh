#!/usr/bin/env bash
set -euo pipefail

# Install Playwright browsers required for the CI Web Push conformance tier.
if command -v npx >/dev/null 2>&1; then
  npx playwright install --with-deps chromium firefox
fi
