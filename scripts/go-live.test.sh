#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export FYKE_GO_LIVE_FUNCTIONS_ONLY=1
# shellcheck source=go-live.sh
source "$REPO_DIR/scripts/go-live.sh"
unset FYKE_GO_LIVE_FUNCTIONS_ONLY

URL=https://example.invalid/setup
if ! output=$(PATH=/path-with-no-browser-programs open_setup_url "$URL"); then
  printf 'FAIL: open_setup_url stopped the setup when no browser was installed.\n' >&2
  exit 1
fi
if [[ "$output" != *"$URL"* ]]; then
  printf 'FAIL: open_setup_url did not show the address.\n' >&2
  exit 1
fi

printf 'PASS: browser address output does not stop the setup.\n'
