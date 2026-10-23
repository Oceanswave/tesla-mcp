#!/usr/bin/env bash
# Check the TypeScript signer's vectors against Tesla's official Go
# implementation. Tesla's signer is in internal/ packages, so the test file is
# compiled inside a pinned checkout of github.com/teslamotors/vehicle-command.
#
# Usage: bash conformance/run.sh   (needs git and Go on PATH)
set -euo pipefail

# vehicle-command v0.4.1. Bump deliberately, together with any vector changes.
VEHICLE_COMMAND_REPO="https://github.com/teslamotors/vehicle-command"
VEHICLE_COMMAND_SHA="49977a18fd68567501d59e16a6c9e4a8b9348544"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_file="$root/conformance/go/tesla_mcp_conformance_test.go"
vectors="$root/test/vectors/vcsec-lock.json"

unformatted="$(gofmt -l "$test_file")"
if [[ -n "$unformatted" ]]; then
  echo "gofmt: $unformatted is not formatted" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src="$work/vehicle-command"

git init --quiet "$src"
git -C "$src" fetch --quiet --depth 1 "$VEHICLE_COMMAND_REPO" "$VEHICLE_COMMAND_SHA"
git -C "$src" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
actual="$(git -C "$src" rev-parse HEAD)"
if [[ "$actual" != "$VEHICLE_COMMAND_SHA" ]]; then
  echo "expected vehicle-command $VEHICLE_COMMAND_SHA, got $actual" >&2
  exit 1
fi

cp "$test_file" "$src/internal/authentication/"

# Use the installed toolchain, and resolve modules only from vehicle-command's
# committed go.sum.
cd "$src"
GOTOOLCHAIN=local GOFLAGS=-mod=readonly TESLA_MCP_VECTORS="$vectors" \
  go test -count=1 -run TeslaMCPConformance -v ./internal/authentication
