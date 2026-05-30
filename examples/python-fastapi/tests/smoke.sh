#!/usr/bin/env bash
# ClearCutt Python FastAPI smoke verification script
set -euo pipefail

IMAGE_NAME="${1:-acme/python314-demo:latest}"

echo "[clearcutt] Launching runtime compliance checks on $IMAGE_NAME..."

# Verify the unprivileged operator user UID
USER_CHECK=$(docker run --entrypoint id "$IMAGE_NAME" -u)
if [ "$USER_CHECK" != "10001" ]; then
  echo "✘ FAILED: Expected runtime execution UID 10001, got $USER_CHECK"
  exit 1
fi
echo "✔ PASS: Unprivileged operator user UID verified as 10001"

# Verify shell utility presence (expected to exist on slim tier, unlike distroless)
echo "[clearcutt] Auditing shell presence for slim tier..."
if ! docker run --entrypoint sh "$IMAGE_NAME" -c "exit 0" 2>/dev/null; then
  echo "✘ FAILED: Expected interactive shell to be present inside slim tier!"
  exit 1
fi
echo "✔ PASS: Interactive shell presence verified inside slim tier"

echo "[clearcutt] Conformance smoke tests passed successfully for $IMAGE_NAME!"
