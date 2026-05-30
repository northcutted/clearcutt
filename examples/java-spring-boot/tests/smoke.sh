#!/usr/bin/env bash
# ClearCutt Spring Boot smoke verification script
set -euo pipefail

IMAGE_NAME="${1:-acme/java25-demo:latest}"

echo "[clearcutt] Launching runtime compliance checks on $IMAGE_NAME..."

# Verify the unprivileged operator user UID
USER_CHECK=$(docker run --entrypoint id "$IMAGE_NAME" -u)
if [ "$USER_CHECK" != "10001" ]; then
  echo "✘ FAILED: Expected runtime execution UID 10001, got $USER_CHECK"
  exit 1
fi
echo "✔ PASS: Unprivileged operator user UID verified as 10001"

# Verify shell utility absence
echo "[clearcutt] Auditing interactive shell absence..."
if docker run --entrypoint sh "$IMAGE_NAME" -c "exit 0" 2>/dev/null; then
  echo "✘ FAILED: Security Violation: Shell binary is present inside distroless closure!"
  exit 1
fi
echo "✔ PASS: Interactive shell absence verified inside distroless closure"

echo "[clearcutt] Conformance smoke tests passed successfully for $IMAGE_NAME!"
