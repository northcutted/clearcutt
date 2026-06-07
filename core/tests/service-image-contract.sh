#!/usr/bin/env bash
set -euo pipefail

service="${1:?usage: service-image-contract.sh <service-id> <archive.tar.gz>}"
archive="${2:?usage: service-image-contract.sh <service-id> <archive.tar.gz>}"

if [[ ! -f "$archive" ]]; then
  echo "service archive not found: $archive" >&2
  exit 1
fi

case "$service" in
  postgres16)
    expected_port="5432/tcp"
    expected_entrypoint="/bin/clearcutt-postgres-entrypoint"
    expected_env="PGDATA=/var/lib/postgresql/data"
    data_dirs=("/var/lib/postgresql/data")
    command_only="false"
    ;;
  valkey8)
    expected_port="6379/tcp"
    expected_entrypoint="/bin/valkey-server"
    expected_env=""
    data_dirs=("/data")
    command_only="false"
    ;;
  oauth2-proxy7)
    expected_port="4180/tcp"
    expected_entrypoint="/bin/oauth2-proxy"
    expected_env=""
    data_dirs=()
    command_only="true"
    ;;
  *)
    echo "unsupported service contract fixture: $service" >&2
    exit 1
    ;;
esac

tmp_dir="$(mktemp -d)"
cleanup() {
  chmod -R +w "$tmp_dir" 2>/dev/null || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

tar -xf "$archive" -C "$tmp_dir"

manifest_file="$tmp_dir/manifest.json"
if [[ ! -f "$manifest_file" ]]; then
  echo "manifest.json not found in $archive" >&2
  exit 1
fi

config_name="$(python3 - "$manifest_file" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
if not manifest:
    raise SystemExit("empty Docker archive manifest")
print(manifest[0]["Config"])
PY
)"
config_file="$tmp_dir/$config_name"
if [[ ! -f "$config_file" ]]; then
  echo "config JSON $config_name not found in $archive" >&2
  exit 1
fi

python3 - "$service" "$config_file" "$expected_port" "$expected_entrypoint" "$expected_env" <<'PY'
import json
import sys

service, config_path, expected_port, expected_entrypoint, expected_env = sys.argv[1:]
doc = json.load(open(config_path, encoding="utf-8"))
config = doc.get("config", {})

def require(condition, message):
    if not condition:
        raise SystemExit(message)

require(config.get("User") == "10001:10001", f"{service}: expected User 10001:10001, got {config.get('User')!r}")
require(config.get("WorkingDir") == "/app", f"{service}: expected WorkingDir /app, got {config.get('WorkingDir')!r}")

ports = config.get("ExposedPorts") or {}
require(expected_port in ports, f"{service}: expected exposed port {expected_port}, got {sorted(ports)}")

entrypoint = config.get("Entrypoint") or []
require(entrypoint == [expected_entrypoint], f"{service}: expected Entrypoint {[expected_entrypoint]!r}, got {entrypoint!r}")

env = set(config.get("Env") or [])
if expected_env:
    require(expected_env in env, f"{service}: expected env {expected_env}, got {sorted(env)}")

labels = config.get("Labels") or {}
require(labels.get("dev.clearcutt.image.kind") == "service", f"{service}: missing service kind label")
require(labels.get("dev.clearcutt.service.id") == service, f"{service}: missing service id label")
require(labels.get("dev.clearcutt.service.template"), f"{service}: missing service template label")
require(labels.get("dev.clearcutt.service.version"), f"{service}: missing service version label")

print(f"{service}: OCI config contract passed")
PY

if ((${#data_dirs[@]} > 0)); then
  python3 - "$service" "$tmp_dir" "${data_dirs[@]}" <<'PY'
import os
import sys
import tarfile

service = sys.argv[1]
root = sys.argv[2]
expected = [d.lstrip("/").rstrip("/") for d in sys.argv[3:]]
found = {}

for dirpath, _, files in os.walk(root):
    if "layer.tar" not in files:
        continue
    layer_path = os.path.join(dirpath, "layer.tar")
    with tarfile.open(layer_path) as layer:
        for member in layer:
            name = member.name.lstrip("/")
            while name.startswith("./"):
                name = name[2:]
            name = name.rstrip("/")
            if member.isdir() and name in expected:
                found[name] = member.mode

for rel in expected:
    mode = found.get(rel)
    if mode is None:
        raise SystemExit(f"{service}: expected writable data directory /{rel} in image layers")
    if mode & 0o222 == 0:
        raise SystemExit(f"{service}: expected writable data directory /{rel}, got mode {mode:o}")

print(f"{service}: writable data directory contract passed")
PY
fi

image_tar="$tmp_dir/image.tar"
gzip -dc "$archive" > "$image_tar"

engine="${CLEARCUTT_ENGINE:-docker}"
load_output="$("$engine" load -i "$image_tar")"
printf '%s\n' "$load_output"

cli="${CLEARCUTT_CLI:-./clearcutt}"
if [[ -n "${CLEARCUTT_IMAGE_REF:-}" ]]; then
  image="$CLEARCUTT_IMAGE_REF"
else
  image="$(printf '%s\n' "$load_output" | sed -n 's/^Loaded image: //p' | tail -n 1)"
  if [[ -z "$image" ]]; then
    image="${CLEARCUTT_IMAGE_PREFIX:-clearcutt}-${service}:current"
  fi
fi
smoke_args=(service smoke "$service" --engine "$engine" --image "$image")
if [[ "$command_only" == "true" ]]; then
  smoke_args+=(--command-only)
fi
"$cli" "${smoke_args[@]}"
