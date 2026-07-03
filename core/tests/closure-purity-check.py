#!/usr/bin/env python3
"""ClearCutt closure-purity checker.

Walks either a Docker/OCI image archive (layer tar headers, so permission
bits survive non-root extraction) or an on-disk /nix/store closure list
(``closureInfo``'s store-paths file) and flags:

  * any store path providing an interactive shell entry point
    (bin/sh, bin/bash, bin/ash, bin/dash);
  * any store path providing a package-manager binary
    (bin/npm, bin/npx, bin/corepack, bin/pip, bin/pip3, bin/pip3.X,
    bin/apk, bin/dpkg, bin/rpm);
  * any setuid/setgid regular file anywhere in the scanned tree.

Findings can be consciously accepted through an allowlist file where each
non-comment line is ``<store-name-pattern> <one-line reason>``. The pattern
is an fnmatch glob matched against the store component name with the hash
prefix stripped (e.g. ``bash-5.2*``); for setuid findings outside
/nix/store the pattern is matched against the full path instead. An entry
without a reason is rejected so exceptions stay explained, mirroring
verify-closure-diff.sh's explained-exception style.

Usage:
  closure-purity-check.py <image-archive> [--allowlist FILE]
  closure-purity-check.py --store-paths FILE [--allowlist FILE]

Exit status: 0 when clean (or fully allowlisted), 1 on violations or
malformed inputs.
"""

import argparse
import fnmatch
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile


SHELL_BINARIES = {"sh", "bash", "ash", "dash"}
PACKAGE_MANAGER_BINARIES = {"npm", "npx", "corepack", "pip", "pip3", "apk", "dpkg", "rpm"}
# Versioned pip entry points (pip3.13, pip3.14, ...) are the same violation.
VERSIONED_PIP_RE = re.compile(r"^pip[0-9]+(\.[0-9]+)*$")

STORE_BIN_RE = re.compile(r"^nix/store/([^/]+)/bin/([^/]+)$")
STORE_COMPONENT_RE = re.compile(r"^nix/store/([^/]+)")


def is_flagged_binary(name):
    if name in SHELL_BINARIES:
        return "interactive shell"
    if name in PACKAGE_MANAGER_BINARIES or VERSIONED_PIP_RE.match(name):
        return "package manager"
    return None


def strip_store_hash(component):
    """Return the store name without the 32-char hash prefix."""
    if "-" in component:
        return component.split("-", 1)[1]
    return component


def store_root(path):
    """/nix/store/<hash-name>/sub/path -> /nix/store/<hash-name>, else None."""
    parts = path.split("/")
    try:
        i = parts.index("store")
    except ValueError:
        return None
    if len(parts) > i + 1 and parts[i + 1]:
        return "/".join(parts[: i + 2])
    return None


def diagnose_referrers(violation_paths, scanned_roots):
    """Best-effort: for each offending store path, name the IN-IMAGE packages
    that reference it, so a purity failure points at its source instead of just
    flagging the leaf (e.g. 'bash-5.3p9 is pulled in by: icu4c-dev'). Needs
    nix-store and the realized closure (present in CI right after the build);
    silently no-ops when unavailable, so it never changes the gate's verdict.
    """
    offenders = sorted({r for r in (store_root(p) for p in violation_paths) if r})
    for bad in offenders:
        try:
            result = subprocess.run(
                ["nix-store", "--query", "--referrers", bad],
                capture_output=True, text=True, timeout=120,
            )
        except (OSError, subprocess.SubprocessError):
            return  # nix-store unavailable (e.g. local run) — best-effort only
        if result.returncode != 0:
            continue
        referrers = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        in_image = sorted(
            strip_store_hash(os.path.basename(r))
            for r in referrers
            if r in scanned_roots and r != bad
        )
        leaf = strip_store_hash(os.path.basename(bad))
        if in_image:
            print(
                f"[closure-purity] DIAGNOSIS: {leaf} is referenced in the image by: "
                f"{', '.join(sorted(set(in_image)))}",
                file=sys.stderr,
            )
        else:
            print(
                f"[closure-purity] DIAGNOSIS: {leaf} has no single in-image referrer "
                "(reached transitively beyond one hop, or it is a root content path)",
                file=sys.stderr,
            )


def load_allowlist(path):
    entries = []
    if path is None or not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2 or not parts[1].strip():
                raise SystemExit(
                    f"allowlist {path}:{lineno}: every entry needs "
                    f"'<store-name-pattern> <one-line reason>', got: {line!r}"
                )
            entries.append((parts[0], parts[1].strip()))
    return entries


def allowlist_reason(entries, candidate):
    for pattern, reason in entries:
        if fnmatch.fnmatch(candidate, pattern):
            return f"{pattern} ({reason})"
    return None


class Findings:
    """Collects violations keyed by in-image path so layer whiteouts can
    drop findings shadowed by later layers."""

    def __init__(self, allowlist):
        self.allowlist = allowlist
        self.violations = {}
        self.accepted = []

    def record(self, path, allow_key, message):
        reason = allowlist_reason(self.allowlist, allow_key)
        if reason is not None:
            self.accepted.append(f"{message} [allowlisted: {reason}]")
            return
        self.violations[path] = message

    def discard(self, path):
        self.violations.pop(path, None)


def normalize_member_name(name):
    name = name.lstrip("/")
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def inspect_member(member, findings):
    name = normalize_member_name(member.name)
    if not name:
        return

    base = os.path.basename(name)
    if base.startswith(".wh."):
        findings.discard(os.path.join(os.path.dirname(name), base[len(".wh."):]))
        return

    store_match = STORE_BIN_RE.match(name)
    if store_match and (member.isfile() or member.issym() or member.islnk()):
        component, binary = store_match.groups()
        category = is_flagged_binary(binary)
        if category:
            findings.record(
                name,
                strip_store_hash(component),
                f"store path /nix/store/{component} provides {category} bin/{binary}",
            )

    if member.isfile() and member.mode & (stat.S_ISUID | stat.S_ISGID):
        bit = "setuid" if member.mode & stat.S_ISUID else "setgid"
        component_match = STORE_COMPONENT_RE.match(name)
        allow_key = (
            strip_store_hash(component_match.group(1))
            if component_match
            else "/" + name
        )
        findings.record(
            name,
            allow_key,
            f"{bit} regular file /{name} (mode {member.mode:o})",
        )


def read_member(archive, name):
    try:
        member = archive.getmember(name)
    except KeyError:
        raise SystemExit(f"image archive is missing referenced member: {name}") from None
    extracted = archive.extractfile(member)
    if extracted is None:
        raise SystemExit(f"image archive member is not readable: {name}")
    return extracted.read()


def docker_layers(archive):
    manifests = json.loads(read_member(archive, "manifest.json"))
    if not manifests:
        raise SystemExit("docker archive manifest.json contains no images")
    for layer in manifests[0].get("Layers", []):
        yield read_member(archive, layer)


def oci_blob_name(digest):
    algorithm, value = digest.split(":", 1)
    return f"blobs/{algorithm}/{value}"


def oci_layers(archive):
    index = json.loads(read_member(archive, "index.json"))
    manifests = index.get("manifests") or []
    if not manifests:
        raise SystemExit("OCI archive index.json contains no manifests")
    manifest = json.loads(read_member(archive, oci_blob_name(manifests[0]["digest"])))
    for layer in manifest.get("layers", []):
        yield read_member(archive, oci_blob_name(layer["digest"]))


def scan_image_archive(archive_path, findings):
    scanned_roots = set()
    with tarfile.open(archive_path, mode="r:*") as archive:
        names = set(archive.getnames())
        if "manifest.json" in names:
            layer_iter = docker_layers(archive)
        elif "index.json" in names and "oci-layout" in names:
            layer_iter = oci_layers(archive)
        else:
            raise SystemExit("unsupported image archive: expected docker save or OCI layout tar")

        for layer_bytes in layer_iter:
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer:
                for member in layer:
                    root = store_root("/" + member.name.lstrip("/"))
                    if root:
                        scanned_roots.add(root)
                    inspect_member(member, findings)
    return scanned_roots


def scan_store_paths(paths_file, findings):
    with open(paths_file, encoding="utf-8") as handle:
        store_paths = [line.strip() for line in handle if line.strip()]
    if not store_paths:
        raise SystemExit(f"store paths file is empty: {paths_file}")

    for store_path in store_paths:
        component = os.path.basename(store_path)
        allow_key = strip_store_hash(component)

        bin_dir = os.path.join(store_path, "bin")
        if os.path.isdir(bin_dir):
            for entry in sorted(os.listdir(bin_dir)):
                category = is_flagged_binary(entry)
                if category and os.path.lexists(os.path.join(bin_dir, entry)):
                    findings.record(
                        f"{store_path}/bin/{entry}",
                        allow_key,
                        f"store path {store_path} provides {category} bin/{entry}",
                    )

        for dirpath, _, filenames in os.walk(store_path):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    bit = "setuid" if st.st_mode & stat.S_ISUID else "setgid"
                    findings.record(
                        full,
                        allow_key,
                        f"{bit} regular file {full} (mode {stat.S_IMODE(st.st_mode):o})",
                    )

    return set(store_paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="?", help="docker save or OCI layout tar (optionally gzipped)")
    parser.add_argument("--store-paths", help="closureInfo store-paths file to scan instead of an archive")
    parser.add_argument("--allowlist", help="explained-exception allowlist file")
    args = parser.parse_args()

    if bool(args.archive) == bool(args.store_paths):
        parser.error("provide exactly one of <image-archive> or --store-paths FILE")

    findings = Findings(load_allowlist(args.allowlist))

    if args.archive:
        scanned_roots = scan_image_archive(args.archive, findings)
    else:
        scanned_roots = scan_store_paths(args.store_paths, findings)

    for note in findings.accepted:
        print(f"[closure-purity] ACCEPTED: {note}")

    if findings.violations:
        for message in sorted(findings.violations.values()):
            print(f"[closure-purity] VIOLATION: {message}", file=sys.stderr)
        diagnose_referrers(findings.violations.keys(), scanned_roots)
        print(
            f"[closure-purity] {len(findings.violations)} violation(s). "
            "Either remove the offending package from the production closure or add an "
            "explained entry to the closure-purity allowlist.",
            file=sys.stderr,
        )
        return 1

    print("[closure-purity] clean: no shells, package managers, or setuid/setgid files found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
