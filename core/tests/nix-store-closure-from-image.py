#!/usr/bin/env python3
"""Extract top-level /nix/store paths from a Docker or OCI image archive."""

import io
import json
import re
import sys
import tarfile


STORE_RE = re.compile(r"^(?:\./)?/?nix/store/([^/]+)")


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
    raw = read_member(archive, "manifest.json")
    manifests = json.loads(raw)
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


def layer_store_roots(layer_bytes):
    roots = set()
    with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer:
        for member in layer:
            match = STORE_RE.match(member.name)
            if match:
                roots.add(f"/nix/store/{match.group(1)}")
    return roots


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} <docker-or-oci-image-archive>")

    roots = set()
    with tarfile.open(sys.argv[1], mode="r:*") as archive:
        names = set(archive.getnames())
        if "manifest.json" in names:
            layer_iter = docker_layers(archive)
        elif "index.json" in names and "oci-layout" in names:
            layer_iter = oci_layers(archive)
        else:
            raise SystemExit("unsupported image archive: expected docker save or OCI layout tar")

        for layer_bytes in layer_iter:
            roots.update(layer_store_roots(layer_bytes))

    if not roots:
        raise SystemExit("image archive contains no /nix/store paths")
    for root in sorted(roots):
        print(root)


if __name__ == "__main__":
    main()
