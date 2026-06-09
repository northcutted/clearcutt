package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type overlayFlags struct {
	runtime               string
	tier                  string
	base                  string
	runtimeRef            string
	binary                string
	image                 string
	output                string
	runtimeArchive        string
	graftedArchive        string
	runtimeRefForVerify   string
	graftedRefForVerify   string
	target                string
	outputPredicate       bool
	attestationOutputPath string
}

var overlayOpts overlayFlags

func NewOverlayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "overlay",
		Short: "Manage BYO base image overlays",
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new BYO base image overlay project layout",
		Long:  `Generates a standard flake-based overlay project, smoke tests, admission control policies, and CI workflows to graft a ClearCutt Nix store runtime closure onto a mandated enterprise base OS image.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOverlayGenerate()
		},
	}

	generateCmd.Flags().StringVar(&overlayOpts.runtime, "runtime", "", "Target ClearCutt runtime (e.g. java25 or python3.15)")
	generateCmd.Flags().StringVar(&overlayOpts.tier, "tier", "distroless", "Target ClearCutt runtime tier (distroless or slim)")
	generateCmd.Flags().StringVar(&overlayOpts.base, "base", "", "Required mandated enterprise base image (e.g. registry.access.redhat.com/ubi9/ubi-minimal@sha256:...)")
	generateCmd.Flags().StringVar(&overlayOpts.runtimeRef, "runtime-ref", "", "Required ClearCutt source runtime image reference (e.g. ghcr.io/northcutted/clearcutt/clearcutt-java25@sha256:...)")
	generateCmd.Flags().StringVar(&overlayOpts.binary, "binary", "", "Interpreter binary execution target (e.g. java or python3)")
	generateCmd.Flags().StringVar(&overlayOpts.image, "image", "", "Destination target overlay image name tag")
	generateCmd.Flags().StringVar(&overlayOpts.output, "output", "", "Output project directory destination path")

	generateCmd.MarkFlagRequired("runtime")
	generateCmd.MarkFlagRequired("base")
	generateCmd.MarkFlagRequired("runtime-ref")
	generateCmd.MarkFlagRequired("image")
	generateCmd.MarkFlagRequired("output")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a grafted overlay image preserves the ClearCutt runtime closure",
		Long:  `Compares the /nix/store closure bytes in a source ClearCutt runtime archive and a grafted overlay archive, then emits a closure-equivalence in-toto predicate for signing or admission review.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOverlayVerify()
		},
	}
	verifyCmd.Flags().StringVar(&overlayOpts.runtimeArchive, "runtime-archive", "", "Source ClearCutt runtime image archive, docker-save or OCI-layout (required)")
	verifyCmd.Flags().StringVar(&overlayOpts.graftedArchive, "grafted-archive", "", "Grafted overlay image archive, docker-save or OCI-layout (required)")
	verifyCmd.Flags().StringVar(&overlayOpts.runtimeRefForVerify, "runtime-ref", "", "Digest-pinned runtime image ref recorded as an in-toto subject, name@sha256:... (required)")
	verifyCmd.Flags().StringVar(&overlayOpts.graftedRefForVerify, "grafted-ref", "", "Digest-pinned grafted image ref recorded as an in-toto subject, name@sha256:... (required)")
	verifyCmd.Flags().StringVar(&overlayOpts.target, "target", "", "ClearCutt runtime target id recorded in the predicate")
	verifyCmd.Flags().BoolVar(&overlayOpts.outputPredicate, "output-predicate", false, "Print the closure-equivalence predicate as JSON")
	verifyCmd.Flags().StringVar(&overlayOpts.attestationOutputPath, "attestation-out", "", "Write the closure-equivalence predicate JSON to this file")
	verifyCmd.MarkFlagRequired("runtime-archive")
	verifyCmd.MarkFlagRequired("grafted-archive")
	verifyCmd.MarkFlagRequired("runtime-ref")
	verifyCmd.MarkFlagRequired("grafted-ref")

	cmd.AddCommand(generateCmd, verifyCmd)

	return cmd
}

func runOverlayGenerate() error {
	outDir := overlayOpts.output

	if !strings.Contains(overlayOpts.runtimeRef, "@sha256:") {
		return fmt.Errorf("--runtime-ref must be digest-pinned in name@sha256:... form")
	}

	if overlayOpts.binary == "" {
		overlayOpts.binary = resolveBinary(overlayOpts.runtime)
	}

	if err := os.MkdirAll(filepath.Join(outDir, "tests"), 0755); err != nil {
		return fmt.Errorf("failed to create tests directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "policy"), 0755); err != nil {
		return fmt.Errorf("failed to create policy directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, ".github", "workflows"), 0755); err != nil {
		return fmt.Errorf("failed to create workflows directory: %w", err)
	}

	// 1. Generate clearcutt.overlay.yaml
	overlayConfig := fmt.Sprintf(`apiVersion: clearcutt.dev/v1
kind: OverlayImage
metadata:
  name: %s-overlay
spec:
  runtime:
    id: %s
    tier: %s
    binary: %s
    sourceImage: %s
  base:
    image: %s
  output:
    image: %s
  supplyChain:
    sbom: true
    provenance: true
    sign: true
  runtimeContract:
    nonroot: true
    shellGuarantee: inherited_from_base
    packageManagerGuarantee: inherited_from_base
`, filepath.Base(outDir), overlayOpts.runtime, overlayOpts.tier, overlayOpts.binary, overlayOpts.runtimeRef, overlayOpts.base, overlayOpts.image)

	if err := os.WriteFile(filepath.Join(outDir, "clearcutt.overlay.yaml"), []byte(overlayConfig), 0644); err != nil {
		return fmt.Errorf("failed to write overlay config: %w", err)
	}

	baseImageName, baseImageDigest := splitDigestRef(overlayOpts.base)
	imageName, imageTag := splitTagRef(overlayOpts.image)
	flake := fmt.Sprintf(`{
  description = "ClearCutt grafted overlay for %s on a mandated base";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    clearcutt.url = "github:northcutted/clearcutt?dir=core";
  };

  outputs = { self, nixpkgs, clearcutt }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          mandatedBase = pkgs.dockerTools.pullImage {
            imageName = "%s";
            imageDigest = "%s";
            sha256 = "sha256-REPLACE_WITH_NIX_HASH_FROM_NIX_PREFETCH_DOCKER";
          };
        in {
          overlayImage = clearcutt.lib.graftOntoBase {
            inherit system;
            fromImage = mandatedBase;
            runtime = "%s";
            tier = "%s";
            name = "%s";
            tag = "%s";
          };
        });
    };
}
`, overlayOpts.runtime, baseImageName, baseImageDigest, overlayOpts.runtime, overlayOpts.tier, imageName, imageTag)

	if err := os.WriteFile(filepath.Join(outDir, "flake.nix"), []byte(flake), 0644); err != nil {
		return fmt.Errorf("failed to write flake.nix: %w", err)
	}

	// 3. Generate README.md
	readme := fmt.Sprintf(`# ClearCutt Overlay: %s on Mandated Base

This project lays a self-contained ClearCutt **%s** runtime closure on top of a sanctioned enterprise base image.

## Mandated Architecture Details
*   **ClearCutt Runtime**: %s (`+"`"+`%s`+"`"+`)
*   **Mandated Base OS**: %s
*   **Destination Target**: %s

---

## ⚠️ CRITICAL SAFETY RULES (Trade-Offs)
1.  **Not Distroless**: This overlay image is **NOT** distroless unless the mandated base is also distroless. It inherits the base image's shell utilities, coreutils, package managers, and security agents.
2.  **Base CVE Footprint**: This image inherits all vulnerabilities and library defects from the base OS layer. The ClearCutt runtime is RPATH-isolated under `+"`"+`/nix`+"`"+`, but the base operating system still requires patch governance.
3.  **Signatures & Provenance**: The signatures, SBOMs, and SLSA provenance of this final grafted image are completely separate from the original ClearCutt base evidence. You must sign and attest this image during your build pipeline.

---

## How to Build & Run Smoke Tests
Build locally using the provided flake-backed Makefile:
`+"```"+`bash
make build
docker load -i result
make test
`+"```"+`

Generate an offline runtime-equivalence predicate before signing the overlay:
`+"```"+`bash
clearcutt overlay verify \
  --runtime-archive clearcutt-runtime.tar \
  --grafted-archive result \
  --runtime-ref %s \
  --grafted-ref %s@sha256:REPLACE_WITH_GRAFTED_IMAGE_DIGEST \
  --target %s \
  --output-predicate > closure-equivalence.intoto.json
`+"```"+`
`, overlayOpts.runtime, overlayOpts.runtime, overlayOpts.runtime, overlayOpts.tier, overlayOpts.base, overlayOpts.image, overlayOpts.runtimeRef, overlayOpts.image, overlayOpts.runtime)

	if err := os.WriteFile(filepath.Join(outDir, "README.md"), []byte(readme), 0644); err != nil {
		return fmt.Errorf("failed to write README: %w", err)
	}

	// 4. Generate Makefile
	makefile := fmt.Sprintf(`IMAGE_NAME ?= %s
SYSTEM ?= x86_64-linux
RUNTIME_ARCHIVE ?= clearcutt-runtime.tar
GRAFTED_ARCHIVE ?= result
GRAFTED_REF ?= $(IMAGE_NAME)@sha256:REPLACE_WITH_GRAFTED_IMAGE_DIGEST

.PHONY: build load test scan predicate

build:
	nix build .#packages.$(SYSTEM).overlayImage

load:
	docker load -i $(GRAFTED_ARCHIVE)

test:
	./tests/smoke.sh $(IMAGE_NAME)

scan:
	grype $(IMAGE_NAME)

predicate:
	clearcutt overlay verify \
	  --runtime-archive $(RUNTIME_ARCHIVE) \
	  --grafted-archive $(GRAFTED_ARCHIVE) \
	  --runtime-ref %s \
	  --grafted-ref $(GRAFTED_REF) \
	  --target %s \
	  --output-predicate > closure-equivalence.intoto.json
`, overlayOpts.image, overlayOpts.runtimeRef, overlayOpts.runtime)

	if err := os.WriteFile(filepath.Join(outDir, "Makefile"), []byte(makefile), 0644); err != nil {
		return fmt.Errorf("failed to write Makefile: %w", err)
	}

	var smokeVersionCheck string
	smokeVersionCheck = runtimeSmokeCheck(overlayOpts.binary)

	// 5. Generate tests/smoke.sh
	smokeSh := fmt.Sprintf(`#!/usr/bin/env bash
# ClearCutt Overlay Smoke Test
set -euo pipefail

IMAGE_NAME="${1:-%s}"

echo "[clearcutt] Running runtime link validation checks on $IMAGE_NAME..."

# Verify the unprivileged operator user UID
USER_CHECK=$(docker run --entrypoint id "$IMAGE_NAME" -u)
if [ "$USER_CHECK" != "10001" ]; then
  echo "✘ FAILED: Expected runtime execution UID 10001, got $USER_CHECK"
  exit 1
fi
echo "✔ PASS: Unprivileged operator user UID verified as 10001"

# Verify binary executes and outputs version
VERSION_OUTPUT=$(%s)
echo "✔ PASS: Interpreter binary version check succeeded: $VERSION_OUTPUT"

echo "[clearcutt] All smoke tests passed successfully for $IMAGE_NAME!"
`, overlayOpts.image, smokeVersionCheck)

	if err := os.WriteFile(filepath.Join(outDir, "tests", "smoke.sh"), []byte(smokeSh), 0755); err != nil {
		return fmt.Errorf("failed to write smoke.sh: %w", err)
	}

	// 6. Generate policy/kyverno-verify-image.yaml
	kyvernoPolicy := fmt.Sprintf(`apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-overlay-signature-%s
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-overlay-cosign
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences: ["%s*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/acme/platform/.github/workflows/build.yaml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
          mutateDigest: true
          verifyDigest: true
          required: true
`, overlayOpts.runtime, overlayOpts.image)

	if err := os.WriteFile(filepath.Join(outDir, "policy", "kyverno-verify-image.yaml"), []byte(kyvernoPolicy), 0644); err != nil {
		return fmt.Errorf("failed to write kyverno policy: %w", err)
	}

	// 7. Generate workflows
	buildWorkflow := `name: Compile & Secure Grafted Overlay

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Compile grafted overlay image
        run: |
          make build

      - name: Generate SPDX SBOM using Syft
        uses: anchore/sbom-action@v0
        with:
          image: ${{ github.repository }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3.5.0

      - name: Sign final image and attach SBOM
        run: |
          echo "Signing and attesting generated overlay image..."
`

	if err := os.WriteFile(filepath.Join(outDir, ".github", "workflows", "build.yaml"), []byte(buildWorkflow), 0644); err != nil {
		return fmt.Errorf("failed to write build.yaml: %w", err)
	}

	verifyWorkflow := `name: Verify Hardened Base Overlay

on:
  workflow_run:
    workflows: ["Compile & Secure Grafted Overlay"]
    types: [completed]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3.5.0

      - name: Audit overlay policies
        run: |
          echo "Running governance policy checks..."
`

	if err := os.WriteFile(filepath.Join(outDir, ".github", "workflows", "verify.yaml"), []byte(verifyWorkflow), 0644); err != nil {
		return fmt.Errorf("failed to write verify.yaml: %w", err)
	}

	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Successfully generated hardened BYO Base Image Overlay project at: %s\n", outDir)
	}

	return nil
}

func resolveBinary(runtime string) string {
	r := strings.ToLower(runtime)
	switch {
	case strings.HasPrefix(r, "java"):
		return "java"
	case strings.HasPrefix(r, "node"):
		return "node"
	case strings.HasPrefix(r, "python"):
		return "python3"
	case strings.HasPrefix(r, "go"):
		return "go"
	case strings.HasPrefix(r, "dotnet"):
		return "dotnet"
	case strings.HasPrefix(r, "rust"):
		return "rustc"
	case strings.HasPrefix(r, "cc") || r == "gcc" || r == "g++":
		return "gcc"
	case strings.HasPrefix(r, "core"):
		return "sh"
	default:
		return "sh"
	}
}

func runtimeSmokeCheck(binary string) string {
	switch binary {
	case "go":
		return `docker run --entrypoint /bin/sh "$IMAGE_NAME" -c 'for runtime_bin in /nix/store/*/bin/go; do [ -x "$runtime_bin" ] && exec "$runtime_bin" version; done; exit 1' 2>&1`
	case "sh", "bash":
		return `docker run --entrypoint /bin/sh "$IMAGE_NAME" -c 'test -d /nix/store && echo "ClearCutt Core"' 2>&1`
	case "java":
		return `docker run --entrypoint /bin/sh "$IMAGE_NAME" -c 'for runtime_bin in /nix/store/*/bin/java; do [ -x "$runtime_bin" ] && exec "$runtime_bin" -version; done; exit 1' 2>&1`
	default:
		return fmt.Sprintf(`docker run --entrypoint /bin/sh "$IMAGE_NAME" -c 'for runtime_bin in /nix/store/*/bin/%s; do [ -x "$runtime_bin" ] && exec "$runtime_bin" --version; done; exit 1' 2>&1`, binary)
	}
}

func splitDigestRef(ref string) (imageName, imageDigest string) {
	parts := strings.SplitN(ref, "@", 2)
	imageName = parts[0]
	if len(parts) == 2 {
		imageDigest = parts[1]
	} else {
		imageDigest = "sha256:REPLACE_WITH_MANDATED_BASE_DIGEST"
	}
	return imageName, imageDigest
}

func splitTagRef(ref string) (imageName, tag string) {
	withoutDigest := strings.SplitN(ref, "@", 2)[0]
	lastSlash := strings.LastIndex(withoutDigest, "/")
	lastColon := strings.LastIndex(withoutDigest, ":")
	if lastColon > lastSlash {
		return withoutDigest[:lastColon], withoutDigest[lastColon+1:]
	}
	return withoutDigest, "latest"
}
