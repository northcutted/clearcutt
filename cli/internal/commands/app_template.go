package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/spf13/cobra"
)

type appTemplateFlags struct {
	configPath string
	outputDir  string
	name       string
	force      bool
}

var appTemplateOpts appTemplateFlags

const (
	currentClearCuttRelease = "v0.17.0"

	appTemplateCheckoutAction    = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2"
	appTemplateDockerLoginAction = "docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee # v4.2.0"
	appTemplateDockerBuildAction = "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8 # v6"
	appTemplateCosignInstaller   = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2"
	appTemplateSBOMAction        = "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0"
	appTemplateBuildProvenance   = "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be # v2.4.0"
	appTemplateAttestSBOM        = "actions/attest-sbom@bd218ad0dbcb3e146bd073d1d9c6d78e08aa8a0b # v2.4.0"
)

var supportedAppTemplateRuntimes = []string{"java", "node", "python", "go", "ruby"}

type appTemplateSpec struct {
	Runtime       string
	RuntimeLine   string
	BaseID        string
	AppName       string
	ClearCuttRepo string
	ClearCuttTag  string
	DevImage      string
	RuntimeImage  string
	Entrypoint    string
	Files         map[string]string
}

func newAppTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template <runtime>",
		Short: "Generate an app-team starter using ClearCutt dev, certify, and rebase flows",
		Long: `Generate an app-team starter using ClearCutt dev, certify, and rebase
flows. The runtime must be enabled in clearcutt.fleet.yaml templates.runtimes
(defaults: java, node, python, go). Supported template generators are java,
node, python, go, and ruby. Other custom runtime lines can be built by the
platform fleet, but they need a ClearCutt template generator before app template
can scaffold an application for them.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime := strings.ToLower(args[0])
			cfg, err := fleet.Load(appTemplateOpts.configPath)
			if err != nil {
				return fmt.Errorf("load fleet config: %w", err)
			}
			outputDir := appTemplateOpts.outputDir
			if outputDir == "" {
				outputDir = "clearcutt-template-" + runtime
			}
			appName := appTemplateOpts.name
			if appName == "" {
				appName = "clearcutt-template-" + runtime
			}
			written, err := writeAppTemplate(cfg, runtime, appName, outputDir, appTemplateOpts.force)
			if err != nil {
				return err
			}
			for _, path := range written {
				fmt.Fprintf(out, "wrote %s\n", path)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&appTemplateOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	cmd.Flags().StringVar(&appTemplateOpts.outputDir, "output", "", "Output directory (default clearcutt-template-<runtime>)")
	cmd.Flags().StringVar(&appTemplateOpts.name, "name", "", "Application/template name")
	cmd.Flags().BoolVar(&appTemplateOpts.force, "force", false, "Overwrite existing files")
	return cmd
}

func writeAppTemplate(cfg fleet.Config, runtime, appName, outputDir string, force bool) ([]string, error) {
	spec, err := buildAppTemplateSpec(cfg, runtime, appName)
	if err != nil {
		return nil, err
	}
	written := []string{}
	for name, body := range spec.Files {
		path := filepath.Join(outputDir, name)
		if err := writeGeneratedFile(path, []byte(body), force); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

func buildAppTemplateSpec(cfg fleet.Config, runtime, appName string) (appTemplateSpec, error) {
	if !appTemplateRuntimeSupported(runtime) {
		return appTemplateSpec{}, fmt.Errorf("unsupported app template runtime %q (supported: %s)", runtime, supportedAppTemplateRuntimeList())
	}
	if !templateRuntimeEnabled(cfg, runtime) {
		return appTemplateSpec{}, fmt.Errorf("app template runtime %q is supported but not enabled in templates.runtimes; enable it in clearcutt.fleet.yaml or run runtime scaffold", runtime)
	}
	spec := appTemplateSpec{
		Runtime:       runtime,
		AppName:       appName,
		ClearCuttRepo: cfg.RepoPath(),
		ClearCuttTag:  currentClearCuttRelease,
		Files:         map[string]string{},
	}
	switch runtime {
	case "java":
		spec.RuntimeLine = "java21"
		spec.BaseID = "java21-distroless"
		spec.Entrypoint = `["java","-jar","/workspace/app.jar"]`
		spec.Files["pom.xml"] = javaPom(appName)
		spec.Files["src/main/java/dev/clearcutt/template/App.java"] = `package dev.clearcutt.template;

public final class App {
  private App() {}

  public static void main(String[] args) {
    System.out.println("ClearCutt Java template ready");
  }
}
`
	case "node":
		spec.RuntimeLine = "node22"
		spec.BaseID = "node22-distroless"
		spec.Entrypoint = `["node","/workspace/server.js"]`
		spec.Files["package.json"] = fmt.Sprintf(`{"name":"%s","version":"1.0.0","private":true,"type":"module","scripts":{"test":"node --check src/server.js","build":"mkdir -p dist && cp src/server.js dist/server.js"}}
`, appName)
		spec.Files["src/server.js"] = `console.log("ClearCutt Node template ready");
`
	case "python":
		spec.RuntimeLine = "python3.14"
		spec.BaseID = "python3.14-distroless"
		spec.Entrypoint = `["python","/workspace/app/main.py"]`
		spec.Files["requirements.txt"] = ""
		spec.Files["app/main.py"] = `print("ClearCutt Python template ready")
`
	case "go":
		spec.RuntimeLine = "go1.25"
		spec.BaseID = "go1.25-distroless"
		spec.Entrypoint = `["/workspace/app"]`
		spec.Files["go.mod"] = fmt.Sprintf("module example.com/%s\n\ngo 1.25\n", strings.ReplaceAll(appName, "-", ""))
		spec.Files["cmd/app/main.go"] = `package main

import "fmt"

func main() {
	fmt.Println("ClearCutt Go template ready")
}
`
	case "ruby":
		spec.RuntimeLine = templateRuntimeLine(cfg, "ruby", "ruby3.4")
		spec.BaseID = spec.RuntimeLine + "-distroless"
		spec.Entrypoint = `["ruby","/workspace/app.rb"]`
		spec.Files["Gemfile"] = `source "https://rubygems.org"
`
		spec.Files["app.rb"] = `puts "ClearCutt Ruby template ready"
`
	default:
		return spec, fmt.Errorf("unsupported app template runtime %q", runtime)
	}
	spec.DevImage = cfg.ImageName(spec.RuntimeLine) + ":dev"
	spec.RuntimeImage = cfg.ImageName(spec.RuntimeLine) + ":distroless"
	spec.Files["README.md"] = templateReadme(spec)
	spec.Files["Dockerfile"] = templateDockerfile(spec)
	spec.Files["certification-policy.yaml"] = templateCertificationPolicy(spec)
	spec.Files[".github/workflows/release.yml"] = templateReleaseWorkflow(spec)
	spec.Files[".github/workflows/rebase.yml"] = templateRebaseWorkflow(spec, cfg)
	spec.Files[".devcontainer/devcontainer.json"] = templateDevContainer(spec)
	return spec, nil
}

func templateRuntimeEnabled(cfg fleet.Config, runtime string) bool {
	for _, enabled := range cfg.Templates.Runtimes {
		if strings.EqualFold(enabled, runtime) {
			return true
		}
	}
	return false
}

func appTemplateRuntimeSupported(runtime string) bool {
	for _, supported := range supportedAppTemplateRuntimes {
		if strings.EqualFold(supported, runtime) {
			return true
		}
	}
	return false
}

func supportedAppTemplateRuntimeList() string {
	return strings.Join(supportedAppTemplateRuntimes, ", ")
}

func templateReadme(spec appTemplateSpec) string {
	return fmt.Sprintf(`# %s

This starter app is the app-team path for one ClearCutt runtime line. It keeps
Nix in the platform fleet and uses normal container tooling for application
delivery.

- build stage: %s
- runtime stage: %s
- ClearCutt CLI release: %s@%s (checksum and Sigstore bundle verified in CI)
- base id for policy/rebase: %s

## Local path

The generated policy requires a digest-pinned image reference. Push the image,
resolve the registry digest, and pass that immutable ref to certification:

~~~bash
APP_IMAGE=ghcr.io/acme/%s:1.0.0
docker build -t "$APP_IMAGE" .
docker push "$APP_IMAGE"
APP_DIGEST=$(docker buildx imagetools inspect "$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save "$APP_IMAGE" -o %s.tar
clearcutt certify %s.tar --base %s --policy certification-policy.yaml --image-ref "${APP_IMAGE%%:*}@${APP_DIGEST}"
~~~

Open this repository in a devcontainer to build with the matching ClearCutt dev
image, then ship the final app image from the runtime stage.

## CI path

The release workflow builds, signs, attests, and certifies the image. The rebase
workflow lets a platform workflow move the app layer onto a patched ClearCutt
base without recompiling the application.
These are starter workflows; fork owners must pin identities, registry
permissions, branch policy, and admission rules before production use.
`, spec.AppName, spec.DevImage, spec.RuntimeImage, spec.ClearCuttRepo, spec.ClearCuttTag, spec.BaseID, spec.AppName, spec.AppName, spec.AppName, spec.BaseID)
}

func templateDockerfile(spec appTemplateSpec) string {
	switch spec.Runtime {
	case "java":
		return fmt.Sprintf(`FROM %s AS builder
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B package

FROM %s
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="%s"
WORKDIR /workspace
COPY --from=builder /workspace/target/app.jar /workspace/app.jar
ENTRYPOINT %s
`, spec.DevImage, spec.RuntimeImage, spec.BaseID, spec.Entrypoint)
	case "node":
		return fmt.Sprintf(`FROM %s AS builder
WORKDIR /workspace
COPY package.json .
COPY src ./src
RUN npm test && npm run build

FROM %s
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="%s"
WORKDIR /workspace
COPY --from=builder /workspace/dist/server.js /workspace/server.js
ENTRYPOINT %s
`, spec.DevImage, spec.RuntimeImage, spec.BaseID, spec.Entrypoint)
	case "python":
		return fmt.Sprintf(`FROM %s AS builder
WORKDIR /workspace
COPY requirements.txt .
COPY app ./app
RUN python -m compileall app

FROM %s
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="%s"
WORKDIR /workspace
COPY --from=builder /workspace/app /workspace/app
ENTRYPOINT %s
`, spec.DevImage, spec.RuntimeImage, spec.BaseID, spec.Entrypoint)
	case "go":
		return fmt.Sprintf(`FROM %s AS builder
WORKDIR /workspace
COPY go.mod .
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /workspace/app ./cmd/app

FROM %s
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="%s"
WORKDIR /workspace
COPY --from=builder /workspace/app /workspace/app
ENTRYPOINT %s
`, spec.DevImage, spec.RuntimeImage, spec.BaseID, spec.Entrypoint)
	case "ruby":
		return fmt.Sprintf(`FROM %s AS builder
WORKDIR /workspace
COPY Gemfile .
COPY app.rb .
RUN ruby -c app.rb

FROM %s
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="%s"
WORKDIR /workspace
COPY --from=builder /workspace/app.rb /workspace/app.rb
ENTRYPOINT %s
`, spec.DevImage, spec.RuntimeImage, spec.BaseID, spec.Entrypoint)
	default:
		return ""
	}
}

func templateRuntimeLine(cfg fleet.Config, runtime, fallback string) string {
	for _, line := range cfg.RuntimeLines {
		if line.AppTemplateRuntime == runtime {
			return line.ID
		}
	}
	return fallback
}

func templateCertificationPolicy(spec appTemplateSpec) string {
	return fmt.Sprintf(`apiVersion: clearcutt.dev/v1
kind: CertificationPolicy
metadata:
  name: %s-policy
spec:
  base:
    allowedImages:
      - %s
    requireDigestPinned: true
    requireKnownBase: true
  supplyChain:
    requireSignature: true
    requireProvenance: true
    requireSbom: true
    minimumSlsaLevel: 3
  runtime:
    requireNonRoot: true
    forbidShell: true
    forbidPackageManagers: true
    forbidDevTier: true
  lifecycle:
    allowPreview: false
    allowDeprecated: false
    allowExperimental: false
  vulnerabilities:
    maxCritical: 0
    maxHigh: 3
    allowExceptions: true
    exceptionFile: exceptions.yaml
`, spec.AppName, spec.BaseID)
}

func templateReleaseWorkflow(spec appTemplateSpec) string {
	return fmt.Sprintf(`name: Build, Sign, Attest, and Certify

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  packages: write
  id-token: write
  attestations: write

env:
  IMAGE: ghcr.io/${{ github.repository }}/%s:latest

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: %s

      - uses: %s
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: %s
        id: build
        with:
          context: .
          push: true
          tags: ${{ env.IMAGE }}

%s

      - name: Sign image digest
        run: cosign sign --yes "${IMAGE}@${{ steps.build.outputs.digest }}"

      - name: Generate SPDX SBOM
        uses: %s
        with:
          image: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Attach cosign SBOM attestation
        run: cosign attest --yes --type spdxjson --predicate sbom.spdx.json "${IMAGE}@${{ steps.build.outputs.digest }}"

      - name: Attach GitHub build provenance
        uses: %s
        with:
          subject-name: ${{ env.IMAGE }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true

      - name: Attach GitHub SBOM attestation
        uses: %s
        with:
          subject-name: ${{ env.IMAGE }}
          subject-digest: ${{ steps.build.outputs.digest }}
          sbom-path: sbom.spdx.json
          push-to-registry: true

      - name: Save image for offline certification
        run: |
          docker pull "${IMAGE}@${{ steps.build.outputs.digest }}"
          docker save "${IMAGE}@${{ steps.build.outputs.digest }}" -o app-image.tar

      - name: Certify image against ClearCutt contracts
        run: |
          clearcutt certify app-image.tar \
            --base %s \
            --policy certification-policy.yaml \
            --image-ref "${IMAGE}@${{ steps.build.outputs.digest }}"
`, spec.AppName, appTemplateCheckoutAction, appTemplateDockerLoginAction, appTemplateDockerBuildAction, templateVerifiedClearCuttInstall(spec.ClearCuttRepo), appTemplateSBOMAction, appTemplateBuildProvenance, appTemplateAttestSBOM, spec.BaseID)
}

func templateRebaseWorkflow(spec appTemplateSpec, cfg fleet.Config) string {
	return fmt.Sprintf(`name: Rebase on Patched ClearCutt Base

on:
  workflow_dispatch:
    inputs:
      image:
        description: Source app image digest to rebase
        required: true
      candidate-base:
        description: Patched ClearCutt base reference
        required: true
        default: %s
      tag:
        description: Target rebased image reference
        required: true

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  rebase:
    runs-on: ubuntu-latest
    steps:
%s

      - name: Check base compatibility
        run: |
          clearcutt app diff-base \
            --image "${{ inputs.image }}" \
            --candidate-base "${{ inputs.candidate-base }}" \
            --candidate-base-id %s \
            --fail-on-incompatible

      - name: Rebase, sign, and attest
        run: |
          clearcutt app rebase \
            --image "${{ inputs.image }}" \
            --candidate-base "${{ inputs.candidate-base }}" \
            --candidate-base-id %s \
            --tag "${{ inputs.tag }}" \
            --dev-identity "https://github.com/${{ github.repository }}/.github/workflows/release.yml@refs/heads/main" \
            --sign \
            --attest
`, spec.RuntimeImage, templateVerifiedClearCuttInstall(cfg.RepoPath()), spec.BaseID, spec.BaseID)
}

func templateVerifiedClearCuttInstall(repoPath string) string {
	return fmt.Sprintf(`      - uses: %s

      - name: Install verified ClearCutt CLI
        shell: bash
        run: |
          set -euo pipefail
          VERSION="%s"
          REPO="%s"
          ASSET="clearcutt-linux-amd64"
          BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
          SIGNING_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/heads/main"
          curl -fsSL -o "${RUNNER_TEMP}/${ASSET}" "${BASE_URL}/${ASSET}"
          curl -fsSL -o "${RUNNER_TEMP}/${ASSET}.sig" "${BASE_URL}/${ASSET}.sig"
          curl -fsSL -o "${RUNNER_TEMP}/SHA256SUMS.txt" "${BASE_URL}/SHA256SUMS.txt"
          (
            cd "${RUNNER_TEMP}"
            grep -E "  ${ASSET}$" SHA256SUMS.txt | sha256sum -c -
          )
          cosign verify-blob "${RUNNER_TEMP}/${ASSET}" \
            --bundle "${RUNNER_TEMP}/${ASSET}.sig" \
            --certificate-identity "${SIGNING_IDENTITY}" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
          install -m 0755 "${RUNNER_TEMP}/${ASSET}" "${RUNNER_TEMP}/clearcutt"
          echo "${RUNNER_TEMP}" >> "$GITHUB_PATH"
          clearcutt --version`, appTemplateCosignInstaller, currentClearCuttRelease, repoPath)
}

func templateDevContainer(spec appTemplateSpec) string {
	return fmt.Sprintf(`{
  "name": "%s",
  "image": "%s",
  "workspaceFolder": "/workspace",
  "remoteUser": "10001",
  "containerEnv": {
    "CLEARCUTT_IMAGE_ID": "%s-dev"
  }
}
`, spec.AppName, spec.DevImage, spec.RuntimeLine)
}

func javaPom(appName string) string {
	return fmt.Sprintf(`<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.clearcutt.template</groupId>
  <artifactId>%s</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.target>21</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <build>
    <finalName>app</finalName>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-jar-plugin</artifactId>
        <version>3.4.1</version>
        <configuration>
          <archive>
            <manifest>
              <mainClass>dev.clearcutt.template.App</mainClass>
            </manifest>
          </archive>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
`, appName)
}

func writeGeneratedFile(path string, data []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (pass --force to overwrite)", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
