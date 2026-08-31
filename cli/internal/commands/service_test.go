package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt/internal/build"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/oci"
)

func TestServiceScaffoldValidateExplainAndMatrix(t *testing.T) {
	oldServiceOpts := serviceOpts
	defer func() { serviceOpts = oldServiceOpts }()

	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")

	stdout, err := runCLI(t,
		"service", "scaffold", "postgres16",
		"--template", "postgres",
		"--version", "16",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service scaffold failed: %v\n%s", err, stdout)
	}
	loaded, err := fleet.Load(configPath)
	if err != nil {
		t.Fatalf("load scaffolded fleet: %v", err)
	}
	service, ok := loaded.ServiceInfo("postgres16")
	if !ok || service.Template != "postgres" || service.Ports[0].Port != 5432 {
		t.Fatalf("unexpected scaffolded service: %#v", service)
	}
	extension, err := os.ReadFile(filepath.Join(coreDir, "lib", "service-extensions.nix"))
	if err != nil {
		t.Fatalf("read service extension: %v", err)
	}
	for _, want := range []string{`id = "postgres16";`, `template = "postgres";`, `packageCandidates = [ "postgresql_16" ];`} {
		if !strings.Contains(string(extension), want) {
			t.Fatalf("service extension missing %q:\n%s", want, extension)
		}
	}

	stdout, err = runCLI(t, "service", "validate", "--all", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, "service.template") || !strings.Contains(stdout, "service.extension") {
		t.Fatalf("service validate failed: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "service", "validate", "postgres16", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, "postgres16") || !strings.Contains(stdout, "service.template") {
		t.Fatalf("service validate one service failed: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "service", "validate", "--fleet-config", configPath, "--core-dir", coreDir)
	if err == nil || !strings.Contains(err.Error(), "pass a service id or --all") {
		t.Fatalf("expected service validate to require id or --all, got err=%v stdout=\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "service", "validate", "postgres16", "--all", "--fleet-config", configPath, "--core-dir", coreDir)
	if err == nil || !strings.Contains(err.Error(), "--all cannot be used with a service id") {
		t.Fatalf("expected service validate id/--all conflict, got err=%v stdout=\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "--format", "json", "service", "explain", "postgres16", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, `"template": "postgres"`) || !strings.Contains(stdout, `"image": "ghcr.io/acme/platform/platform-postgres16"`) {
		t.Fatalf("service explain failed: %v\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "service", "explain", "postgres16", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, "FIELD") || !strings.Contains(stdout, "5432/tcp") {
		t.Fatalf("service explain table failed: %v\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "--format", "yaml", "service", "explain", "postgres16", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, "template: postgres") || !strings.Contains(stdout, "productionAllowed: false") {
		t.Fatalf("service explain YAML failed: %v\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "--format", "json", "service", "validate", "--all", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, `"id": "postgres16"`) || !strings.Contains(stdout, `"status": "pass"`) {
		t.Fatalf("service validate JSON failed: %v\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "--format", "json", "service", "matrix", "--github-actions", "--matrix", "image", "--fleet-config", configPath)
	if err != nil || !strings.Contains(stdout, `"service": "postgres16"`) {
		t.Fatalf("service matrix failed: %v\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "--format", "yaml", "service", "matrix", "--fleet-config", configPath)
	if err != nil || !strings.Contains(stdout, "id: postgres16") || !strings.Contains(stdout, "template: postgres") {
		t.Fatalf("service matrix YAML failed: %v\n%s", err, stdout)
	}
}

func flattenServiceCalls(calls []externalCommand) string {
	lines := make([]string, 0, len(calls))
	for _, call := range calls {
		lines = append(lines, call.Name+" "+strings.Join(call.Args, " "))
	}
	return strings.Join(lines, "\n")
}

func TestServicePublishGoEnginePublishesAndStagesEvidence(t *testing.T) {
	oldServiceOpts := serviceOpts
	oldRunner := fleetBuildRunner
	oldPush := fleetPushImageArchive
	defer func() {
		serviceOpts = oldServiceOpts
		fleetBuildRunner = oldRunner
		fleetPushImageArchive = oldPush
	}()

	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t,
		"service", "scaffold", "postgres16",
		"--template", "postgres",
		"--version", "16",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	); err != nil {
		t.Fatalf("service scaffold failed: %v", err)
	}

	// A real gzipped docker archive: the engine gunzips it for Syft.
	serviceArchiveRaw, err := os.ReadFile(gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-postgresql-16/bin/postgres": 0o755,
	})))
	if err != nil {
		t.Fatal(err)
	}
	fleetBuildRunner = func() build.Runner {
		return &fakeFleetBuildRunner{archive: serviceArchiveRaw}
	}
	var pushedRef, pushedArchive string
	fleetPushImageArchive = func(client *oci.Client, ref, archivePath string) (string, error) {
		pushedRef = ref
		pushedArchive = archivePath
		return "sha256:service-stage", nil
	}

	stdout, err := runCLI(t,
		"service", "publish", "postgres16",
		"--system", "aarch64-linux",
		"--version-tag", "v1.2.3",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service publish go engine failed: %v\n%s", err, stdout)
	}
	outputDir := filepath.Join(coreDir, "build-outputs")
	if pushedArchive != filepath.Join(outputDir, "postgres16.tar.gz") {
		t.Fatalf("pushed archive = %q", pushedArchive)
	}
	if pushedRef != "ghcr.io/acme/platform/platform-postgres16:_stage-service-arm64" {
		t.Fatalf("pushed ref = %q", pushedRef)
	}
	for _, name := range []string{"postgres16-arm64.sbom.json", "postgres16-arm64.test-results.json"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("expected staged service release asset %s: %v", name, err)
		}
	}
	if !strings.Contains(stdout, "Go engine") || !strings.Contains(stdout, "sha256:service-stage") {
		t.Fatalf("expected Go engine digest output, got:\n%s", stdout)
	}
}

func TestServiceScaffoldForceAndCustomTemplateOptions(t *testing.T) {
	oldServiceOpts := serviceOpts
	defer func() { serviceOpts = oldServiceOpts }()

	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")
	args := []string{
		"service", "scaffold", "oauth2-proxy7",
		"--template", "oauth2-proxy",
		"--version", "7",
		"--description", "Edge OAuth proxy",
		"--package", "oauth2-proxy_7",
		"--port", "http:4180/tcp",
		"--env", "OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180",
		"--entrypoint", "oauth2-proxy",
		"--cmd=--http-address=0.0.0.0:4180",
		"--smoke", "oauth2-proxy --version",
		"--production-allowed",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	}
	stdout, err := runCLI(t, args...)
	if err != nil {
		t.Fatalf("service scaffold custom failed: %v\n%s", err, stdout)
	}
	args = append(args, "--force")
	stdout, err = runCLI(t, args...)
	if err != nil || !strings.Contains(stdout, "updated oauth2-proxy7") {
		t.Fatalf("service scaffold --force failed: %v\n%s", err, stdout)
	}
	loaded, err := fleet.Load(configPath)
	if err != nil {
		t.Fatalf("load custom service config: %v", err)
	}
	service, ok := loaded.ServiceInfo("oauth2-proxy7")
	if !ok {
		t.Fatal("oauth2-proxy7 should resolve")
	}
	if service.Description != "Edge OAuth proxy" || service.PackageCandidates[0] != "oauth2-proxy_7" || !service.ProductionAllowed {
		t.Fatalf("custom service options were not preserved: %#v", service)
	}
	if len(service.Cmd) != 1 || service.Cmd[0] != "--http-address=0.0.0.0:4180" || len(service.Env) != 1 {
		t.Fatalf("custom argv/env options were not preserved: %#v", service)
	}
	extension, err := os.ReadFile(filepath.Join(coreDir, "lib", "service-extensions.nix"))
	if err != nil {
		t.Fatalf("read service extension: %v", err)
	}
	for _, want := range []string{`description = "Edge OAuth proxy";`, `env = [ "OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180" ];`, `productionAllowed = true;`} {
		if !strings.Contains(string(extension), want) {
			t.Fatalf("service extension missing %q:\n%s", want, extension)
		}
	}
}

func TestServiceSmokeNixEvalMatrixAndPortBranches(t *testing.T) {
	oldServiceOpts := serviceOpts
	oldRun := runExternalCommand
	oldSleep := serviceSmokeSleep
	defer func() {
		serviceOpts = oldServiceOpts
		runExternalCommand = oldRun
		serviceSmokeSleep = oldSleep
	}()
	serviceSmokeSleep = func(_ time.Duration) {}

	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")
	stdout, err := runCLI(t,
		"service", "scaffold", "custom-postgres",
		"--template", "postgres",
		"--version", "16",
		"--port", "db:15432/tcp,metrics:9187/udp",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service scaffold with ports failed: %v\n%s", err, stdout)
	}

	var calls []externalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}

	stdout, err = runCLI(t, "--format", "yaml", "service", "validate", "custom-postgres", "--nix", "--system", "x86_64-linux", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil || !strings.Contains(stdout, "service.nix") {
		t.Fatalf("service validate --nix failed: %v\n%s", err, stdout)
	}
	if len(calls) == 0 || calls[0].Name != "nix" || !strings.Contains(strings.Join(calls[0].Args, " "), `.#packages.x86_64-linux."custom-postgres".name`) {
		t.Fatalf("expected nix eval call, got %#v", calls)
	}

	calls = nil
	stdout, err = runCLI(t, "service", "smoke", "custom-postgres", "--engine", "podman", "--image", "local/custom-postgres:service", "--fleet-config", configPath)
	if err != nil {
		t.Fatalf("service smoke failed: %v\n%s", err, stdout)
	}
	if len(calls) != 6 {
		t.Fatalf("expected postgres command smoke plus functional smoke, got %#v", calls)
	}
	for _, call := range calls[:3] {
		if call.Name != "podman" || !strings.Contains(strings.Join(call.Args, " "), "--entrypoint") {
			t.Fatalf("unexpected smoke command: %#v", call)
		}
	}
	postgresCalls := flattenServiceCalls(calls)
	for _, want := range []string{
		"podman run -d --name clearcutt-smoke-custom-postgres-",
		"podman exec clearcutt-smoke-custom-postgres-",
		"pg_isready -h 127.0.0.1 -p 5432",
		"podman rm -f clearcutt-smoke-custom-postgres-",
	} {
		if !strings.Contains(postgresCalls, want) {
			t.Fatalf("expected functional smoke call %q in:\n%s", want, postgresCalls)
		}
	}

	calls = nil
	stdout, err = runCLI(t, "service", "smoke", "custom-postgres", "--command-only", "--engine", "podman", "--image", "local/custom-postgres:service", "--fleet-config", configPath)
	if err != nil {
		t.Fatalf("service smoke --command-only failed: %v\n%s", err, stdout)
	}
	if len(calls) != 3 {
		t.Fatalf("expected command-only smoke to run three commands, got %#v", calls)
	}

	stdout, err = runCLI(t,
		"service", "scaffold", "custom-valkey",
		"--template", "valkey",
		"--version", "8",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service scaffold valkey failed: %v\n%s", err, stdout)
	}
	calls = nil
	stdout, err = runCLI(t, "service", "smoke", "custom-valkey", "--engine", "podman", "--image", "local/custom-valkey:service", "--fleet-config", configPath)
	if err != nil {
		t.Fatalf("valkey service smoke failed: %v\n%s", err, stdout)
	}
	if len(calls) != 5 {
		t.Fatalf("expected valkey command smoke plus functional smoke, got %#v", calls)
	}
	joinedCalls := flattenServiceCalls(calls)
	for _, want := range []string{
		"podman run -d --name clearcutt-smoke-custom-valkey-",
		"podman exec clearcutt-smoke-custom-valkey-",
		"valkey-cli -h 127.0.0.1 -p 6379 PING",
		"podman rm -f clearcutt-smoke-custom-valkey-",
	} {
		if !strings.Contains(joinedCalls, want) {
			t.Fatalf("expected functional smoke call %q in:\n%s", want, joinedCalls)
		}
	}

	stdout, err = runCLI(t, "service", "smoke", "custom-postgres", "--engine", "nerdctl", "--fleet-config", configPath)
	if err == nil || !strings.Contains(err.Error(), "--engine must be docker or podman") {
		t.Fatalf("expected invalid engine error, got err=%v stdout=\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "service", "validate", "missing", "--fleet-config", configPath, "--core-dir", coreDir)
	if !errors.Is(err, ErrCheckFailed) || !strings.Contains(stdout, "service.configured") {
		t.Fatalf("expected missing service validation failure, got err=%v stdout=\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "service", "matrix", "--fleet-config", configPath)
	if err != nil || !strings.Contains(stdout, "custom-postgres") {
		t.Fatalf("service matrix table failed: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "service", "matrix", "--github-actions", "--matrix", "bad", "--fleet-config", configPath)
	if err == nil || !strings.Contains(err.Error(), "--matrix must be release or image") {
		t.Fatalf("expected bad matrix error, got err=%v stdout=\n%s", err, stdout)
	}
	if _, err := parseServicePort("db:not-a-port"); err == nil {
		t.Fatal("expected invalid service port parse error")
	}
	if _, err := parseServicePort("db:5432/sctp"); err == nil {
		t.Fatal("expected invalid service protocol parse error")
	}
}

func TestServiceValidationHelperBranches(t *testing.T) {
	oldServiceOpts := serviceOpts
	defer func() { serviceOpts = oldServiceOpts }()

	serviceOpts = serviceFlags{
		coreDir: t.TempDir(),
		system:  "",
	}
	cfg := fleet.DefaultConfig("acme", "platform")
	service := fleet.ServiceImage{
		ID:                "custom",
		Template:          "unknown",
		Version:           "1",
		PackageCandidates: []string{"custom-package"},
		ProductionAllowed: true,
	}
	result, failed := validateService(cfg, service)
	if !failed || result.Status != "fail" {
		t.Fatalf("expected helper validation failure, got failed=%v result=%#v", failed, result)
	}
	seen := map[string]string{}
	for _, check := range result.Checks {
		seen[check.ID] = check.Status
	}
	for id, status := range map[string]string{
		"service.template":   "fail",
		"service.packages":   "pass",
		"service.ports":      "warn",
		"service.storage":    "pass",
		"service.production": "pass",
		"service.extension":  "fail",
	} {
		if seen[id] != status {
			t.Fatalf("expected %s=%s, got checks %#v", id, status, result.Checks)
		}
	}
	if err := runServiceNixEval(service); err == nil || !strings.Contains(err.Error(), "--system must not be empty") {
		t.Fatalf("expected empty system validation error, got %v", err)
	}
	if entrypoint, args := splitSmokeCommand(" \t "); entrypoint != "" || args != nil {
		t.Fatalf("empty smoke command should be ignored, got %q %#v", entrypoint, args)
	}
}

func TestServiceFunctionalSmokeFailureDumpsLogsAndCleansUp(t *testing.T) {
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	oldSleep := serviceSmokeSleep
	defer func() {
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
		serviceSmokeSleep = oldSleep
	}()
	serviceSmokeSleep = func(_ time.Duration) {}

	var calls []externalCommand
	logsCalled := false
	inspectCalled := false
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		if len(c.Args) > 0 && c.Args[0] == "exec" {
			return errors.New("not ready")
		}
		return nil
	}
	captureExternalOutput = func(c externalCommand) (string, error) {
		if len(c.Args) > 0 && c.Args[0] == "logs" {
			logsCalled = true
			return "database boot log", nil
		}
		if len(c.Args) > 0 && c.Args[0] == "inspect" {
			inspectCalled = true
			return `{"ExitCode":127,"Error":"missing interpreter"}`, nil
		}
		return "", nil
	}

	err := runServiceFunctionalSmoke("docker", fleet.ServiceImage{ID: "valkey8", Template: "valkey"}, "local/valkey8:service")
	if err == nil || !strings.Contains(err.Error(), "functional smoke probe failed") {
		t.Fatalf("expected functional smoke failure, got %v", err)
	}
	if !logsCalled {
		t.Fatal("expected failed functional smoke to collect container logs")
	}
	if !inspectCalled {
		t.Fatal("expected failed functional smoke to inspect container state")
	}
	joined := flattenServiceCalls(calls)
	if !strings.Contains(joined, "docker rm -f clearcutt-smoke-valkey8-") {
		t.Fatalf("expected failed functional smoke to clean up container, got:\n%s", joined)
	}

	calls = nil
	err = runServiceFunctionalSmoke("docker", fleet.ServiceImage{ID: "postgres16", Template: "postgres"}, "local/postgres:service")
	if err == nil || !strings.Contains(err.Error(), "postgres functional smoke probe failed") {
		t.Fatalf("expected postgres functional smoke failure, got %v", err)
	}
	if joined := flattenServiceCalls(calls); !strings.Contains(joined, "pg_isready -h 127.0.0.1 -p 5432") || !strings.Contains(joined, "docker rm -f clearcutt-smoke-postgres16-") {
		t.Fatalf("expected postgres probe and cleanup calls, got:\n%s", joined)
	}

	calls = nil
	err = runServiceFunctionalSmoke("docker", fleet.ServiceImage{ID: "oauth2-proxy7", Template: "oauth2-proxy"}, "local/oauth:service")
	if err != nil || len(calls) != 0 {
		t.Fatalf("oauth2-proxy should not run a functional profile, err=%v calls=%#v", err, calls)
	}
}

func TestServiceAssembleAndExportProvenance(t *testing.T) {
	oldServiceOpts := serviceOpts
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	oldPushIndex := fleetPushImageIndex
	defer func() {
		serviceOpts = oldServiceOpts
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
		fleetPushImageIndex = oldPushIndex
	}()

	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")
	if _, err := runCLI(t,
		"service", "scaffold", "postgres16",
		"--template", "postgres",
		"--version", "16",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	); err != nil {
		t.Fatalf("service scaffold failed: %v", err)
	}
	buildOutputs := filepath.Join(root, "build-outputs")
	githubOutput := filepath.Join(root, "github-output.txt")
	var calls []externalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	var indexCalls []struct {
		ref     string
		sources []oci.IndexImage
	}
	fleetPushImageIndex = func(client *oci.Client, ref string, sources []oci.IndexImage) (string, error) {
		indexCalls = append(indexCalls, struct {
			ref     string
			sources []oci.IndexImage
		}{ref: ref, sources: append([]oci.IndexImage(nil), sources...)})
		return "sha256:service-digest", nil
	}
	var provenanceRefs []string
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name == "nix" && strings.Contains(strings.Join(c.Args, " "), "--command cosign download attestation") {
			if len(c.Args) > 0 {
				provenanceRefs = append(provenanceRefs, c.Args[len(c.Args)-1])
			}
			return "provenance\n", nil
		}
		return "", nil
	}

	stdout, err := runCLI(t,
		"service", "assemble", "postgres16",
		"--version-tag", "v1.2.3",
		"--build-outputs", buildOutputs,
		"--github-output", githubOutput,
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service assemble failed: %v\n%s", err, stdout)
	}
	if len(indexCalls) != 2 {
		t.Fatalf("expected rolling and versioned service index pushes, got %#v", indexCalls)
	}
	if indexCalls[0].ref != "ghcr.io/acme/platform/platform-postgres16:service" ||
		indexCalls[1].ref != "ghcr.io/acme/platform/platform-postgres16:v1.2.3-service" {
		t.Fatalf("unexpected service index refs: %#v", indexCalls)
	}
	if len(indexCalls[0].sources) != 2 {
		t.Fatalf("unexpected service index sources: %#v", indexCalls[0].sources)
	}
	if len(calls) < 4 {
		t.Fatalf("expected cosign sign/attest calls, got %#v", calls)
	}
	joinedCalls := flattenServiceCalls(calls)
	if strings.Contains(joinedCalls, "crane") {
		t.Fatalf("service assemble should not shell out to crane, got %#v", calls)
	}
	for _, want := range []string{
		"nix develop --extra-experimental-features nix-command flakes --accept-flake-config --command cosign sign --yes ghcr.io/acme/platform/platform-postgres16:v1.2.3-service",
		"--command cosign attest --yes --type spdxjson",
		"--command cosign attest --yes --type custom",
	} {
		if !strings.Contains(joinedCalls, want) {
			t.Fatalf("service assemble missing wrapped cosign command %q in:\n%s", want, joinedCalls)
		}
	}
	for _, call := range calls {
		if call.Name == "cosign" {
			t.Fatalf("service assemble should use core-pinned cosign through nix, got direct command: %#v", call)
		}
	}
	digestRaw, err := os.ReadFile(filepath.Join(buildOutputs, "digests", "postgres16.digest.json"))
	if err != nil {
		t.Fatalf("read service digest: %v", err)
	}
	if !strings.Contains(string(digestRaw), `"tier": "service"`) || !strings.Contains(string(digestRaw), `"versionedTag": "v1.2.3-service"`) {
		t.Fatalf("unexpected digest manifest:\n%s", digestRaw)
	}
	ghRaw, err := os.ReadFile(githubOutput)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	if !strings.Contains(string(ghRaw), "digest=sha256:service-digest") {
		t.Fatalf("unexpected github output:\n%s", ghRaw)
	}

	stdout, err = runCLI(t,
		"service", "export-provenance", "postgres16",
		"--build-outputs", buildOutputs,
		"--fleet-config", configPath,
		"--core-dir", coreDir,
		"--ref", "registry.example.com/acme/fleet/service-postgres16@sha256:service-digest",
	)
	if err != nil {
		t.Fatalf("service export-provenance failed: %v\n%s", err, stdout)
	}
	provRaw, err := os.ReadFile(filepath.Join(buildOutputs, "postgres16.intoto.jsonl"))
	if err != nil {
		t.Fatalf("read service provenance: %v", err)
	}
	if !strings.Contains(string(provRaw), "provenance") {
		t.Fatalf("unexpected provenance output:\n%s", provRaw)
	}
	if len(provenanceRefs) != 1 || provenanceRefs[0] != "registry.example.com/acme/fleet/service-postgres16@sha256:service-digest" {
		t.Fatalf("expected immutable service provenance ref, got %#v", provenanceRefs)
	}
}
