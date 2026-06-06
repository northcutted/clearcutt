package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
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

func TestServiceBuildUsesServicePipelineKind(t *testing.T) {
	oldServiceOpts := serviceOpts
	oldRun := runExternalCommand
	defer func() {
		serviceOpts = oldServiceOpts
		runExternalCommand = oldRun
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

	var calls []externalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}

	stdout, err := runCLI(t,
		"service", "build", "postgres16",
		"--system", "x86_64-linux",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service build failed: %v\n%s", err, stdout)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one external command, got %#v", calls)
	}
	call := calls[0]
	if call.Name != "nix" || call.Dir != coreDir {
		t.Fatalf("unexpected command: %#v", call)
	}
	joined := strings.Join(call.Args, " ")
	for _, want := range []string{
		"develop --extra-experimental-features nix-command flakes --accept-flake-config",
		"--command ./pipeline/pipeline.sh",
		"--kind service",
		"--system x86_64-linux",
		"postgres16",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("service build args missing %q in %q", want, joined)
		}
	}
	joinedEnv := strings.Join(call.Env, "\n")
	for _, want := range []string{
		"CLEARCUTT_SERVICE_LIFECYCLE_STATUS=preview",
		"CLEARCUTT_SERVICE_PRODUCTION_ALLOWED=false",
	} {
		if !strings.Contains(joinedEnv, want) {
			t.Fatalf("service build env missing %q in %q", want, joinedEnv)
		}
	}

	outputDir := filepath.Join(coreDir, "build-outputs")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("create build outputs: %v", err)
	}
	for _, name := range []string{"postgres16.sbom.json", "postgres16.test-results.json"} {
		if err := os.WriteFile(filepath.Join(outputDir, name), []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	calls = nil
	stdout, err = runCLI(t,
		"service", "publish", "postgres16",
		"--system", "x86_64-linux",
		"--version-tag", "v1.2.3",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("service publish failed: %v\n%s", err, stdout)
	}
	if len(calls) != 1 || !strings.Contains(strings.Join(calls[0].Args, " "), "--publish") || !strings.Contains(strings.Join(calls[0].Args, " "), "--version-tag v1.2.3") {
		t.Fatalf("unexpected publish command: %#v", calls)
	}
	for _, name := range []string{"postgres16-amd64.sbom.json", "postgres16-amd64.test-results.json"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("expected staged service release asset %s: %v", name, err)
		}
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
	defer func() {
		serviceOpts = oldServiceOpts
		runExternalCommand = oldRun
	}()

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
	if len(calls) != 3 {
		t.Fatalf("expected three smoke commands, got %#v", calls)
	}
	for _, call := range calls {
		if call.Name != "podman" || !strings.Contains(strings.Join(call.Args, " "), "--entrypoint") {
			t.Fatalf("unexpected smoke command: %#v", call)
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

func TestServiceAssembleAndExportProvenance(t *testing.T) {
	oldServiceOpts := serviceOpts
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	defer func() {
		serviceOpts = oldServiceOpts
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
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
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name == "crane" {
			return "sha256:service-digest\n", nil
		}
		if c.Name == "cosign" {
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
	)
	if err != nil {
		t.Fatalf("service assemble failed: %v\n%s", err, stdout)
	}
	if len(calls) < 6 {
		t.Fatalf("expected crane/cosign calls, got %#v", calls)
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
}
