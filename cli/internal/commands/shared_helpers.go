package commands

// Helpers recovered from the deleted image-factory command group. They are not
// factory-specific — credential resolution, tool path handling, and GitHub
// Actions output plumbing are all used by the governance commands that remain.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func registryDestCredentialPair() (string, string) {
	user := firstNonEmptyString(os.Getenv("REGISTRY_USER"), os.Getenv("CLEARCUTT_REGISTRY_USER"), os.Getenv("GITHUB_ACTOR"))
	token := firstNonEmptyString(os.Getenv("REGISTRY_TOKEN"), os.Getenv("CLEARCUTT_REGISTRY_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	return user, token
}

// absToolPath anchors a predicate/artifact path to an absolute path before it
// is handed to a core-pinned tool. runCoreToolCommand runs the tool through
// `nix develop` with cwd = coreDir, so a path relative to the CLI's own cwd
// (where the release workflow stages build-outputs) would otherwise resolve
// against coreDir and miss. Falls back to the input if Abs fails.
func absToolPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func appendGitHubOutputs(path string, values map[string]string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := fmt.Fprintf(f, "%s=%s\n", key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type externalCommand struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

func runExternalCommandDefault(c externalCommand) error {
	cmd := exec.Command(c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", c.Name, err)
	}
	return nil
}

func captureExternalCommandDefault(c externalCommand) (string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Command(c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderrBuf.String())
		if detail != "" {
			fmt.Fprintln(errOut, detail)
		}
		return "", fmt.Errorf("%s failed: %w", c.Name, err)
	}
	return stdoutBuf.String(), nil
}

// The external-command seam. Tests replace these to drive the CLI without
// running real subprocesses; production code never calls the defaults directly.
var (
	runExternalCommand    = runExternalCommandDefault
	captureExternalOutput = captureExternalCommandDefault
)
