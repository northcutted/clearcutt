package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
)

// Small shared helpers that outlived the remediation subsystem they were written
// for. They are used by catalog build/enrich, scan, verify, and evidence
// manifesting, none of which have anything to do with CVE patching.

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// fallbackString returns value, or fallback when value is empty.
func fallbackString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// envIntValue reads an integer from the environment, falling back on absent or
// unparseable values rather than failing: these tune batch sizes, and a typo in a
// workflow variable should not break a catalog build.
func envIntValue(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

// fixedVersionString takes the first version from a scanner's comma-separated
// "fixed in" field, which lists every fixing version across affected branches.
func fixedVersionString(value *string) string {
	if value == nil {
		return ""
	}
	parts := strings.SplitN(*value, ",", 2)
	return strings.TrimSpace(parts[0])
}

// findingHasFix reports whether a scanner finding names any fixing version.
func findingHasFix(fixedIn *string) bool {
	return fixedVersionString(fixedIn) != ""
}

// productionTier reports whether a tier is production-facing under the policy.
func productionTier(policy fleet.RemediationPolicy, tier string) bool {
	policy = fleet.EffectiveRemediationPolicy(policy)
	for _, item := range policy.ProductionTiers {
		if item == tier {
			return item == tier
		}
	}
	return false
}

// remediationPolicyFromJSON parses a policy blob, falling back to the default on
// anything malformed. Callers use it to interpret scanner thresholds, so a bad blob
// should degrade to the documented defaults rather than fail the gate open.
func remediationPolicyFromJSON(raw string) fleet.RemediationPolicy {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "null" {
		return fleet.DefaultRemediationPolicy()
	}
	var policy fleet.RemediationPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return fleet.DefaultRemediationPolicy()
	}
	return fleet.EffectiveRemediationPolicy(policy)
}

// resolveCoreDir locates the Nix core workspace, preferring an explicit path.
func resolveCoreDir(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	for _, candidate := range []string{".", "core"} {
		if isClearCuttCoreWorkspace(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not locate ClearCutt core workspace; pass --core-dir")
}

// isClearCuttCoreWorkspace identifies the core directory by its flake plus the
// runtime registry the flake compiles from.
func isClearCuttCoreWorkspace(dir string) bool {
	if !fileExists(filepath.Join(dir, "flake.nix")) {
		return false
	}
	return fileExists(filepath.Join(dir, "lib", "registry.nix"))
}
