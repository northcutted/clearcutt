package commands

import (
	"fmt"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/versionpolicy"
)

func TestCheckGithubRegistryCredentialNames(t *testing.T) {
	oldCapture := captureExternalOutput
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	type result struct{ check, status, detail string }
	collect := func() (*[]result, func(string, string, string)) {
		results := &[]result{}
		return results, func(check, status, detail string) {
			*results = append(*results, result{check, status, detail})
		}
	}

	captureExternalOutput = func(c externalCommand) (string, error) {
		return `[{"name":"CLEARCUTT_REGISTRY_USER"}]`, nil
	}
	secrets := []githubName{{Name: "CLEARCUTT_REGISTRY_TOKEN"}}
	results, add := collect()
	checkGithubRegistryCredentialNames("acme/fleet", secrets, nil, add)
	if len(*results) != 1 || (*results)[0].status != "pass" {
		t.Fatalf("configured credentials should pass, got %#v", *results)
	}

	results, add = collect()
	checkGithubRegistryCredentialNames("acme/fleet", nil, nil, add)
	if len(*results) != 1 || (*results)[0].status != "fail" {
		t.Fatalf("missing token secret should fail, got %#v", *results)
	}

	captureExternalOutput = func(c externalCommand) (string, error) {
		return "", fmt.Errorf("gh unavailable")
	}
	results, add = collect()
	checkGithubRegistryCredentialNames("acme/fleet", secrets, nil, add)
	if len(*results) != 1 || (*results)[0].status != "fail" || !strings.Contains((*results)[0].detail, "read failed") {
		t.Fatalf("gh read failure should fail with detail, got %#v", *results)
	}
}

func TestVersionPolicyLoaded(t *testing.T) {
	policy := versionpolicy.Loaded()
	if len(policy.Languages) == 0 {
		t.Fatal("embedded version policy should classify at least one language")
	}
}
