package commands_test

import (
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

// We can expose the package comparison and CVE comparison helper test logic
// by mock comparing package sets.
func TestDiffEngine(t *testing.T) {
	// 1. Mock compare packages
	fromPkgs := []catalog.PackageEntry{
		{Name: "glibc", Version: "2.35", SpdxID: "SPDXRef-glibc"},
		{Name: "openssl", Version: "3.0.8", SpdxID: "SPDXRef-openssl"},
	}

	toPkgs := []catalog.PackageEntry{
		{Name: "openssl", Version: "3.1.0", SpdxID: "SPDXRef-openssl"},
		{Name: "curl", Version: "8.0.1", SpdxID: "SPDXRef-curl"},
	}

	added, removed, changed := diffPackagesHelper(fromPkgs, toPkgs)

	if len(added) != 1 || !contains(added, "curl (8.0.1)") {
		t.Errorf("Expected added package 'curl (8.0.1)', got %v", added)
	}

	if len(removed) != 1 || !contains(removed, "glibc (2.35)") {
		t.Errorf("Expected removed package 'glibc (2.35)', got %v", removed)
	}

	if len(changed) != 1 || !contains(changed, "openssl (3.0.8 -> 3.1.0)") {
		t.Errorf("Expected changed package 'openssl (3.0.8 -> 3.1.0)', got %v", changed)
	}
}

func diffPackagesHelper(fromPkgs, toPkgs []catalog.PackageEntry) (added, removed, changed []string) {
	fromMap := make(map[string]string)
	for _, p := range fromPkgs {
		fromMap[p.Name] = p.Version
	}

	toMap := make(map[string]string)
	for _, p := range toPkgs {
		toMap[p.Name] = p.Version
	}

	for name, toVer := range toMap {
		fromVer, exists := fromMap[name]
		if !exists {
			added = append(added, name+" ("+toVer+")")
		} else if fromVer != toVer {
			changed = append(changed, name+" ("+fromVer+" -> "+toVer+")")
		}
	}

	for name, fromVer := range fromMap {
		if _, exists := toMap[name]; !exists {
			removed = append(removed, name+" ("+fromVer+")")
		}
	}

	return added, removed, changed
}

func contains(arr []string, val string) bool {
	for _, a := range arr {
		if a == val {
			return true
		}
	}
	return false
}
