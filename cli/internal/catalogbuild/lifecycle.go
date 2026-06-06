package catalogbuild

import (
	"strings"

	"github.com/northcutted/clearcutt/internal/catalog"
)

// Lifecycle mirrors the lifecycle object the Node producer emits.
type Lifecycle struct {
	Status            string  `json:"status"`
	Support           string  `json:"support"`
	ProductionAllowed bool    `json:"productionAllowed"`
	DeprecatedAt      *string `json:"deprecatedAt"`
	EOLAt             *string `json:"eolAt"`
	Reason            *string `json:"reason"`
}

// RuntimeContract mirrors the runtimeContract object the Node producer emits.
type RuntimeContract struct {
	User                  string  `json:"user"`
	WorkingDir            string  `json:"workingDir"`
	ShellPresent          bool    `json:"shellPresent"`
	PackageManagerPresent bool    `json:"packageManagerPresent"`
	CACertificatesPresent bool    `json:"caCertificatesPresent"`
	TimezoneDataPresent   bool    `json:"timezoneDataPresent"`
	DefaultEntrypoint     *string `json:"defaultEntrypoint"`
	ProductionTier        bool    `json:"productionTier"`
}

func Str(s string) *string { return &s }

// gatherLangKey strips the trailing tier segment from a target id, matching the
// `target.lastIndexOf('-')` split in gather-catalog.mjs.
func gatherLangKey(target string) string {
	if idx := strings.LastIndex(target, "-"); idx != -1 {
		return target[:idx]
	}
	return target
}

func determineLifecycle(target, tier string) Lifecycle {
	langKey := gatherLangKey(target)

	status, support, productionAllowed := "preview", "preview", false
	switch langKey {
	case "coreLTS", "java21", "node22", "dotnet8":
		status, support = "active", "lts"
		if tier != "dev" {
			productionAllowed = true
		}
	case "python3.13":
		status, support = "active", "current"
		if tier != "dev" {
			productionAllowed = true
		}
	case "java25", "node24", "python3.14", "python3.15", "dotnet10":
		status, support, productionAllowed = "preview", "preview", false
	case "go1.25", "go1.26", "rust1.95", "cc15":
		status, support, productionAllowed = "experimental", "unsupported", false
	}

	return Lifecycle{
		Status:            status,
		Support:           support,
		ProductionAllowed: productionAllowed,
	}
}

func determineRuntimeContract(target, tier string) RuntimeContract {
	langKey := gatherLangKey(target)

	var entrypoint *string
	switch {
	case strings.HasPrefix(langKey, "java"):
		entrypoint = Str("/usr/local/bin/java")
	case strings.HasPrefix(langKey, "node"):
		entrypoint = Str("/usr/bin/node")
	case strings.HasPrefix(langKey, "python"):
		entrypoint = Str("/usr/bin/python")
	case strings.HasPrefix(langKey, "go"):
		entrypoint = Str("/usr/bin/go")
	case strings.HasPrefix(langKey, "dotnet"):
		entrypoint = Str("/usr/bin/dotnet")
	case langKey == "coreLTS":
		entrypoint = Str("/bin/sh")
	}

	shellPresent, packageManagerPresent, productionTier := true, true, false
	switch tier {
	case "slim":
		shellPresent, packageManagerPresent, productionTier = true, false, true
	case "distroless":
		shellPresent, packageManagerPresent, productionTier = false, false, true
	default:
		shellPresent, packageManagerPresent, productionTier = true, true, false
	}

	return RuntimeContract{
		User:                  "10001",
		WorkingDir:            "/app",
		ShellPresent:          shellPresent,
		PackageManagerPresent: packageManagerPresent,
		CACertificatesPresent: true,
		TimezoneDataPresent:   true,
		DefaultEntrypoint:     entrypoint,
		ProductionTier:        productionTier,
	}
}

func defaultGatherExceptions() catalog.ExceptionSummary {
	return catalog.ExceptionSummary{}
}
