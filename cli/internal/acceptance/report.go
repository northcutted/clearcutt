package acceptance

import (
	"encoding/json"
	"os"
	"strings"
)

// grypeReport is the subset of Grype's JSON output the gate reads.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Fix      struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

// BlockingSeverities are the severities the fleet gate fails on, matching the
// `--fail-on high` Grype is invoked with.
var BlockingSeverities = map[string]bool{"high": true, "critical": true}

// ReadGrypeFindings extracts the findings a `--fail-on high --only-fixed` run
// would block on: fixable, at or above High. Anything else is reported by the
// scanner but is not what the gate turns on, so classifying it would invite
// acceptances for findings that never needed one.
func ReadGrypeFindings(path string) ([]Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	seen := map[Finding]bool{}
	var out []Finding
	for _, m := range report.Matches {
		if !BlockingSeverities[strings.ToLower(m.Vulnerability.Severity)] {
			continue
		}
		if m.Vulnerability.Fix.State != "fixed" {
			continue
		}
		f := Finding{
			ID:       m.Vulnerability.ID,
			Package:  m.Artifact.Name,
			Version:  m.Artifact.Version,
			Severity: m.Vulnerability.Severity,
			FixedIn:  strings.Join(m.Vulnerability.Fix.Versions, ","),
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out, nil
}
