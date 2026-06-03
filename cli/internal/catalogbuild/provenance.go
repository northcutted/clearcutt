package catalogbuild

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// -- in-toto / SLSA provenance summarization ---------------------------------
type Provenance struct {
	PredicateType  string     `json:"predicateType"`
	Builder        builderOut `json:"builder"`
	BuildType      *string    `json:"buildType"`
	SourceURI      *string    `json:"sourceUri"`
	SourceRevision *string    `json:"sourceRevision"`
	SlsaLevel      int        `json:"slsaLevel"`
}

type builderOut struct {
	ID string `json:"id"`
}

type intotoLine struct {
	DsseEnvelope *struct {
		Payload string `json:"payload"`
	} `json:"dsseEnvelope"`
	Payload       string          `json:"payload"`
	PredicateType string          `json:"predicateType"`
	Raw           json.RawMessage `json:"-"`
}

type IntotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     intotoPredicate `json:"predicate"`
}

type intotoPredicate struct {
	Builder         *intotoBuilder         `json:"builder"`
	RunDetails      *intotoRunDetails      `json:"runDetails"`
	BuildType       string                 `json:"buildType"`
	BuildDefinition *intotoBuildDefinition `json:"buildDefinition"`
	Invocation      *intotoInvocation      `json:"invocation"`
	Materials       []intotoDependency     `json:"materials"`
}

type intotoBuilder struct {
	ID string `json:"id"`
}

type intotoRunDetails struct {
	Builder *intotoBuilder `json:"builder"`
}

type intotoBuildDefinition struct {
	BuildType            string                `json:"buildType"`
	ExternalParameters   *intotoExternalParams `json:"externalParameters"`
	ResolvedDependencies []intotoDependency    `json:"resolvedDependencies"`
}

type intotoExternalParams struct {
	Workflow  *intotoWorkflow `json:"workflow"`
	Source    *intotoSource   `json:"source"`
	SourceURI string          `json:"sourceUri"`
}

type intotoWorkflow struct {
	Repository string `json:"repository"`
}

type intotoSource struct {
	URI    string        `json:"uri"`
	Digest *intotoDigest `json:"digest"`
}

type intotoInvocation struct {
	ConfigSource *intotoSource `json:"configSource"`
}

type intotoDependency struct {
	URI    string        `json:"uri"`
	Digest *intotoDigest `json:"digest"`
}

type intotoDigest struct {
	Sha1      string `json:"sha1"`
	GitCommit string `json:"gitCommit"`
}

func decodeIntotoPayload(line []byte) *IntotoStatement {
	var env intotoLine
	if err := json.Unmarshal(line, &env); err != nil {
		return nil
	}
	payloadB64 := env.Payload
	if env.DsseEnvelope != nil {
		payloadB64 = env.DsseEnvelope.Payload
	}
	if payloadB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			return nil
		}
		var stmt IntotoStatement
		if err := json.Unmarshal(decoded, &stmt); err != nil {
			return nil
		}
		return &stmt
	}
	if env.PredicateType != "" {
		var stmt IntotoStatement
		if err := json.Unmarshal(line, &stmt); err != nil {
			return nil
		}
		return &stmt
	}
	return nil
}

func firstGitDependency(pred intotoPredicate) *intotoDependency {
	deps := pred.Materials
	if pred.BuildDefinition != nil && len(pred.BuildDefinition.ResolvedDependencies) > 0 {
		deps = pred.BuildDefinition.ResolvedDependencies
	}
	for i := range deps {
		if strings.Contains(deps[i].URI, "github.com") {
			return &deps[i]
		}
	}
	return nil
}

func SummarizeIntotoStatement(stmt IntotoStatement) Provenance {
	predicateType := stmt.PredicateType
	if predicateType == "" {
		predicateType = "unknown"
	}
	out := Provenance{PredicateType: predicateType, Builder: builderOut{ID: "unknown"}, SlsaLevel: 3}
	pred := stmt.Predicate

	var buildDef intotoBuildDefinition
	if pred.BuildDefinition != nil {
		buildDef = *pred.BuildDefinition
	}
	var workflow intotoWorkflow
	if buildDef.ExternalParameters != nil && buildDef.ExternalParameters.Workflow != nil {
		workflow = *buildDef.ExternalParameters.Workflow
	}
	var configSource *intotoSource
	if pred.Invocation != nil && pred.Invocation.ConfigSource != nil {
		configSource = pred.Invocation.ConfigSource
	} else if buildDef.ExternalParameters != nil {
		configSource = buildDef.ExternalParameters.Source
	}
	gitDep := firstGitDependency(pred)

	// builder.id: pred.builder.id || pred.runDetails.builder.id || unknown
	if pred.Builder != nil && pred.Builder.ID != "" {
		out.Builder.ID = pred.Builder.ID
	} else if pred.RunDetails != nil && pred.RunDetails.Builder != nil && pred.RunDetails.Builder.ID != "" {
		out.Builder.ID = pred.RunDetails.Builder.ID
	}

	out.BuildType = firstNonEmptyPtr(pred.BuildType, buildDef.BuildType)

	sourceURI := ""
	if configSource != nil {
		sourceURI = configSource.URI
	}
	sourceURI = FirstNonEmptyStr(sourceURI, workflow.Repository)
	if buildDef.ExternalParameters != nil {
		sourceURI = FirstNonEmptyStr(sourceURI, buildDef.ExternalParameters.SourceURI)
	}
	if gitDep != nil {
		sourceURI = FirstNonEmptyStr(sourceURI, gitDep.URI)
	}
	out.SourceURI = PtrIfNotEmpty(sourceURI)

	sourceRev := ""
	if configSource != nil && configSource.Digest != nil {
		sourceRev = FirstNonEmptyStr(configSource.Digest.Sha1, configSource.Digest.GitCommit)
	}
	if buildDef.ExternalParameters != nil && buildDef.ExternalParameters.Source != nil && buildDef.ExternalParameters.Source.Digest != nil {
		d := buildDef.ExternalParameters.Source.Digest
		sourceRev = FirstNonEmptyStr(sourceRev, d.Sha1, d.GitCommit)
	}
	if gitDep != nil && gitDep.Digest != nil {
		sourceRev = FirstNonEmptyStr(sourceRev, gitDep.Digest.GitCommit, gitDep.Digest.Sha1)
	}
	out.SourceRevision = PtrIfNotEmpty(sourceRev)

	return out
}

func isUsefulProvenanceSummary(p Provenance) bool {
	return p.PredicateType != "unknown" || p.Builder.ID != "unknown" ||
		p.BuildType != nil || p.SourceURI != nil || p.SourceRevision != nil
}

func summarizeProvenance(intotoJSONL string) Provenance {
	fallback := Provenance{PredicateType: "unknown", Builder: builderOut{ID: "unknown"}, SlsaLevel: 3}
	var best *Provenance
	for _, line := range strings.Split(intotoJSONL, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		stmt := decodeIntotoPayload([]byte(line))
		if stmt == nil {
			continue
		}
		summary := SummarizeIntotoStatement(*stmt)
		if strings.Contains(summary.PredicateType, "slsa.dev/provenance") {
			return summary
		}
		if best == nil && isUsefulProvenanceSummary(summary) {
			s := summary
			best = &s
		}
	}
	if best != nil {
		return *best
	}
	return fallback
}
