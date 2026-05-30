package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/northcutted/clearcutt/internal/catalog"
)

type policyFlags struct {
	tag               string
	format            string
	output            string
	environment       string
	requireDigest     bool
	requireSignature  bool
	requireProvenance bool
	denyDevTier       bool
	denyPreview       bool
	namespace         string
}

var policyOpts policyFlags

func NewPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy <image-id>",
		Short: "Generate Kubernetes admission control policy bundles natively",
		Long:  `Dynamically extracts OIDC signatures from the base image catalog to output deployable Kyverno or OPA Gatekeeper policy manifests matching environment profiles.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicy(args[0])
		},
	}

	cmd.Flags().StringVar(&policyOpts.tag, "tag", "", "Target release tag version (defaults to latest)")
	cmd.Flags().StringVar(&policyOpts.format, "format", "kyverno", "Policy type: kyverno or gatekeeper")
	cmd.Flags().StringVar(&policyOpts.output, "output", "", "Output manifest file path destination")
	cmd.Flags().StringVar(&policyOpts.environment, "environment", "production", "Policy environment profile: development, production, or strict")
	cmd.Flags().BoolVar(&policyOpts.requireDigest, "require-digest", false, "Require digest pinning on container images")
	cmd.Flags().BoolVar(&policyOpts.requireSignature, "require-signature", false, "Require Cosign keyless signatures")
	cmd.Flags().BoolVar(&policyOpts.requireProvenance, "require-provenance", false, "Require SLSA build provenance attestations")
	cmd.Flags().BoolVar(&policyOpts.denyDevTier, "deny-dev-tier", false, "Deny images from the 'dev' tooling tier")
	cmd.Flags().BoolVar(&policyOpts.denyPreview, "deny-preview", false, "Deny images marked as preview lifecycle stage")
	cmd.Flags().StringVar(&policyOpts.namespace, "namespace", "default", "Kubernetes namespace context target")

	return cmd
}

func runPolicy(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	var release *catalog.ReleaseEntry
	if policyOpts.tag != "" {
		for i := range record.Releases {
			if record.Releases[i].Tag == policyOpts.tag {
				release = &record.Releases[i]
				break
			}
		}
		if release == nil {
			return fmt.Errorf("release tag %q not found for image %q", policyOpts.tag, imageID)
		}
	} else {
		for i := range record.Releases {
			if record.Releases[i].IsLatest {
				release = &record.Releases[i]
				break
			}
		}
		if release == nil && len(record.Releases) > 0 {
			release = &record.Releases[0]
		}
	}

	if release == nil {
		return fmt.Errorf("no releases found for image %q", imageID)
	}

	// Resolve OIDC subject and issuer
	subject := "https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main"
	issuer := "https://token.actions.githubusercontent.com"

	if release.Signature != nil && release.Signature.Certificate != nil {
		if release.Signature.Certificate.Subject != nil {
			subject = *release.Signature.Certificate.Subject
		}
		if release.Signature.Certificate.Issuer != nil {
			issuer = *release.Signature.Certificate.Issuer
		}
	}

	// Resolve defaults by environment profile
	env := strings.ToLower(policyOpts.environment)
	reqDigest := policyOpts.requireDigest
	reqSig := policyOpts.requireSignature
	reqProv := policyOpts.requireProvenance
	denyDev := policyOpts.denyDevTier
	denyPrev := policyOpts.denyPreview

	if env == "production" {
		reqDigest = true
		reqSig = true
		reqProv = true
		denyDev = true
		denyPrev = true
	} else if env == "strict" {
		reqDigest = true
		reqSig = true
		reqProv = true
		denyDev = true
		denyPrev = true
	} else if env == "development" {
		reqSig = true
	}

	var outputPolicy string

	switch strings.ToLower(policyOpts.format) {
	case "gatekeeper", "opa":
		outputPolicy = fmt.Sprintf(`apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8scosignsignatureverify
spec:
  crd:
    spec:
      names:
        kind: K8sCosignSignatureVerify
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8scosignsignatureverify

        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          image := input.review.object.spec.containers[_].image
          startswith(image, "%s")
          msg := sprintf("Security Violation: Image %%q must be verified using Cosign keyless signatures", [image])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sCosignSignatureVerify
metadata:
  name: verify-signature-%s
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["%s"]
  parameters:
    imagePattern: "%s:*"
    requireDigest: %t
    requireSignature: %t
    requireProvenance: %t
    denyDevTier: %t
    denyPreview: %t
    subject: "%s"
    issuer: "%s"
`, record.FullName, record.ID, policyOpts.namespace, record.FullName, reqDigest, reqSig, reqProv, denyDev, denyPrev, subject, issuer)

	default: // Kyverno
		var rulesBlock strings.Builder

		// Main signature and digest rule
		rulesBlock.WriteString(fmt.Sprintf(`    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["%s"]
      verifyImages:
        - imageReferences: ["%s:*"]
          mutateDigest: %t
          verifyDigest: %t
          required: %t
`, policyOpts.namespace, record.FullName, reqDigest, reqDigest, reqSig))

		if reqSig {
			rulesBlock.WriteString(fmt.Sprintf(`          attestors:
            - entries:
                - keyless:
                    subject: "%s"
                    issuer: "%s"
`, subject, issuer))
		}

		if reqProv {
			rulesBlock.WriteString(fmt.Sprintf(`          attestations:
            - predicateType: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "%s"
                        issuer: "%s"
`, subject, issuer))
		}

		if denyDev {
			rulesBlock.WriteString(fmt.Sprintf(`    - name: deny-dev-images
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["%s"]
      validate:
        message: "Security Violation: Dev tier images are forbidden in this environment"
        pattern:
          spec:
            containers:
              - =(image): "!*:*-dev"
`, policyOpts.namespace))
		}

		outputPolicy = fmt.Sprintf(`apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-signature-%s
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
%s`, record.ID, rulesBlock.String())
	}

	if policyOpts.output != "" {
		if err := os.WriteFile(policyOpts.output, []byte(outputPolicy), 0644); err != nil {
			return fmt.Errorf("failed to write policy manifest file: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Printf("Successfully generated policy manifest file: %s\n", policyOpts.output)
		}
	} else {
		os.Stdout.Write([]byte(outputPolicy))
	}

	return nil
}
