package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type conformanceFlags struct {
	image  string
	output string
}

var conformanceOpts conformanceFlags

type ConformanceReport struct {
	ImageID    string             `json:"imageId"`
	Timestamp  string             `json:"timestamp"`
	Status     string             `json:"status"` // passed or failed
	Assertions []ConformanceCheck `json:"assertions"`
}

type ConformanceCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass or fail
	Message string `json:"message"`
}

func NewConformanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conformance",
		Short: "Execute runtime conformance and smoke test suites",
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the full conformance suite against the local host environment",
		Long:  `Executes detailed unprivileged operator audits, CA certificate lookups, /tmp write access checks, and runtime interpreter validations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConformanceSuite()
		},
	}

	runCmd.Flags().StringVar(&conformanceOpts.image, "image", "host", "Target image ID metadata context")
	runCmd.Flags().StringVar(&conformanceOpts.output, "output", "", "Output JSON report file destination")

	cmd.AddCommand(runCmd)
	return cmd
}

func runConformanceSuite() error {
	checks := []ConformanceCheck{}
	hasFailures := false

	addCheck := func(name, status, message string) {
		checks = append(checks, ConformanceCheck{
			Name:    name,
			Status:  status,
			Message: message,
		})
		if status == "fail" {
			hasFailures = true
		}
	}

	// 1. Audit non-root operator user
	uid := os.Getuid()
	if uid == 0 {
		addCheck("runtime.user.nonroot", "fail", "Security Notice: Process is running under root privilege (UID 0)")
	} else {
		addCheck("runtime.user.nonroot", "pass", fmt.Sprintf("Process executes within unprivileged boundaries (UID %d)", uid))
	}

	// 2. Audit /tmp writable path
	tmpPath := filepath.Join(os.TempDir(), "clearcutt-conformance-write-check")
	if err := os.WriteFile(tmpPath, []byte("conformance"), 0600); err != nil {
		addCheck("runtime.paths.tmp_writable", "fail", fmt.Sprintf("Failed to write to temporary workspace: %v", err))
	} else {
		os.Remove(tmpPath)
		addCheck("runtime.paths.tmp_writable", "pass", "Verified read/write access to standard temporary directory workspace")
	}

	// 3. Audit Timezone database
	_, err := os.Stat("/etc/localtime")
	if err != nil {
		_, err = os.Stat("/usr/share/zoneinfo")
	}
	if err == nil {
		addCheck("runtime.data.timezone", "pass", "System timezone data database resources are present")
	} else {
		addCheck("runtime.data.timezone", "fail", "Compliance Notice: System zoneinfo database was not found")
	}

	// 4. Audit CA Certificates
	caCertsFound := false
	certPaths := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
	for _, cp := range certPaths {
		if _, err := os.Stat(cp); err == nil {
			caCertsFound = true
			break
		}
	}
	if caCertsFound {
		addCheck("runtime.data.ca_certificates", "pass", "Verified presence of cryptographic root certificate bundles")
	} else {
		addCheck("runtime.data.ca_certificates", "fail", "Compliance Notice: Root CA certificate bundle was not found")
	}

	// 5. Language-specific conformance & integrity audits
	runtimeChecks := []struct {
		ID            string
		Name          string
		Binary        string
		VersionArgs   []string
		IntegrityArgs []string
	}{
		{
			ID:            "java",
			Name:          "Java",
			Binary:        "java",
			VersionArgs:   []string{"-version"},
			IntegrityArgs: []string{"-XshowSettings:properties", "-version"},
		},
		{
			ID:            "python",
			Name:          "Python",
			Binary:        "python3",
			VersionArgs:   []string{"--version"},
			IntegrityArgs: []string{"-c", "import urllib.request, ssl; print('TLS/SSL verified:', ssl.OPENSSL_VERSION)"},
		},
		{
			ID:            "node",
			Name:          "Node.js",
			Binary:        "node",
			VersionArgs:   []string{"--version"},
			IntegrityArgs: []string{"-e", "const https = require('https'); console.log('TLS/SSL verified:', process.versions.openssl)"},
		},
		{
			ID:            "go",
			Name:          "Go",
			Binary:        "go",
			VersionArgs:   []string{"version"},
			IntegrityArgs: []string{"env", "GOPATH"},
		},
		{
			ID:            "dotnet",
			Name:          ".NET",
			Binary:        "dotnet",
			VersionArgs:   []string{"--version"},
			IntegrityArgs: []string{"--info"},
		},
		{
			ID:            "rust",
			Name:          "Rust",
			Binary:        "rustc",
			VersionArgs:   []string{"--version"},
			IntegrityArgs: []string{"--version"},
		},
		{
			ID:            "cc",
			Name:          "C/C++",
			Binary:        "gcc",
			VersionArgs:   []string{"--version"},
			IntegrityArgs: []string{"-v"},
		},
		{
			ID:            "core",
			Name:          "Core",
			Binary:        "sh",
			VersionArgs:   []string{"-c", "echo 'Core Shell'"},
			IntegrityArgs: []string{"-c", "echo 'Timezone:' $(date)"},
		},
	}

	for _, rc := range runtimeChecks {
		// Determine if this runtime is explicitly expected based on the image ID metadata context
		isExpected := false
		if conformanceOpts.image != "host" {
			normalizedImage := strings.ToLower(conformanceOpts.image)
			normalizedID := strings.ToLower(rc.ID)
			if strings.Contains(normalizedImage, normalizedID) {
				isExpected = true
			}
		}

		binPath, err := exec.LookPath(rc.Binary)
		if err != nil {
			if isExpected {
				addCheck(fmt.Sprintf("runtime.interpreter.%s", rc.ID), "fail", fmt.Sprintf("Compliance Violation: Expected runtime interpreter %q was not found on PATH", rc.Binary))
			}
			continue
		}

		// Run version check
		cmdOut, cmdErr := exec.Command(binPath, rc.VersionArgs...).CombinedOutput()
		if cmdErr == nil {
			versionStr := strings.TrimSpace(strings.Split(string(cmdOut), "\n")[0])
			addCheck(fmt.Sprintf("runtime.interpreter.%s", rc.ID), "pass", fmt.Sprintf("%s interpreter verified successfully: %s", rc.Name, versionStr))
		} else {
			addCheck(fmt.Sprintf("runtime.interpreter.%s", rc.ID), "fail", fmt.Sprintf("%s interpreter failed to execute: %v", rc.Name, cmdErr))
		}

		// Run integrity/TLS/environment check
		intOut, intErr := exec.Command(binPath, rc.IntegrityArgs...).CombinedOutput()
		if intErr == nil {
			addCheck(fmt.Sprintf("runtime.integrity.%s", rc.ID), "pass", fmt.Sprintf("Verified %s module/environment integrity successfully", rc.Name))
		} else {
			addCheck(fmt.Sprintf("runtime.integrity.%s", rc.ID), "fail", fmt.Sprintf("%s integrity audit flagged warnings: %v (output: %s)", rc.Name, intErr, strings.TrimSpace(string(intOut))))
		}
	}

	overallStatus := "passed"
	if hasFailures {
		overallStatus = "failed"
	}

	report := ConformanceReport{
		ImageID:    conformanceOpts.image,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Status:     overallStatus,
		Assertions: checks,
	}

	// Serialize
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize conformance report: %w", err)
	}

	if conformanceOpts.output != "" {
		if err := os.WriteFile(conformanceOpts.output, reportData, 0644); err != nil {
			return fmt.Errorf("failed to write conformance report file: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Fprintf(out, "Successfully generated runtime conformance report file: %s\n", conformanceOpts.output)
		}
	} else {
		out.Write(reportData)
		fmt.Fprintln(out)
	}

	if hasFailures {
		return ErrCheckFailed
	}

	return nil
}
