package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

const (
	nixOSSubstituter = "https://cache.nixos.org"
	nixOSPublicKey   = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

	clearcuttNixConfigBegin = "# BEGIN ClearCutt managed Nix config"
	clearcuttNixConfigEnd   = "# END ClearCutt managed Nix config"
)

type platformNixFlags struct {
	configPath      string
	repoRoot        string
	coreDir         string
	configOutput    string
	githubEnvPath   string
	writeUserConfig bool
	printConfig     bool
	skipWarm        bool
}

type NixSetupResult struct {
	Status          string   `json:"status"`
	NixVersion      string   `json:"nixVersion,omitempty"`
	CoreDir         string   `json:"coreDir"`
	UserConfigPath  string   `json:"userConfigPath,omitempty"`
	ConfigOutput    string   `json:"configOutput,omitempty"`
	GitHubEnvPath   string   `json:"githubEnvPath,omitempty"`
	CacheConfigured bool     `json:"cacheConfigured"`
	Warmed          bool     `json:"warmed"`
	Command         []string `json:"command,omitempty"`
}

var platformNixOpts platformNixFlags

func NewPlatformSetupNixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup-nix [-- command...]",
		Short: "Configure and verify the Nix environment for the fleet",
		Long: `Configures the Nix client side of a ClearCutt-powered fleet from
clearcutt.fleet.yaml. The command writes optional nix.conf/GitHub environment
state, checks that Nix is installed with flakes available, and warms or runs the
core dev shell used by fleet builds.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlatformSetupNix(args)
		},
	}
	cmd.Flags().StringVar(&platformNixOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to inspect")
	cmd.Flags().StringVar(&platformNixOpts.repoRoot, "repo-root", ".", "Repository root containing the fleet config and core directory")
	cmd.Flags().StringVar(&platformNixOpts.coreDir, "core-dir", "core", "Path to the Nix fleet core directory")
	cmd.Flags().StringVar(&platformNixOpts.configOutput, "config-output", "", "Optional path to write the generated nix.conf fragment")
	cmd.Flags().StringVar(&platformNixOpts.githubEnvPath, "github-env", "", "Optional GITHUB_ENV file to append NIX_CONFIG for subsequent GitHub Actions steps")
	cmd.Flags().BoolVar(&platformNixOpts.writeUserConfig, "write-user-config", false, "Write or replace the ClearCutt block in the user's nix.conf")
	cmd.Flags().BoolVar(&platformNixOpts.printConfig, "print-config", false, "Print the generated nix.conf fragment")
	cmd.Flags().BoolVar(&platformNixOpts.skipWarm, "skip-warm", false, "Do not warm the default core dev shell when no command is provided")
	return cmd
}

func runPlatformSetupNix(command []string) error {
	root := platformNixOpts.repoRoot
	cfg, err := fleet.Load(joinRoot(root, platformNixOpts.configPath))
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	coreDir := joinRoot(root, platformNixOpts.coreDir)
	config := buildNixClientConfig(cfg)
	result := NixSetupResult{
		Status:          "pass",
		CoreDir:         coreDir,
		CacheConfigured: fleetNixCacheReady(cfg),
	}

	if platformNixOpts.configOutput != "" {
		path := joinRoot(root, platformNixOpts.configOutput)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
			return err
		}
		result.ConfigOutput = path
	}
	if platformNixOpts.writeUserConfig {
		path, err := writeUserNixConfig(config)
		if err != nil {
			return err
		}
		result.UserConfigPath = path
	}
	if platformNixOpts.githubEnvPath != "" {
		path := joinRoot(root, platformNixOpts.githubEnvPath)
		if err := appendGitHubEnvMultiline(path, "NIX_CONFIG", strings.TrimSpace(config)); err != nil {
			return err
		}
		result.GitHubEnvPath = path
	}

	version, err := captureExternalOutput(externalCommand{Name: "nix", Args: []string{"--version"}})
	if err != nil {
		return fmt.Errorf("nix is not installed or not on PATH; install Nix first, then run clearcutt platform setup-nix again: %w", err)
	}
	result.NixVersion = strings.TrimSpace(version)

	if len(command) > 0 || !platformNixOpts.skipWarm {
		nixCommand := command
		if len(nixCommand) == 0 {
			nixCommand = []string{"true"}
			result.Warmed = true
		} else {
			result.Command = append([]string{}, nixCommand...)
		}
		args := append([]string{
			"develop",
			"--extra-experimental-features", "nix-command flakes",
			"--accept-flake-config",
		}, nixClientOptionArgs(cfg)...)
		args = append(args, "--command")
		args = append(args, nixCommand...)
		if err := runExternalCommand(externalCommand{Name: "nix", Args: args, Dir: coreDir}); err != nil {
			return err
		}
	}

	if platformNixOpts.printConfig {
		_, err := fmt.Fprint(out, config)
		return err
	}
	return printNixSetupResult(result)
}

func printNixSetupResult(result NixSetupResult) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, result)
	case "yaml", "yml":
		return output.PrintYAML(out, result)
	default:
		tp := output.NewTablePrinter("CHECK", "VALUE")
		tp.AddRow("status", result.Status)
		tp.AddRow("nix", result.NixVersion)
		tp.AddRow("core", result.CoreDir)
		if result.CacheConfigured {
			tp.AddRow("cache", "fleet cache configured")
		} else {
			tp.AddRow("cache", "using public NixOS cache only")
		}
		if result.UserConfigPath != "" {
			tp.AddRow("user config", result.UserConfigPath)
		}
		if result.ConfigOutput != "" {
			tp.AddRow("config output", result.ConfigOutput)
		}
		if result.GitHubEnvPath != "" {
			tp.AddRow("github env", result.GitHubEnvPath)
		}
		if result.Warmed {
			tp.AddRow("dev shell", "warmed")
		}
		if len(result.Command) > 0 {
			tp.AddRow("command", strings.Join(result.Command, " "))
		}
		return tp.Print(out)
	}
}

func buildNixClientConfig(cfg fleet.Config) string {
	substituters := []string{nixOSSubstituter}
	publicKeys := []string{nixOSPublicKey}
	if fleetNixCacheReady(cfg) {
		substituters = append(substituters, strings.TrimRight(strings.TrimSpace(cfg.Release.NixCache.PublicBaseURL), "/"))
		publicKeys = append(publicKeys, trustedNixCachePublicKey(cfg.Release.NixCache))
	}
	sort.Strings(substituters[1:])
	sort.Strings(publicKeys[1:])
	return strings.Join([]string{
		"experimental-features = nix-command flakes",
		"accept-flake-config = true",
		"sandbox = true",
		"substituters = " + strings.Join(uniqueStrings(substituters), " "),
		"trusted-public-keys = " + strings.Join(uniqueStrings(publicKeys), " "),
		"connect-timeout = 5",
		"download-attempts = 3",
		"",
	}, "\n")
}

func nixClientOptionArgs(cfg fleet.Config) []string {
	if !fleetNixCacheReady(cfg) {
		return nil
	}
	return []string{
		"--option", "extra-substituters", strings.TrimRight(strings.TrimSpace(cfg.Release.NixCache.PublicBaseURL), "/"),
		"--option", "extra-trusted-public-keys", trustedNixCachePublicKey(cfg.Release.NixCache),
	}
}

func fleetNixCacheReady(cfg fleet.Config) bool {
	cache := cfg.Release.NixCache
	return strings.TrimSpace(cache.PublicBaseURL) != "" && trustedNixCachePublicKey(cache) != ""
}

func trustedNixCachePublicKey(cache fleet.NixCache) string {
	key := strings.TrimSpace(cache.PublicKey)
	if key == "" {
		return ""
	}
	if strings.Contains(key, ":") {
		return key
	}
	name := strings.TrimSpace(cache.SigningKeyName)
	if name == "" {
		return key
	}
	return name + ":" + key
}

func writeUserNixConfig(config string) (string, error) {
	path, err := userNixConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	updated := replaceManagedNixConfigBlock(string(raw), config)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func userNixConfigPath() (string, error) {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "nix", "nix.conf"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "nix", "nix.conf"), nil
}

func replaceManagedNixConfigBlock(existing, config string) string {
	block := clearcuttNixConfigBegin + "\n" + strings.TrimSpace(config) + "\n" + clearcuttNixConfigEnd + "\n"
	start := strings.Index(existing, clearcuttNixConfigBegin)
	end := strings.Index(existing, clearcuttNixConfigEnd)
	if start >= 0 && end >= start {
		end += len(clearcuttNixConfigEnd)
		next := existing[end:]
		next = strings.TrimPrefix(next, "\r\n")
		next = strings.TrimPrefix(next, "\n")
		prefix := strings.TrimRight(existing[:start], "\r\n")
		if prefix != "" {
			prefix += "\n\n"
		}
		if next != "" {
			return prefix + block + "\n" + next
		}
		return prefix + block
	}
	existing = strings.TrimRight(existing, "\r\n")
	if existing == "" {
		return block
	}
	return existing + "\n\n" + block
}

func appendGitHubEnvMultiline(path, key, value string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	delimiter := "CLEARCUTT_NIX_CONFIG"
	_, err = fmt.Fprintf(f, "%s<<%s\n%s\n%s\n", key, delimiter, value, delimiter)
	return err
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
