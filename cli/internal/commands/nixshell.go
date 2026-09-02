package commands

// nixDevelopCommand returns argv for running a tool inside a Nix dev shell.
//
// ClearCutt no longer builds images, so it no longer ships a flake — but the
// capability is generic and worth keeping: anyone with their own flake can run
// the scanner from a pinned dev shell instead of whatever happens to be on
// PATH, which is the difference between a reproducible scan and an approximate
// one. Point --core-dir at the directory holding the flake.
func nixDevelopCommand(name string, args ...string) []string {
	out := []string{
		"develop",
		"--extra-experimental-features", "nix-command flakes",
		"--accept-flake-config",
		"--command", name,
	}
	return append(out, args...)
}
