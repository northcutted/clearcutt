package commands

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// collectCommandPaths returns the arg path for every (sub)command in the tree,
// skipping cobra's auto-generated help/completion commands.
func collectCommandPaths(cmd *cobra.Command, prefix []string, out *[][]string) {
	for _, c := range cmd.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		path := append(append([]string{}, prefix...), c.Name())
		*out = append(*out, path)
		collectCommandPaths(c, path, out)
	}
}

// Guards the whole command tree, which `go build` cannot: cobra panics at
// help-render time when a command's GroupID is not registered on its parent
// (`AddGroup`), and the top-level command grouping + the `verify` subcommand
// split make that easy to break. Rendering --help for every command catches group
// mis-registration, broken usage templates, and missing metadata in the same
// `go test` that already runs on every PR — no new CI infrastructure.
func TestCommandTreeRendersHelpWithoutPanic(t *testing.T) {
	// Structural pass: every GroupID must exist on the parent (clearer failure
	// than the eventual panic).
	var walk func(cmd *cobra.Command, path []string)
	walk = func(cmd *cobra.Command, path []string) {
		if cmd.GroupID != "" && cmd.HasParent() && !cmd.Parent().ContainsGroup(cmd.GroupID) {
			t.Errorf("%s: GroupID %q is not registered on its parent (add it via AddGroup)", strings.Join(path, " "), cmd.GroupID)
		}
		if cmd.HasParent() && cmd.Short == "" {
			t.Errorf("%s: missing Short description", strings.Join(path, " "))
		}
		for _, c := range cmd.Commands() {
			if c.Name() == "help" || c.Name() == "completion" {
				continue
			}
			walk(c, append(path, c.Name()))
		}
	}
	walk(NewRootCmd(), []string{"clearcutt"})

	// Behavioral pass: actually render --help for root and every command path. A
	// group/registration bug panics here; recover so one bad command reports a
	// clean failure instead of crashing the whole test binary.
	var paths [][]string
	collectCommandPaths(NewRootCmd(), nil, &paths)
	paths = append([][]string{{}}, paths...) // include root itself

	for _, p := range paths {
		label := "clearcutt " + strings.Join(p, " ")
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("`%s --help` panicked: %v", label, r)
				}
			}()
			args := append(append([]string{}, p...), "--help")
			if _, err := runCLI(t, args...); err != nil {
				t.Errorf("`%s --help` returned an error: %v", label, err)
			}
		}()
	}
}
