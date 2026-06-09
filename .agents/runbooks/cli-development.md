# Runbook: CLI Development & Schema Enforcement

This runbook guides you through adding commands to the Go governance CLI (`clearcutt`), updating declarative YAML/JSON schemas, and verifying CLI changes.

---

## 1. CLI Project Structure

All Go command implementations and logic live in the `cli/` workspace:

* **`cli/cmd/clearcutt/main.go`:** Statically compiled Cobra entrypoint.
* **`cli/internal/commands/`:** Individual subcommand declarations and logic.
  * `root.go`: Cobra root command registrations.
  * `<command_name>.go`: cobra subcommand implementations.
* **`cli/internal/testdata/catalog/`:** The offline catalog fixture used for unit tests.

---

## 2. Walkthrough: Adding a CLI Command

### Step A: Declare the Command File
Create a new file under `cli/internal/commands/<cmd_name>.go`.

Example Cobra Subcommand Skeleton:
```go
package commands

import (
	"fmt"
	"github.com/spf13/cobra"
)

var myCmdFlags struct {
	customFlag string
}

func init() {
	myCmd := &cobra.Command{
		Use:   "mycommand",
		Short: "Brief description of my command",
		Long:  `Detailed description of my command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMyCommand()
		},
	}

	myCmd.Flags().StringVar(&myCmdFlags.customFlag, "custom-flag", "", "Description of custom flag")
	rootCmd.AddCommand(myCmd)
}

func runMyCommand() error {
	// Write command execution logic here
	fmt.Println("Executing my command!")
	return nil
}
```

### Step B: Offline Testing Pattern
When writing tests under `cli/internal/commands/<cmd_name>_test.go`, never rely on a dynamically generated catalog index. Point `--catalog` at the committed fixture catalog to make it run offline:

```go
func TestMyCommand(t *testing.T) {
	// Call your command runner, supplying the local fixture directory:
	catalogPath := "../testdata/catalog"
	// Assert expected command outcomes against fixture records...
}
```

---

## 3. Schema & Validation Policies

If your command processes YAML/JSON policies (like Triages, Exceptions, or Certification policies):

* **JSON Schema:** Declare or update schema definitions inside `schemas/`.
* **Schema Validation:** Implement schema verification constraints inside the Go code using structured JSON schema checkers.
* **Exceptions Constraint:** Remember that exceptions triages MUST declare exactly `kind: VulnerabilityExceptions`. Do not use generic resource kinds.

---

## 4. Compile & Verify Gates

Always run the full suite of checks before completing your CLI work:

### Step A: Build & Vet CLI
```bash
# Build the clearcutt executable to the root
make cli-build

# Run Go linter checks and tests
make cli-vet
make cli-test
```

### Step B: Execute the Ecosystem Smoke Gating
Run the unified verification script to ensure your CLI changes haven't regressed composite actions, schemas, or doc flags:
```bash
./.claude/skills/test-clearcutt/scripts/verify.sh
```
If formatting checks fail (`gofmt`), run `gofmt -w` on all modified `.go` files and execute the script again.
