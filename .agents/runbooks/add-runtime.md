# Runbook: Adding or Updating a Matrix Runtime

This runbook guides you through adding a new target language runtime or updating an existing version in the ClearCutt Nix image factory.

---

## 1. Locate the Central Registry

All language specifications, runtime attributes, package targets, and transformers are declared in `core/lib/registry.nix`.

---

## 2. Walkthrough: Adding a Runtime

### Step A: Declare the Language and Version
Open `core/lib/registry.nix` and navigate to the `languages` attribute set. Add your new language or version inside the appropriate block.

Example: Adding `java` version `"26"`:
```nix
java = {
  versions = {
    # Existing versions (21, 25...)
    "26" = {
      overlayName = "clearcuttJava26";
      raw = [ (getPkg [ [ "jdk26" ] [ "openjdk26" ] ] "Java 26 is not available in this nixpkgs version") ];
      devExtra = [ pkgs.maven pkgs.gradle ];
      runtimeTransformer = pkg: if pkg ? jre then pkg.jre else pkg;
    };
  };
};
```

### Step B: Configure Runtime Rules
Set the relevant attributes based on the runtime constraints:
* **`overlayName`:** The camelCase name used when registering in the downstream Nix overlay (e.g., `clearcuttNode24`).
* **`raw`:** A list of primary derivations fetched from nixpkgs. Use `getPkg [ [ "path" "to" "pkg" ] ] "Error message"` to handle fallback gracefully.
* **`devExtra`:** Extra utility packages bundled only in the `dev` (Builder) tier (e.g., compile-time tools, package managers like Maven/Pip).
* **`runtimeTransformer`:** A lambda function to strip development modules when producing the `slim` / `distroless` execution layers.
* **`omitInProduction`:** Set to `true` if the runtime is purely for building and has no slim/distroless counterpart (e.g., Go compiler, Rust, C++).
* **`useRemoveNpm`:** Custom flag for Node environments to strip package manager bloat in production.
* **`slimOverride` / `distrolessOverride`:** Explicitly override the production derivations instead of using the raw set. (Used by `.NET` to load bare ASP.NET runtime runtimes).

---

## 3. Verify & Smoke Test

### Step A: Enter the devShell
Move into the core workspace:
```bash
cd core
nix develop --extra-experimental-features "nix-command flakes"
```

### Step B: Build Target Layers
Compile your new image layers locally using the host platform to verify Nix evaluation:
```bash
# General package syntax: <lang><version>-<tier>
nix build .#java26-dev
nix build .#java26-slim
nix build .#java26-distroless
```

### Step C: Execute Verification Gate
Run the standard validation script to check dynamic link paths, CA cert bounds, and non-root execution permissions:
```bash
# Inside the core directory
./tests/verify.sh
```
If all tests pass, the new runtime is ready. Run `make test` from the repo root before committing.
