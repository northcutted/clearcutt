# ClearCutt clean-clone demo tape.
# Regenerate docs/images/demo.gif with ./scripts/record-demo.sh — every
# command below runs against the committed fixture catalog, so the recording
# is reproducible from a fresh checkout with no published catalog data.

Output docs/images/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1100
Set Height 650
Set Padding 12
Set TypingSpeed 30ms

Type "# ClearCutt — evidence-backed base images, provable from a clean clone"
Enter
Sleep 1.5s

Type "./clearcutt --catalog cli/internal/testdata/catalog list"
Enter
Sleep 3s

Type "./clearcutt --catalog cli/internal/testdata/catalog inspect java21-distroless"
Enter
Sleep 4.5s

Type "./clearcutt --catalog cli/internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --max-critical 0 --max-high 3 --allow-preview"
Enter
Sleep 4.5s

Type "./clearcutt app template java --name demo-api --output /tmp/clearcutt-demo-app --force"
Enter
Sleep 3s

Type "./clearcutt catalog site build --catalog cli/internal/testdata/mixed-catalog --template site --output /tmp/clearcutt-demo-site --install --clean"
Enter
Sleep 7s
