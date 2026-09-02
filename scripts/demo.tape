# ClearCutt demo tape.
#
# Regenerate docs/images/demo.gif with ./scripts/record-demo.sh. Every command
# below runs against committed fixtures, so the recording is reproducible from a
# fresh checkout with no network and no published catalog data.
#
# The story, in three beats:
#   1. what an estate is built on, and how strongly we know it
#   2. what it has in common, and what one bad layer would reach
#   3. which images ship a package an advisory just named

Output docs/images/demo.gif

Set Shell bash
Set FontSize 13
Set Width 1240
Set Height 720
Set Padding 12
Set TypingSpeed 25ms

Type "# ClearCutt governs container image estates — including ones it did not build."
Enter
Sleep 1s
Type "# These 19 images are real public ones: debian, alpine, node, postgres, chainguard, paketo."
Enter
Sleep 2s

Type "./clearcutt graph build --observations examples/public-estate/observations.json --output /tmp/estate/graph.json | head -14"
Enter
Sleep 7s

Type "# 3 of 19 resolved. Only 2 are PROVEN by layer digests; the third rests on a label."
Enter
Sleep 2.5s
Type "# The other 14 are reported as undetermined, with the reason. Absence is never zero."
Enter
Sleep 3s

Type "./clearcutt graph layers --observations examples/public-estate/observations.json --output /tmp/estate/layers.json"
Enter
Sleep 5s

Type "# Now an openssl advisory lands. Which images actually ship it?"
Enter
Sleep 2s

Type "./clearcutt graph packages --observations examples/nix-estate/observations.json --package openssl"
Enter
Sleep 7s

Type "# Read from the image config that was already fetched. No SBOM, no extra requests."
Enter
Sleep 3s
