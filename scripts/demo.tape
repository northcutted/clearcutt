# ClearCutt demo tape.
#
# Regenerate docs/images/demo.gif with ./scripts/record-demo.sh. Every command
# runs against committed fixtures, so the recording reproduces from a fresh
# checkout with no network and no credentials.
#
# It tells one incident in three questions, in the order they actually get
# asked, and each command is the whole answer:
#   1. an advisory names openssl - which images ship it?        (nix-estate)
#   2. what would one bad layer reach?                          (public-estate)
#   3. what are those images even based on, and how do we know? (public-estate)
#
# The provenance beat runs last on purpose. It is both the densest screen and
# the one thing no scanner does, so it is what the loop rests on.
#
# Captions are typed fast (Type@8ms) because they are meant to be read, not
# watched; commands are typed at human speed so they register as commands.
#
# The geometry is measured, not guessed. Width 1280 at FontSize 16 fits the
# widest line the CLI emits here (114 columns) without wrapping, and stays
# legible after GitHub scales the GIF into a README column. Height 600 gives
# 29 rows; the tallest beat -- `graph build` with its captions -- needs 27, so
# nothing scrolls off the top and no beat sits in a field of dead pixels.

Output docs/images/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1280
Set Height 600
Set Padding 14
Set TypingSpeed 25ms

# Setup, hidden: put the built CLI on PATH, take a clean prompt, open the Nix
# estate. Each fixture directory holds an observations.json, which is the
# default every graph command reads -- hence the bare commands below.
Hide
Type "export PATH=$PWD:$PATH" Enter
Type "export PS1='$ '" Enter
Type "cd examples/nix-estate" Enter
Type "clear" Enter
Show
Sleep 800ms

Type@8ms "# An openssl advisory just landed. Which of our images actually ship it?"
Enter
Sleep 1s
Type "clearcutt graph packages --package openssl"
Enter
Sleep 4.5s

Type@8ms "# Four of ten, by name and version - read out of image configs already fetched."
Enter
Type@8ms "# No SBOM to build, no scanner to run, nothing to rebuild."
Enter
Sleep 3.2s

Hide
Type "cd ../public-estate" Enter
Type "clear" Enter
Show
Sleep 400ms

Type@8ms "# Different estate: 19 public images we run but did not build. What would one bad layer reach?"
Enter
Sleep 1.2s
Type "clearcutt graph layers"
Enter
Sleep 3.2s

Type@8ms "# 12 layers shared across the estate - and that reuse saves 15% of what storing them would cost."
Enter
Sleep 3.2s

Hide
Type "clear" Enter
Show
Sleep 400ms

Type@8ms "# And what are those 19 based on? debian, alpine, node, postgres, chainguard, paketo."
Enter
Sleep 1.2s
Type "clearcutt graph build | head -21"
Enter
Sleep 6.5s

Type@8ms "# 3 resolved - and it says which 2 are proven by layer digest, not merely claimed by a label."
Enter
Type@8ms "# The other 14 come back undetermined, each with its reason. ClearCutt does not guess."
Enter
Sleep 1.8s
Type@8ms "# Govern the container images you already run - including every one you did not build."
Enter
Sleep 4s
