# ClearCutt demo tape.
#
# Regenerate docs/images/demo.gif with ./scripts/record-demo.sh.
#
# This recording is LIVE, not fixture-backed: it starts from nothing but a list
# of image references and actually observes docker.io, so `import observe` needs
# network. That is deliberate. The single most common question about the earlier
# cut was "what is an observations.json?", and the honest answer is not a caption
# -- it is watching one get made out of eight public image names in two seconds.
#
# The story is what the tool is genuinely for, in the order a person hits it:
#   1. here is the estate, and here is where the data comes from   (cat + import)
#   2. what are these built on, and what would patching move?      (graph build)
#   3. which of them ship openssl?                                 (graph packages)
#
# Beat 3 is a deliberate non-answer. Debian records no package set, so the tool
# says UNKNOWN and prices the fix rather than reporting absence as zero. Showing
# the tool fail honestly is the point; a demo that only shows wins teaches a
# viewer nothing about whether to trust the wins.
#
# All eight images are public and recognisable and none of them are ours -- the
# whole claim is that this works on images you did not build.
#
# Geometry: FontSize 16 at Width 1240 gives 111 columns, which keeps every
# summary and table line whole and lets only the two long prose explanations
# wrap. Fewer columns means a larger effective font once GitHub scales the GIF
# into a README, so this is as narrow as the content allows. Height 500 gives
# 24 rows against a 23-row tallest beat, so no screen sits in dead pixels.

Output docs/images/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1240
Set Height 500
Set Padding 14
Set TypingSpeed 20ms

# Hidden setup: build a scratch estate containing nothing but the ref list, so
# what follows is genuinely end-to-end and the repo is not written to.
Hide
Type "export PATH=$PWD:$PATH" Enter
Type "export PS1='$ '" Enter
Type "rm -rf /tmp/clearcutt-demo && mkdir -p /tmp/clearcutt-demo" Enter
Type "cat examples/runtime-estate/refs.txt > /tmp/clearcutt-demo/refs.txt" Enter
Type "cd /tmp/clearcutt-demo" Enter
Type "clear" Enter
Show
Sleep 600ms

Type@8ms "# Eight images we run. We built none of them, and none of them say what they are."
Enter
Sleep 800ms
Type "cat refs.txt"
Enter
Sleep 2.2s

Type "clearcutt import images --refs refs.txt --output images.yaml"
Enter
Sleep 1s
Type "clearcutt import observe --images images.yaml --output observations.json"
Enter
Sleep 2.5s

Type@8ms "# That is all an observations file is: 8 manifests and configs, read from the registries."
Enter
Sleep 2.2s

Hide
Type "clear" Enter
Show
Sleep 300ms

Type@8ms "# The question that matters: what are they built on, and what would patching actually move?"
Enter
Sleep 1s
Type "clearcutt graph build"
Enter
Sleep 5.5s

Type@8ms "# One debian layer under 6 of the 8 - proven by layer digest, not taken on trust from a label."
Enter
Type@8ms "# nginx and node:20 are not on it. Patch debian and they do not move. It says so, and says why."
Enter
Sleep 4s

Hide
Type "clear" Enter
Show
Sleep 300ms

Type@8ms "# And the question every advisory opens with: which of these ship openssl?"
Enter
Sleep 1s
Type "clearcutt graph packages --package openssl"
Enter
Sleep 4s

Type@8ms "# It does not know - and refuses to call that zero. It prices the answer instead: 8 fetches."
Enter
Sleep 3s

Type@8ms "# Proven where it can be proven. Named where it cannot. No scanner, no rebuild, no agent."
Enter
Sleep 3s
