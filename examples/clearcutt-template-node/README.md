# clearcutt-template-node

This starter app uses one ClearCutt runtime line for the whole path:

- build in: ghcr.io/northcutted/clearcutt/clearcutt-node22:dev
- run in: ghcr.io/northcutted/clearcutt/clearcutt-node22:distroless
- certify with: northcutted/clearcutt/.github/actions/certify-app@v0.11.1
- optional rebase base id: node22-distroless

The release workflow builds, signs, attests, and certifies the image. The rebase
workflow lets a platform workflow move the app layer onto a patched ClearCutt base
without recompiling the application.
