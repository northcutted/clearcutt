# clearcutt-template-java

This starter app uses one ClearCutt runtime line for the whole path:

- build in: ghcr.io/northcutted/clearcutt/clearcutt-java21:dev
- run in: ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless
- certify with: northcutted/clearcutt/.github/actions/certify-app@v0.11.1
- optional rebase base id: java21-distroless

The release workflow builds, signs, attests, and certifies the image. The rebase
workflow lets a platform workflow move the app layer onto a patched ClearCutt base
without recompiling the application.
