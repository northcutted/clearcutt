FROM ghcr.io/northcutted/clearcutt/clearcutt-go1.25:dev AS builder
WORKDIR /workspace
COPY go.mod .
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /workspace/app ./cmd/app

FROM ghcr.io/northcutted/clearcutt/clearcutt-go1.25:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="go1.25-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/app /workspace/app
ENTRYPOINT ["/workspace/app"]
