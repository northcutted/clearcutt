FROM ghcr.io/northcutted/clearcutt/clearcutt-node22:dev AS builder
WORKDIR /workspace
COPY package.json .
COPY src ./src
RUN npm test && npm run build

FROM ghcr.io/northcutted/clearcutt/clearcutt-node22:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="node22-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/dist/server.js /workspace/server.js
ENTRYPOINT ["node","/workspace/server.js"]
