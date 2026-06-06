FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.15:dev AS builder
WORKDIR /workspace
COPY requirements.txt .
COPY app ./app
RUN python -m compileall app

FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.15:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="python3.15-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/app /workspace/app
ENTRYPOINT ["python","/workspace/app/main.py"]
