# =========================================================================
# Stage 1: Build virtual environment dependencies in Python 3.15 Dev
# =========================================================================
FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.15:dev AS builder
WORKDIR /workspace

COPY requirements.txt .
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# =========================================================================
# Stage 2: Graft compiled virtual environment onto Python 3.15 Slim
# =========================================================================
# Pin base to concrete cryptographic digest in production
FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.15:slim@sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app ./app

# Add virtualenv to PATH and set execution context
ENV PATH="/opt/venv/bin:$PATH"
USER 10001:10001

EXPOSE 8000
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
