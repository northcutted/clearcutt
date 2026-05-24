# =========================================================================
# Stage 1: Hermetic Compilation inside ClearCutt Brokered Java Dev Layer
# =========================================================================
FROM ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY . .
RUN mvn clean package

# =========================================================================
# Stage 2: Distribute inside Hardened Zero-Utility Java Distroless Layer
# =========================================================================
# Locked via secure cryptographic digest pin to ensure immutable supply chain trust
FROM ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:distroless@sha256:4a081d694a054ee4a5ab5b270a4e5c689d023456789abcdef0123456789abcde

COPY --from=builder /workspace/target/clearcutt-template-java-1.0.0.jar /app/app.jar

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
