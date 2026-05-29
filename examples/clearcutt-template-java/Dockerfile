# =========================================================================
# Stage 1: Hermetic Compilation inside ClearCutt Brokered Java Dev Layer
# =========================================================================
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY . .
RUN mvn clean package

# =========================================================================
# Stage 2: Distribute inside Hardened Zero-Utility Java Distroless Layer
# =========================================================================
# Pin this base to a verified @sha256 digest in production after running the
# catalog verification commands for the target release.
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless

COPY --from=builder /workspace/target/clearcutt-template-java-1.0.0.jar /app/app.jar

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
