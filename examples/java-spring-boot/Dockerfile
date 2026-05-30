# =========================================================================
# Stage 1: Compile the application fat JAR in Java 25 Dev Environment
# =========================================================================
FROM ghcr.io/northcutted/clearcutt/clearcutt-java25:dev AS builder
WORKDIR /workspace

# Copy dependencies list and cache them
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and package fat JAR
COPY src ./src
RUN mvn package -DskipTests

# =========================================================================
# Stage 2: Graft the application onto Java 25 Hardened Distroless Base
# =========================================================================
# Pin base to concrete cryptographic digest in production
FROM ghcr.io/northcutted/clearcutt/clearcutt-java25:distroless@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

WORKDIR /app
COPY --from=builder /workspace/target/demo-0.0.1-SNAPSHOT.jar /app/demo.jar

# Enforce numeric rootless execution boundaries
USER 10001:10001
ENTRYPOINT ["java", "-jar", "/app/demo.jar"]
