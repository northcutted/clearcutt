FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B package

FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="java21-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/target/app.jar /workspace/app.jar
ENTRYPOINT ["java","-jar","/workspace/app.jar"]
