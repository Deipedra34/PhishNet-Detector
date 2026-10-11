# syntax=docker/dockerfile:1

# ---- Stage 1: build the runnable fat jar ------------------------------------
# Runs on the build host's native platform: the jar is platform-independent, so
# a multi-arch build only compiles once instead of once per architecture under
# emulation. Java 26 matches maven.compiler.* in pom.xml.
FROM --platform=$BUILDPLATFORM maven:3.9-eclipse-temurin-26 AS build

WORKDIR /build
COPY pom.xml .
COPY src ./src

# package runs the test suite too (network-tagged tests are excluded via pom.xml),
# so a broken build never produces an image. The cache mount keeps downloaded
# dependencies between local rebuilds without baking them into a layer.
RUN --mount=type=cache,target=/root/.m2 mvn -B clean package

# ---- Stage 2: minimal JRE-only runtime --------------------------------------
FROM eclipse-temurin:26-jre-alpine

# Run as an unprivileged user. A fixed numeric UID/GID lets orchestrators
# (e.g. Kubernetes runAsNonRoot) verify the image doesn't run as root.
RUN addgroup -S -g 10001 phishnet \
    && adduser -S -D -H -u 10001 -G phishnet -s /sbin/nologin phishnet \
    && mkdir -p /opt/phishnet /data \
    && chown phishnet:phishnet /data

# The jar stays root-owned and read-only to the runtime user.
COPY --from=build /build/target/phishnet.jar /opt/phishnet/phishnet.jar

# Working directory for relative paths: mount files to scan here, and the default
# ./phishnet-history.csv and HTML reports are written here.
WORKDIR /data

USER 10001:10001

# Default port for "serve" mode; publish it with -p when running the API.
EXPOSE 8080

# Arguments to "docker run <image> ..." go straight to the CLI, e.g.
#   docker run --rm <image> --url https://example.com
#   docker run --rm -p 8080:8080 <image> serve --port 8080
ENTRYPOINT ["java", "-jar", "/opt/phishnet/phishnet.jar"]
CMD ["--help"]
