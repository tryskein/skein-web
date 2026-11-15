# syntax=docker/dockerfile:1.7
#
# skein-web — .NET 10 BFF/Gateway. Hosts cookie session, SignalR Hub
# (/hub), reverse-proxy for /api/v1/* → skein-api, and the auth
# controllers (/api/auth/*). NO LONGER serves the React SPA — that
# moved to a sibling skein-frontend image (nginx-unprivileged) in
# May 2026. Rationale for the split:
#   - Frontend-only changes (CSS, typo fixes) no longer roll the BFF,
#     so live SignalR sessions survive a SPA-only release.
#   - The version-check banner now reflects "deployed SPA version"
#     specifically — backend-only deploys correctly do not trigger
#     a "please refresh" notification.
#   - Independent CI / image-policy cadence for the two artefacts.
#
# Stages:
#   1. backend-build  — mcr.microsoft.com/dotnet/sdk:10.0-alpine,
#                       restores and publishes SkeinWeb in Release.
#   2. runtime        — mcr.microsoft.com/dotnet/aspnet:10.0-alpine
#                       with diagnostic utilities, the base image's
#                       non-root user (numeric APP_UID), and
#                       the published backend. No wwwroot/ — SPA lives
#                       in the skein-frontend image.

# ============ Stage 1: backend-build ============
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS backend-build

WORKDIR /build

# Restore in a separate layer so dependency restore is cached when only
# C# source files change.
COPY src/SkeinWeb.csproj ./
RUN dotnet restore SkeinWeb.csproj

COPY src/ ./
RUN dotnet publish SkeinWeb.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

# ============ Stage 2: runtime ============
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine

# Diagnostic utilities so operators can
# debug a live container: HTTP probes, network reach, DB connectivity, DNS
# resolution, and TCP port checks.
RUN apk add --no-cache \
    curl \
    iputils-ping \
    postgresql16-client \
    bind-tools \
    netcat-openbsd \
    ca-certificates \
    tzdata

WORKDIR /app

COPY --from=backend-build /app/publish ./

# The license text travels with every copy of the image (BSL 1.1 requires it).
COPY LICENSE /licenses/LICENSE

# Non-root, by numeric id: the base image's own `app` user (APP_UID, 1654).
# A numeric USER lets the kubelet verify runAsNonRoot without a runAsUser
# override; a user name cannot be checked and the pod would not start.
USER $APP_UID

# Default port; can be overridden via the PORT env var without rebuilding.
ENV PORT=8080
EXPOSE 8080

# Liveness for runtimes that read the image healthcheck (plain docker,
# compose without its own `healthcheck:`). /healthz checks no dependency
# (Program.cs), so an outage of Redis or NATS does not mark the
# container unhealthy; readiness stays with /ready. The shell form reads
# PORT at check time, the same variable the app binds to, with the same
# 8080 fallback. The port opens only after skein-api answers the
# instance-config request, which waits up to SKEIN_API_STARTUP_TIMEOUT_SECONDS
# (60 s by default); start-period covers that default. A deployment that
# raises the timeout must raise start-period with it, or the container is
# reported unhealthy while it is still legitimately waiting.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS -o /dev/null "http://127.0.0.1:${PORT:-8080}/healthz" || exit 1

ENTRYPOINT ["dotnet", "SkeinWeb.dll"]
