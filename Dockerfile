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
#                       with diagnostic utilities, non-root user, and
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

# Non-root user — running as root inside containers is forbidden by org policy
# and breaks Kubernetes PodSecurity restricted profiles.
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -D appuser

WORKDIR /app

COPY --from=backend-build /app/publish ./

# The license text travels with every copy of the image (BSL 1.1 requires it).
COPY LICENSE /licenses/LICENSE

USER appuser

# Default port; can be overridden via the PORT env var without rebuilding.
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "SkeinWeb.dll"]
