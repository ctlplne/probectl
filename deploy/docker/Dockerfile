# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
#
# Multi-arch build for any probectl Go binary, selected with the COMPONENT build
# arg (probectl-control | probectl-agent | probectl-ebpf-agent | probectl-endpoint | probectl).
# The builder stage runs natively on the build platform and cross-compiles to the
# target arch (CGO disabled, pure Go), so multi-arch builds need no emulation.
# Build context is the repository root.

ARG GO_VERSION=1.26.7
ARG NODE_VERSION=22

# UX-002: build the web UI FIRST, on the build platform, and hand its bundle to
# the Go stage so go:embed (internal/webui) ships the REAL single-page app — not
# the "not bundled" placeholder. The release image previously compiled Go without
# ever running `npm run build`, so every shipped binary served the stub. Building
# it here makes the default production image serve the real UI.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 AS web
WORKDIR /web
# Cache npm deps on the lockfile only.
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# The ee/ web seam is aliased to ../ee/web (vite.config.ts: resolve(__dirname,
# '../ee/web')). WORKDIR is /web, so ../ee/web resolves to /ee/web — COPY the
# commercial UI source there so the import resolves (the bundle always includes
# it; visibility is runtime-gated by the API, per the editions boundary).
COPY ee/web /ee/web
# The keyboard-journey contract test is type-checked by `npm run build` and
# imports this committed product baseline from outside web/. Preserve that same
# repository-relative path inside the isolated web build stage.
COPY docs/ux/journey-baseline.json /docs/ux/journey-baseline.json
# The web prebuild runs the rendered-browser self-test from the repository
# `scripts/` directory. That self-test also validates its dashboard fixture
# against the served OpenAPI schema, so both inputs must exist at their original
# repository-relative paths inside this isolated stage.
COPY scripts/web_rendered_a11y.mjs /scripts/web_rendered_a11y.mjs
COPY internal/control/openapi.json /internal/control/openapi.json
RUN npm run build   # → /web/dist (hashed assets)

# Digest-pinned (U-061); bumped manually per docs/dependency-policy.md (no
# auto-update bot). Tag kept for humans.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:6ef6e30f0ea5c384f6d111cf856e024e3086bbdcb1779da3f3b3fbba0aea53d2 AS build
ARG COMPONENT
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown
# GO_TAGS: optional Go build tags. EMPTY for release builds (the default), so
# release/CI images are byte-for-byte unaffected. The evaluation compose
# (deploy/compose/eval.yml) passes GO_TAGS=devauth to compile the LOCAL-ONLY
# dev-auth control plane (RED-001) — release pipelines must never set it.
ARG GO_TAGS=""
# GOFIPS140: EMPTY for the standard build. Set to the validated Go Cryptographic
# Module version (e.g. v1.0.0) together with GO_TAGS=probectl_fips to produce
# the FIPS 140-3 artifact from this Dockerfile — the same pair `make build-fips`
# uses — so an operator gets a FIPS image without a second build recipe.
ARG GOFIPS140=""
# DPR-001: optional link-time license trust anchors (comma-separated base64
# PEMs) on top of the committed internal/license/trusted_keys/*.pub anchors.
# Empty leaves the committed anchors as the only trust. See docs/editions.md.
ARG LICENSE_PUBKEYS_B64=""
WORKDIR /src

# Cache dependencies first for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN test -n "$COMPONENT" || { echo "COMPONENT build-arg is required"; exit 1; }
# UX-002: overlay the real Vite bundle over the committed placeholder so the
# control plane's go:embed (internal/webui) ships the actual UI. The build above
# always runs, so the shipped image can never silently serve the stub.
COPY --from=web /web/dist/ ./internal/webui/dist/
RUN test -d ./internal/webui/dist/assets || { echo "UX-002: web bundle missing — internal/webui/dist has no assets/"; exit 1; }
# DPR-018: the documented "build from this checkout" command passes no
# VERSION/COMMIT/DATE, and a control plane that reports 0.0.0-dev / unknown /
# unknown cannot be told apart from a stale one in a support bundle. Without
# build-args, stamp the checkout's VERSION file (suffixed -local: not a release)
# and the build time; the commit stays "unknown" because .git is excluded from
# the build context (pass --build-arg COMMIT=$(git rev-parse --short HEAD)).
# Release builds set all three explicitly and are byte-for-byte unaffected.
RUN --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    version="${VERSION}"; build_date="${DATE}"; \
    if [ "${version}" = "0.0.0-dev" ] && [ -s VERSION ]; then version="$(tr -d '[:space:]' < VERSION)-local"; fi; \
    if [ "${build_date}" = "unknown" ]; then build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; fi; \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 GOTOOLCHAIN=local ${GOFIPS140:+GOFIPS140=${GOFIPS140}} \
    go build -trimpath ${GO_TAGS:+-tags ${GO_TAGS}} \
      -ldflags "-s -w \
        -X github.com/ctlplne/probectl/internal/version.Version=${version} \
        -X github.com/ctlplne/probectl/internal/version.Commit=${COMMIT} \
        -X github.com/ctlplne/probectl/internal/version.Date=${build_date} \
        ${LICENSE_PUBKEYS_B64:+-X github.com/ctlplne/probectl/internal/license.builtinPubKeysB64=${LICENSE_PUBKEYS_B64}}" \
      -o /out/app ./cmd/${COMPONENT}
# DPR-001: a requested link-time trust anchor must actually be in the binary.
# The -X payload is stored verbatim as string data, so a silent drop (a typo'd
# variable path, a stripped flag) is caught here for any target architecture.
# DPR-024: only for the binaries that verify license files
# (internal/license/anchored_binaries.txt); agents and collectors never call
# TrustedKeys, so the linker drops the unused string from them by design.
RUN if [ -n "${LICENSE_PUBKEYS_B64}" ] && grep -qx -- "${COMPONENT}" internal/license/anchored_binaries.txt; then \
      grep -qaF -- "${LICENSE_PUBKEYS_B64}" /out/app \
        || { echo "DPR-001: license trust anchor was not linked into ${COMPONENT}"; exit 1; }; \
    fi
# Named volumes mounted over paths absent from the image are initialized as
# root-owned. Seed both writable runtime paths with the distroless nonroot
# identity: certgen needs /certs for its 0600 private key, and control plus the
# real-Dex overlay need /var/lib/probectl for the envelope/evidence keys, tenant
# object store, and Dex SQLite state.
# DPR-019: agents document /var/lib/probectl-agent as their state directory;
# seed it non-root-owned as well so a fresh named volume mounted there is
# writable by the distroless nonroot user.
RUN install -d -m 0700 -o 65532 -g 65532 /out/certs /out/probectl /out/probectl-agent

# Minimal, non-root runtime. distroless/static keeps the image tiny and
# vulnerability-free for static Go binaries.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
ARG COMPONENT
LABEL org.opencontainers.image.source="https://github.com/ctlplne/probectl" \
      org.opencontainers.image.title="${COMPONENT}" \
      org.opencontainers.image.description="probectl ${COMPONENT}"
COPY --from=build /out/app /usr/local/bin/app
COPY --from=build --chown=nonroot:nonroot /out/certs/ /certs/
COPY --from=build --chown=nonroot:nonroot /out/probectl/ /var/lib/probectl/
COPY --from=build --chown=nonroot:nonroot /out/probectl-agent/ /var/lib/probectl-agent/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/app"]
