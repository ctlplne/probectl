# syntax=docker/dockerfile:1
#
# Multi-arch build for any probectl Go binary, selected with the COMPONENT build
# arg (probectl-control | probectl-agent | probectl-ebpf-agent | probectl-endpoint | probectl).
# The builder stage runs natively on the build platform and cross-compiles to the
# target arch (CGO disabled, pure Go), so multi-arch builds need no emulation.
# Build context is the repository root.

ARG GO_VERSION=1.26
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
RUN npm run build   # → /web/dist (hashed assets)

# Digest-pinned (U-061); dependabot bumps the digest. Tag kept for humans.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:5d2b868674b57c9e48cdd39e891acce4196b6926ca6d11e9c270a8f85106203d AS build
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
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build -trimpath ${GO_TAGS:+-tags ${GO_TAGS}} \
      -ldflags "-s -w \
        -X github.com/imfeelingtheagi/probectl/internal/version.Version=${VERSION} \
        -X github.com/imfeelingtheagi/probectl/internal/version.Commit=${COMMIT} \
        -X github.com/imfeelingtheagi/probectl/internal/version.Date=${DATE}" \
      -o /out/app ./cmd/${COMPONENT}

# Minimal, non-root runtime. distroless/static keeps the image tiny and
# vulnerability-free for static Go binaries.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
ARG COMPONENT
LABEL org.opencontainers.image.source="https://github.com/imfeelingtheagi/probectl" \
      org.opencontainers.image.title="${COMPONENT}" \
      org.opencontainers.image.description="probectl ${COMPONENT}"
COPY --from=build /out/app /usr/local/bin/app
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/app"]
