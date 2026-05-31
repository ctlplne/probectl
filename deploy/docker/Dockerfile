# syntax=docker/dockerfile:1
#
# Multi-arch build for any netctl Go binary, selected with the COMPONENT build
# arg (netctl-control | netctl-agent | netctl-ebpf-agent | netctl-endpoint | netctl).
# The builder stage runs natively on the build platform and cross-compiles to the
# target arch (CGO disabled, pure Go), so multi-arch builds need no emulation.
# Build context is the repository root.

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
ARG COMPONENT
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown
WORKDIR /src

# Cache dependencies first. (Only go.mod today — no third-party deps yet.)
COPY go.mod ./
RUN go mod download

COPY . .
RUN test -n "$COMPONENT" || { echo "COMPONENT build-arg is required"; exit 1; }
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/imfeelingtheagi/netctl/internal/version.Version=${VERSION} \
        -X github.com/imfeelingtheagi/netctl/internal/version.Commit=${COMMIT} \
        -X github.com/imfeelingtheagi/netctl/internal/version.Date=${DATE}" \
      -o /out/app ./cmd/${COMPONENT}

# Minimal, non-root runtime. distroless/static keeps the image tiny and
# vulnerability-free for static Go binaries.
FROM gcr.io/distroless/static-debian12:nonroot
ARG COMPONENT
LABEL org.opencontainers.image.source="https://github.com/imfeelingtheagi/netctl" \
      org.opencontainers.image.title="${COMPONENT}" \
      org.opencontainers.image.description="netctl ${COMPONENT}"
COPY --from=build /out/app /usr/local/bin/app
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/app"]
