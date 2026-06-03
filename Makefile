# netctl — developer & CI tooling. Run `make help` for the target list.
# See docs/development.md for details. No business logic lives here (S0).

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# ---- configuration -------------------------------------------------------
MODULE   := github.com/imfeelingtheagi/netctl
GO       ?= go
BIN_DIR  := bin
BINARIES := netctl-control netctl-agent netctl-ebpf-agent netctl-endpoint netctl

# Go modules in the workspace (each has its own go.mod).
GO_MODULE_DIRS := . test

# Build metadata, injected into internal/version via -ldflags.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# Container / dev-stack settings.
IMAGE_REGISTRY ?= ghcr.io/imfeelingtheagi
IMAGE_TAG      ?= $(VERSION)
PLATFORMS      ?= linux/amd64,linux/arm64
DOCKERFILE     := deploy/docker/Dockerfile
COMPOSE_DEV    := deploy/compose/dev.yml

# Pinned tool versions.
GOLANGCI_LINT_VERSION ?= v2.12.2

# ---- meta ----------------------------------------------------------------
.PHONY: help
help: ## Show this help.
	@awk 'BEGIN{FS=":.*##"; print "netctl make targets:"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- build ---------------------------------------------------------------
.PHONY: build
build: ## Build all Go binaries into ./bin.
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do \
		echo ">> building $$b"; \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$b ./cmd/$$b || exit 1; \
	done

.PHONY: build-cross
build-cross: ## Cross-compile every binary for linux amd64 + arm64 (smoke test).
	@for arch in amd64 arm64; do \
		for b in $(BINARIES); do \
			echo ">> $$b linux/$$arch"; \
			GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -o /dev/null ./cmd/$$b || exit 1; \
		done; \
	done
	@echo "cross-compile OK (linux/amd64, linux/arm64)"

.PHONY: run
run: ## Run the control-plane server locally.
	$(GO) run ./cmd/netctl-control

.PHONY: ebpf-agent
ebpf-agent: ## Build netctl-ebpf-agent WITH the live CO-RE loader (-tags ebpf; Linux + clang + bpftool + BTF; run `go get github.com/cilium/ebpf` once first).
	@command -v clang   >/dev/null 2>&1 || { echo "ebpf-agent: clang required (e.g. apt install clang llvm libbpf-dev)"; exit 1; }
	@command -v bpftool >/dev/null 2>&1 || { echo "ebpf-agent: bpftool required (e.g. apt install linux-tools-common)"; exit 1; }
	@mkdir -p $(BIN_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
	cd internal/ebpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -tags ebpf l4flow ./bpf/l4flow.bpf.c -- -I./bpf
	cd internal/ebpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -tags ebpf sslsniff ./bpf/sslsniff.bpf.c -- -I./bpf
	CGO_ENABLED=0 $(GO) build -tags ebpf -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netctl-ebpf-agent ./cmd/netctl-ebpf-agent
	@echo "built $(BIN_DIR)/netctl-ebpf-agent (eBPF loader enabled)"

# ---- test ----------------------------------------------------------------
.PHONY: test
test: ## Run unit tests across all workspace modules.
	@for d in $(GO_MODULE_DIRS); do \
		echo ">> go test ($$d)"; \
		( cd $$d && $(GO) test -race -count=1 ./... ) || exit 1; \
	done

.PHONY: test-isolation
test-isolation: ## Run the cross-tenant isolation gate (CLAUDE.md §7 guardrail 1).
	$(GO) test -tags=isolation -race -count=1 ./...

.PHONY: test-integration
test-integration: ## Run integration tests across modules (needs a database / dev stack).
	@for d in $(GO_MODULE_DIRS); do \
		echo ">> integration tests ($$d)"; \
		( cd $$d && $(GO) test -tags=integration -count=1 ./... ) || exit 1; \
	done

.PHONY: test-python
test-python: ## Run the Python analyzer test suite (pytest).
	cd analyzer && python -m pytest

.PHONY: cover
cover: ## Run unit tests with a coverage profile.
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

# Packages the coverage gate floors: pure-logic / parser / probe code that needs
# no external services. Stateful DB/transport packages are gated for correctness
# by the integration + cross-tenant-isolation jobs instead (see check_coverage.sh).
COVER_PKGS := ./internal/apierror/... ./internal/otel/... ./internal/otel/otlp/... ./internal/version/... \
	./internal/config/... ./internal/a2a/... ./internal/canary/... ./internal/path/... \
	./internal/bgp/... ./internal/bus/... ./internal/pipeline/... ./internal/crypto/... \
	./internal/cli/... ./internal/opendata/... ./internal/alert/... ./internal/incident/... \
	./internal/auth/... ./internal/perf/... ./internal/ebpf/... ./internal/ebpf/l7/... ./internal/topology/... ./internal/ai/... ./internal/ai/mcp/... ./internal/ai/author/... ./internal/testspec/... ./internal/threat/... ./internal/change/... ./internal/scim/... ./internal/siem/... \
	./internal/store/pathstore/... ./internal/store/tsdb/... ./internal/store/migrate/...

.PHONY: cover-gate
cover-gate: ## Coverage profile (integration tag, service-free) + per-package floor gate.
	$(GO) test -tags=integration -covermode=atomic -coverprofile=coverage.out -count=1 $(COVER_PKGS)
	$(GO) tool cover -func=coverage.out | tail -1
	bash scripts/check_coverage.sh coverage.out

.PHONY: openapi-gate
openapi-gate: ## OpenAPI completeness gate (S19): valid 3.1 spec + no undocumented routes.
	GO=$(GO) bash scripts/check_openapi.sh

.PHONY: perf-smoke
perf-smoke: ## Load/perf smoke (S18a): ingest baseline (no DB) + pooled multi-tenant (needs Postgres).
	# Run without -race: this measures throughput/latency, and race instrumentation
	# distorts timing. The ingest baseline needs no services; the pooled
	# multi-tenant smoke uses NETCTL_DATABASE_URL (skips if absent).
	$(GO) test -count=1 -v -run '^TestIngestBaseline$$' ./internal/perf/
	$(GO) test -tags=integration -count=1 -v -run '^TestPooledMultiTenant$$' ./internal/perf/

.PHONY: fuzz-smoke
fuzz-smoke: ## Run each fuzz target briefly to catch crashers (CI smoke).
	$(GO) test -run=^$$ -fuzz=^FuzzParseICMPv4$$     -fuzztime=15s ./internal/path/
	$(GO) test -run=^$$ -fuzz=^FuzzParseTimeExceeded$$ -fuzztime=15s ./internal/path/
	$(GO) test -run=^$$ -fuzz=^FuzzEmbeddedEcho$$     -fuzztime=10s ./internal/path/
	$(GO) test -run=^$$ -fuzz=^FuzzIngest$$           -fuzztime=15s ./internal/bgp/

# ---- lint / format -------------------------------------------------------
.PHONY: lint
lint: lint-go lint-python ## Run all linters (Go + Python).

# The gofmt scope excludes generated code (*/gen/*) and throwaway spikes
# (./spike/* — separate out-of-workspace modules, not built/tested by CI; see
# spike/README.md). go vet runs over GO_MODULE_DIRS and golangci-lint over the
# workspace, so neither touches spike/ either.
.PHONY: lint-go
lint-go: ## gofmt check + go vet + golangci-lint + crypto-import guard.
	@files=$$(find . -name '*.go' -not -path '*/gen/*' -not -path './spike/*'); \
		bad=$$(gofmt -l $$files); \
		test -z "$$bad" || { echo "gofmt needed on:"; echo "$$bad"; exit 1; }
	@for d in $(GO_MODULE_DIRS); do ( cd $$d && $(GO) vet ./... ) || exit 1; done
	golangci-lint run
	./scripts/check_crypto_imports.sh

.PHONY: lint-python
lint-python: ## Lint the Python analyzer (ruff + black --check).
	ruff check analyzer
	black --check analyzer

.PHONY: fmt
fmt: ## Auto-format Go and Python.
	gofmt -w $$(find . -name '*.go' -not -path '*/gen/*' -not -path './spike/*')
	-ruff check --fix analyzer
	-black analyzer

.PHONY: tidy
tidy: ## Tidy go.mod across modules.
	@for d in $(GO_MODULE_DIRS); do ( cd $$d && $(GO) mod tidy ); done

# ---- codegen -------------------------------------------------------------
.PHONY: proto
proto: ## Lint and generate Go (+ gRPC) from protobuf via buf.
	@command -v buf >/dev/null 2>&1 || { echo "buf not installed — run 'make proto-tools'"; exit 1; }
	buf lint
	buf generate

.PHONY: proto-tools
proto-tools: ## Install protobuf codegen tools (buf + Go plugins) into GOPATH/bin.
	$(GO) install github.com/bufbuild/buf/cmd/buf@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# ---- migrate -------------------------------------------------------------
.PHONY: migrate
migrate: ## Apply DB migrations against NETCTL_DATABASE_URL.
	$(GO) run ./cmd/netctl-control migrate

# ---- security ------------------------------------------------------------
.PHONY: vuln
vuln: ## Scan Go dependencies for known vulnerabilities (govulncheck).
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# ---- containers / dev stack ---------------------------------------------
.PHONY: images
images: ## Build multi-arch images for all components (Buildx).
	@for b in $(BINARIES); do \
		echo ">> buildx $$b ($(PLATFORMS))"; \
		docker buildx build --platform $(PLATFORMS) \
			-f $(DOCKERFILE) --build-arg COMPONENT=$$b \
			--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
			-t $(IMAGE_REGISTRY)/$$b:$(IMAGE_TAG) -t $(IMAGE_REGISTRY)/$$b:latest \
			. || exit 1; \
	done

.PHONY: compose-up
compose-up: ## Start the local dev stack (Postgres/Kafka/ClickHouse/Prometheus).
	docker compose -f $(COMPOSE_DEV) up -d --wait

.PHONY: compose-down
compose-down: ## Stop and remove the local dev stack.
	docker compose -f $(COMPOSE_DEV) down -v

# ---- housekeeping --------------------------------------------------------
.PHONY: tools
tools: ## Install pinned dev tools (golangci-lint) into GOPATH/bin.
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
		| sh -s -- -b $$($(GO) env GOPATH)/bin $(GOLANGCI_LINT_VERSION)

.PHONY: clean
clean: ## Remove build output.
	rm -rf $(BIN_DIR) dist coverage.out

.PHONY: ci
ci: lint test test-isolation ## Run the core CI gates locally.
