# probectl — developer & CI tooling. Run `make help` for the target list.
# See docs/development.md for details. No business logic lives here (S0).

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# ---- configuration -------------------------------------------------------
MODULE   := github.com/imfeelingtheagi/probectl
GO       ?= go
BIN_DIR  := bin
BINARIES := probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl

# FIPS 140-3 validated Go Cryptographic Module version (S-EE1). Selected at
# build time via GOFIPS140 — see docs/hardening.md for the validated boundary.
FIPS_MODULE ?= v1.0.0

# Go modules in the workspace (each has its own go.mod).
GO_MODULE_DIRS := . test

# Build metadata, injected into internal/version via -ldflags.
# OPS-008: the repo-root VERSION file is the single source of version truth
# (binary == chart appVersion == compose image pin). A tagged release overrides
# it via `git describe` (the tag is authoritative on release); otherwise the
# VERSION file is stamped into the binary so dev/compose/chart all agree.
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//' || cat VERSION 2>/dev/null || echo "0.0.0-dev")
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
# Codegen + scanner pins (U-059): match the committed internal/gen headers —
# bump these together with a regenerated tree; floating versions are banned.
BUF_VERSION ?= v1.50.0
PROTOC_GEN_GO_VERSION ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2
GOVULNCHECK_VERSION ?= v1.1.4

# ---- meta ----------------------------------------------------------------
.PHONY: help
help: ## Show this help.
	@awk 'BEGIN{FS=":.*##"; print "probectl make targets:"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- build ---------------------------------------------------------------
.PHONY: build
build: ## Build all Go binaries into ./bin.
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do \
		echo ">> building $$b"; \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$b ./cmd/$$b || exit 1; \
	done

.PHONY: build-fips
build-fips: ## Build the FIPS 140-3 distribution artifact (S-EE1): validated Go Cryptographic Module (GOFIPS140) + the probectl_fips marker tag. The artifact is the gate — no runtime license check.
	@mkdir -p $(BIN_DIR)
	@for b in probectl-control probectl-agent; do \
		echo ">> building $$b (FIPS 140-3, GOFIPS140=$(FIPS_MODULE), GOTOOLCHAIN=local)"; \
		GOTOOLCHAIN=local GOFIPS140=$(FIPS_MODULE) CGO_ENABLED=0 $(GO) build -trimpath -tags probectl_fips \
			-ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$b-fips ./cmd/$$b || exit 1; \
	done
	@echo "FIPS build OK -> $(BIN_DIR)/*-fips"

.PHONY: fips-gate
fips-gate: ## S-EE1 gate: the FIPS artifact builds AND its power-on self-test passes with the validated module active (proves the build is real, not just tagged).
	GOFIPS140=$(FIPS_MODULE) $(GO) test -tags probectl_fips -count=1 \
		-run '^TestPowerOnSelfTest$$|^TestTransparentSwap$$|^TestStatusReflectsBuild$$' ./internal/crypto/
	@echo "fips-gate: OK (validated module active, KATs pass, swap transparent)"

.PHONY: build-cross
build-cross: ## Cross-compile every binary for linux amd64 + arm64 (smoke test).
	@for arch in amd64 arm64; do \
		for b in $(BINARIES); do \
			echo ">> $$b linux/$$arch"; \
			GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -o /dev/null ./cmd/$$b || exit 1; \
		done; \
	done
	@echo "cross-compile OK (linux/amd64, linux/arm64)"

.PHONY: endpoint-build
endpoint-build: ## Cross-OS build smoke for the endpoint/DEM agent (Linux/macOS/Windows × amd64/arm64).
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			echo ">> probectl-endpoint $$os/$$arch"; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -o /dev/null ./cmd/probectl-endpoint || exit 1; \
		done; \
	done
	@echo "endpoint cross-OS build OK (linux, darwin, windows × amd64, arm64)"

.PHONY: run
run: ## Run the control-plane server locally.
	$(GO) run ./cmd/probectl-control

.PHONY: ebpf-agent
ebpf-agent: ## Build probectl-ebpf-agent WITH the live CO-RE loader (-tags ebpf; Linux + clang + bpftool + BTF; run `go get github.com/cilium/ebpf` once first).
	@command -v clang   >/dev/null 2>&1 || { echo "ebpf-agent: clang required (e.g. apt install clang llvm)"; exit 1; }  # libbpf headers are vendored under internal/ebpf/bpf/headers
	@command -v bpftool >/dev/null 2>&1 || { echo "ebpf-agent: bpftool required (e.g. apt install linux-tools-common)"; exit 1; }
	@mkdir -p $(BIN_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
	cd internal/ebpf && GO=$(GO) bash gen_bpf.sh all   # bpf2go for l4flow + sslsniff (single source of truth)
	cd internal/ebpf && $(GO) run ./gendigests .   # U-014: SHA-256 manifest of the objects, verified before kernel load
	CGO_ENABLED=0 $(GO) build -tags ebpf -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/probectl-ebpf-agent ./cmd/probectl-ebpf-agent
	@echo "built $(BIN_DIR)/probectl-ebpf-agent (eBPF loader enabled)"

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
test-python: ## Run the Python analyzer test suite with the coverage floor (U-094).
	cd analyzer && python -m pytest --cov=probectl_analyzer --cov-report=term

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
	./internal/auth/... ./internal/perf/... ./internal/ebpf/... ./internal/ebpf/l7/... ./internal/topology/... ./internal/ai/... ./internal/ai/mcp/... ./internal/ai/author/... ./internal/testspec/... ./internal/threat/... ./internal/change/... ./internal/scim/... ./internal/siem/... ./internal/notify/... ./internal/lifecycle/... ./internal/browser/... ./internal/objectstore/... ./internal/endpoint/... \
	./internal/flow/... ./internal/store/flowstore/... ./internal/device/... \
	./internal/promapi/... ./internal/cmdb/... ./internal/secrets/... ./internal/cost/... ./internal/slo/... ./internal/compliance/... ./internal/outage/... ./internal/rum/... ./internal/chaos/... ./internal/carbon/... ./internal/license/... \
	./internal/store/pathstore/... ./internal/store/tsdb/... ./internal/store/migrate/... \
	./ee/provider/... ./ee/silo/... ./ee/billing/... ./ee/whitelabel/... ./ee/tenantkeys/... ./ee/remediation/... ./internal/branding/... ./internal/cluster/... ./internal/fairness/... ./internal/govern/... ./internal/support/... ./internal/tenantcrypto/... ./internal/tenantlife/... ./internal/remediation/...

.PHONY: cover-gate
cover-gate: ## Coverage profile (integration tag, service-free) + per-package floor gate.
	$(GO) test -tags=integration -covermode=atomic -coverprofile=coverage.out -count=1 $(COVER_PKGS)
	$(GO) tool cover -func=coverage.out | tail -1
	bash scripts/check_coverage.sh coverage.out

.PHONY: openapi-gate
openapi-gate: ## OpenAPI completeness gate (S19): valid 3.1 spec + no undocumented routes.
	GO=$(GO) bash scripts/check_openapi.sh

.PHONY: migration-gate
migration-gate: ## Migration gate (S34/SCHEMA-001/003): reject destructive + locking Postgres DDL AND destructive ClickHouse DDL.
	$(GO) test -run 'TestMigrationsExpandContractCompat|TestCheckSQL' ./internal/store/migrate/...
	$(GO) test -run 'TestCheckMigrations|TestCheckMigrationsAllowsAdditive' ./internal/store/chmigrate/...
	$(GO) test -run 'TestClickHouseMigrationGate' ./internal/store/

.PHONY: helm-gate
helm-gate: ## Helm chart lint + secure-by-default hardening assertions (S35). Needs helm.
	bash scripts/check_helm_hardening.sh

.PHONY: gitops-gate
gitops-gate: ## GitOps (ArgoCD/Flux) manifest structural validation (S35). Needs python3 + PyYAML.
	bash scripts/check_gitops_manifests.sh

.PHONY: terraform-gate
terraform-gate: ## Terraform fmt + validate the probectl module (S35). Needs terraform.
	terraform -chdir=deploy/terraform fmt -recursive -check
	cd deploy/terraform/examples/kubernetes && terraform init -backend=false -input=false >/dev/null && terraform validate

.PHONY: browser-worker-check
browser-worker-check: ## Syntax-check the Playwright browser-worker (S36). Needs node. (Real-browser smoke runs in CI's Playwright container.)
	cd browser-worker && node --check worker.mjs && node --check smoke.mjs

.PHONY: editions-gate
third-party: ## SUPPLY-009: regenerate the third-party license inventory (NOTICE + docs/third-party-licenses.md) from the module graph.
	./scripts/gen_third_party.sh

third-party-gate: third-party ## SUPPLY-009 gate: regenerate the inventory and fail on drift (mirrors the proto drift gate).
	git diff --exit-code -- NOTICE docs/third-party-licenses.md || { echo "third-party license inventory is stale — commit NOTICE + docs/third-party-licenses.md"; exit 1; }

editions-gate: ## The S-T0/S-T1 editions gate: ee/ import guard (with self-test) + the core-only build/test (-tags probectl_core links ZERO ee/ code via the attach-seam twin).
	SELFTEST=1 ./scripts/check_editions_imports.sh
	$(GO) build -tags probectl_core $$($(GO) list ./... | grep -v '^github.com/imfeelingtheagi/probectl/ee')
	$(GO) test -tags probectl_core -count=1 $$($(GO) list ./... | grep -v '^github.com/imfeelingtheagi/probectl/ee')

.PHONY: scale-gate
scale-gate: ## The S48 L/XL scale gate at FULL scale (reference hardware): make scale-gate TIER=L
	PROBECTL_SCALE=1 PROBECTL_SCALE_TIER=$(or $(TIER),L) \
		$(GO) test -count=1 -v -timeout 30m -run '^TestScaleGate' ./internal/perf/

.PHONY: scale-gate-m
scale-gate-m: ## Sprint 17 nightly regression guard: the M profile (results + flow planes) at CI scale — fails on any SLO/materiality violation.
	PROBECTL_SCALE_TIER=M \
		$(GO) test -count=1 -v -timeout 15m -run '^TestScaleGate' ./internal/perf/

.PHONY: load-test-smoke
load-test-smoke: ## U-005 S-tier FULL-STACK load smoke (real Kafka + Prometheus; make compose-up first or the ci load-smoke job).
	PROBECTL_TEST_KAFKA=$(or $(PROBECTL_TEST_KAFKA),localhost:9092) \
	PROBECTL_PROM_URL=$(or $(PROBECTL_PROM_URL),http://localhost:9090) \
	PROBECTL_SCALE_TIER=S \
		$(GO) test -tags=integration -count=1 -v -timeout 12m -run '^TestFullStackLoadGate$$' ./internal/perf/

.PHONY: load-test
load-test: ## U-005 full-stack L/XL load gate on reference hardware: make load-test TIER=L (commit the result row to docs/scale-gate.md).
	PROBECTL_TEST_KAFKA=$(or $(PROBECTL_TEST_KAFKA),localhost:9092) \
	PROBECTL_PROM_URL=$(or $(PROBECTL_PROM_URL),http://localhost:9090) \
	PROBECTL_SCALE=1 PROBECTL_SCALE_TIER=$(or $(TIER),L) \
		$(GO) test -tags=integration -count=1 -v -timeout 60m -run '^TestFullStackLoadGate$$' ./internal/perf/

.PHONY: perf-smoke
perf-smoke: ## Load/perf smoke (S18a): ingest baseline (no DB) + pooled multi-tenant (needs Postgres).
	# Run without -race: this measures throughput/latency, and race instrumentation
	# distorts timing. The ingest baseline needs no services; the pooled
	# multi-tenant smoke uses PROBECTL_DATABASE_URL (skips if absent).
	$(GO) test -count=1 -v -run '^TestIngestBaseline$$' ./internal/perf/
	$(GO) test -tags=integration -count=1 -v -run '^TestPooledMultiTenant$$' ./internal/perf/

.PHONY: fuzz-smoke
fuzz-smoke: ## Run each fuzz target briefly to catch crashers (CI smoke; crasher-artifact-aware).
	GO=$(GO) bash scripts/fuzz_smoke.sh

# ---- lint / format -------------------------------------------------------
.PHONY: lint
lint: lint-go lint-python ## Run all linters (Go + Python).

# The gofmt scope excludes generated code (*/gen/*). (The throwaway spike/
# tree was removed from main in U-080 — git history preserves it.)
.PHONY: lint-go
lint-go: ## gofmt + vet + golangci-lint + crypto-import/editions/no-stringbuilt-sql/unified-TLS guards.
	@files=$$(find . -name '*.go' -not -path '*/gen/*'); \
		bad=$$(gofmt -l $$files); \
		test -z "$$bad" || { echo "gofmt needed on:"; echo "$$bad"; exit 1; }
	@for d in $(GO_MODULE_DIRS); do ( cd $$d && $(GO) vet ./... ) || exit 1; done
	golangci-lint run
	./scripts/check_crypto_imports.sh
	./scripts/check_repo_hygiene.sh SELFTEST && ./scripts/check_repo_hygiene.sh
	./scripts/check_docs_claims.sh SELFTEST && ./scripts/check_docs_claims.sh
	SELFTEST=1 ./scripts/check_editions_imports.sh
	./scripts/check_swallowed_errors.sh
	./scripts/check_http_clients.sh
	SELFTEST=1 ./scripts/check_stringbuilt_sql.sh
	SELFTEST=1 ./scripts/check_tls_configs.sh
	SELFTEST=1 ./scripts/check_enrollment_scoping.sh

.PHONY: lint-python
lint-python: ## Lint the Python analyzer (ruff + black --check).
	ruff check analyzer
	black --check analyzer

.PHONY: verify-all
verify-all: ## Sprint 25 umbrella: build + lint + race tests + scans + eBPF compile, every output tee'd to receipts/ (executed verification, not static claims). Load+attach rides the ebpf-kernel-matrix CI job.
	./scripts/verify_all.sh

.PHONY: fmt
fmt: ## Auto-format Go and Python.
	gofmt -w $$(find . -name '*.go' -not -path '*/gen/*')
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
	$(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

# ---- packaging / air-gap ------------------------------------------------
.PHONY: airgap-bundle
airgap-bundle: ## OPS-003: build the offline install bundle (images+chart+binaries+docs): make airgap-bundle VERSION=0.2.0
	VERSION=$(VERSION) ./scripts/airgap-bundle.sh

# ---- migrate -------------------------------------------------------------
.PHONY: migrate
migrate: ## Apply DB migrations against PROBECTL_DATABASE_URL.
	$(GO) run ./cmd/probectl-control migrate

# ---- security ------------------------------------------------------------
.PHONY: vuln
vuln: ## Scan Go dependencies for known vulnerabilities (govulncheck).
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

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

.PHONY: e2e
e2e: ## U-054 black-box full-stack e2e (test/e2e): compose deps + real binaries + public API + tenancy boundary. Nightly CI.
	PROBECTL_E2E=1 $(GO) test -count=1 -v -timeout 15m -run '^TestE2E$$' ./test/...

.PHONY: backup-restore-drill
backup-restore-drill: ## U-030 restore drill vs dev compose: seed -> backup -> wipe -> restore -> verify (runs in CI).
	./scripts/backup_restore_drill.sh

.PHONY: failover-drill
failover-drill: ## U-053 timed failover drill: kill the primary, promote the streaming replica, measure RTO/RPO (DESTRUCTIVE to the dev stack; runs in CI).
	./scripts/failover_drill.sh

.PHONY: compose-up
compose-up: ## Start the local dev stack (Postgres/Kafka/ClickHouse/Prometheus).
	docker compose -f $(COMPOSE_DEV) up -d --wait

.PHONY: compose-down
compose-down: ## Stop and remove the local dev stack.
	docker compose -f $(COMPOSE_DEV) down -v

# ---- housekeeping --------------------------------------------------------
.PHONY: build-devauth
build-devauth: ## Build probectl-control WITH dev auth compiled in (-tags devauth) — LOCAL EVALUATION ONLY (RED-001). Release targets never use this tag.
	$(GO) build -tags devauth -o $(BIN_DIR)/probectl-control-devauth ./cmd/probectl-control

.PHONY: tools
tools: ## Install pinned dev tools (golangci-lint) into GOPATH/bin.
	# U-060: installed as a Go module at a pinned version — every artifact is
	# checksum-verified against the Go module sum database (no curl-pipe from
	# a floating HEAD install script).
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: clean
clean: ## Remove build output.
	rm -rf $(BIN_DIR) dist coverage.out

.PHONY: ci
ci: lint test test-isolation ## Run the core CI gates locally.
