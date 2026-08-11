// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"fmt"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mockRe    = regexp.MustCompile(`(^|[/_.-])mocks?([/_.-]|$)`)
	tagRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// Diagnostic is one stable, machine-readable reason a signed receipt cannot
// promote a capability.
type Diagnostic struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Problem string `json:"problem"`
}

// Lint applies the delivery-not-tests policy. Cryptographic validity is
// deliberately separate: call Verify first. FAILED receipts return the single
// non-promotable status diagnostic but remain valid signed evidence.
func Lint(receipt Receipt) []Diagnostic {
	if receipt.Status == OutcomeFailed {
		out := []Diagnostic{{Code: "status-failed", Field: "status", Problem: "signed receipt records a FAILED audit and cannot promote the item"}}
		fixture := receipt.EvidenceSources.Fixture != nil && *receipt.EvidenceSources.Fixture
		mock := receipt.EvidenceSources.Mock != nil && *receipt.EvidenceSources.Mock
		testdata := receipt.EvidenceSources.TestData != nil && *receipt.EvidenceSources.TestData
		out = addDiagnosticIf(out, fixture || mock || testdata || containsForbiddenEvidenceMarker(receipt),
			"fixture-only", "evidence_sources", "FAILED evidence contains fixture, mock, testdata, or another test-only marker")
		sort.SliceStable(out, func(i, j int) bool { return out[i].Code < out[j].Code })
		return out
	}
	if receipt.HumanPath.PathClass == HumanPathClassGovernedReview {
		return lintGovernedReview(receipt)
	}
	artifactKinds := indexArtifactKinds(receipt.Artifacts)
	var out []Diagnostic
	out = append(out, lintSourceAndBuild(receipt)...)
	out = append(out, lintHumanObservations(receipt, artifactKinds)...)
	out = append(out, lintReachability(receipt, artifactKinds)...)
	out = append(out, lintStoreIsolation(receipt, artifactKinds)...)
	out = append(out, lintTrustAndSources(receipt, artifactKinds)...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Problem < out[j].Problem
	})
	return out
}

func lintGovernedReview(receipt Receipt) []Diagnostic {
	kinds := indexArtifactKinds(receipt.Artifacts)
	var out []Diagnostic
	out = addDiagnosticIf(out, !fullSHARe.MatchString(receipt.Source.GitSHA) || !fullSHARe.MatchString(receipt.Source.TreeSHA),
		"exact-sha-required", "source", "source git_sha and tree_sha must be full lowercase 40-character SHAs")
	out = addDiagnosticIf(out, receipt.Source.Dirty == nil || *receipt.Source.Dirty,
		"dirty-source", "source.dirty", "VERIFIED evidence requires an explicit clean source checkout")
	out = addDiagnosticIf(out, invalidIndependentAuditor(receipt.Auditor),
		"independent-auditor-required", "auditor", "auditor identity must be explicit and independently authorized by the out-of-band trusted signer")
	out = addDiagnosticIf(out, receipt.HarnessScope.Mode != HarnessModeGovernedReview ||
		receipt.HarnessScope.BrowserAuthMode != HarnessAuthNotApplicable || receipt.HarnessScope.CLIAuthMode != HarnessAuthNotApplicable ||
		receipt.HarnessScope.ProviderCompatibilityValidated == nil || *receipt.HarnessScope.ProviderCompatibilityValidated ||
		receipt.HarnessScope.CapabilityDriver.Kind != HarnessDriverNotApplicable ||
		receipt.HarnessScope.BrowserDriver.Kind != HarnessDriverNotApplicable ||
		invalidHarnessDriver(receipt.HarnessScope.CapabilityDriver) || invalidHarnessDriver(receipt.HarnessScope.BrowserDriver),
		"harness-scope-invalid", "harness_scope", "governed review must use governed_review/not_applicable scope and make no provider or runtime-driver claim")
	out = addDiagnosticIf(out, strings.TrimSpace(receipt.HumanPath.ID) == "" ||
		receipt.HumanPath.Coverage != HumanPathCoverageGovernedReview ||
		receipt.HumanPath.Reproduced == nil || !*receipt.HumanPath.Reproduced || strings.TrimSpace(receipt.HumanPath.Summary) == "",
		"governed-review-invalid", "human_path", "governed review must identify one completed, bounded artifact-review workflow")
	out = addDiagnosticIf(out, invalidGovernedReviewEvidence(receipt.GovernedReview, receipt.Item, receipt.CapabilityID, kinds),
		"governed-review-invalid", "governed_review", "review must be a passed, source-bound artifact/methodology/legal/release review with nonempty checks")
	out = addDiagnosticIf(out, hasExecutableEvidence(receipt),
		"review-runtime-overclaim", "human_path.path_class", "governed review profile must not carry executable build/API/CLI/UI/store/TLS claims")
	out = addDiagnosticIf(out, invalidNegativeControlDeclarations(receipt.Artifacts),
		"negative-control-invalid", "artifacts", "VERIFIED receipt must declare one strict linter output, signed FAILED envelope, and planted fixture artifact")
	fixture, mock, testdata := evidenceFlagsInvalid(receipt)
	out = addDiagnosticIf(out, fixture || mock || testdata || containsForbiddenEvidenceMarker(receipt),
		"fixture-only", "evidence_sources", "VERIFIED review evidence cannot depend on fixtures, mocks, testdata, or test-only markers")
	out = addDiagnosticIf(out, len(receipt.FailureReasons) != 0,
		"verified-has-failures", "failure_reasons", "VERIFIED receipt cannot carry failure reasons")
	return sortAndDedupeDiagnostics(out)
}

func invalidGovernedReviewEvidence(review GovernedReviewEvidence, item, capabilityID string, kinds map[string]ArtifactKind) bool {
	if kinds[review.Artifact] != ArtifactGovernedReview || !validGovernedReviewKind(review.Kind) ||
		!validSourceRelativePath(review.AuthorityPath) || strings.TrimSpace(review.AuthorityAnchor) == "" ||
		!strings.Contains(review.AuthorityAnchor, item) || !strings.Contains(review.AuthorityAnchor, capabilityID) ||
		!validSourceRelativePath(review.MethodologyPath) || len(review.Subjects) == 0 || len(review.Subjects) > 64 ||
		len(review.Checks) == 0 || len(review.Checks) > 128 || review.Conclusion != GovernedReviewConclusionPass {
		return true
	}
	seenSubjects := make(map[string]bool, len(review.Subjects))
	for _, subject := range review.Subjects {
		if !validSourceRelativePath(subject.Path) || !digestRe.MatchString(subject.SHA256) || !fullSHARe.MatchString(subject.GitBlobSHA) || seenSubjects[subject.Path] {
			return true
		}
		seenSubjects[subject.Path] = true
	}
	if !seenSubjects[review.AuthorityPath] || !seenSubjects[review.MethodologyPath] {
		return true
	}
	seenChecks := make(map[string]bool, len(review.Checks))
	for _, check := range review.Checks {
		if strings.TrimSpace(check.ID) == "" || check.Outcome != GovernedReviewCheckPass || strings.TrimSpace(check.Detail) == "" || seenChecks[check.ID] {
			return true
		}
		seenChecks[check.ID] = true
	}
	return false
}

func validGovernedReviewKind(kind string) bool {
	switch kind {
	case GovernedReviewKindArtifact, GovernedReviewKindMethodology, GovernedReviewKindLegal, GovernedReviewKindRelease:
		return true
	default:
		return false
	}
}

func hasExecutableEvidence(receipt Receipt) bool {
	return !reflect.DeepEqual(receipt.Build, BuildEvidence{}) || !reflect.DeepEqual(receipt.CLI, CLIEvidence{}) ||
		!reflect.DeepEqual(receipt.UI, UIEvidence{}) || !reflect.DeepEqual(receipt.BrowserNetwork, BrowserNetworkEvidence{}) ||
		!reflect.DeepEqual(receipt.Reachability, ReachabilityEvidence{}) || !reflect.DeepEqual(receipt.Activation, ActivationEvidence{}) ||
		!reflect.DeepEqual(receipt.Stores, StoreEvidence{}) || !reflect.DeepEqual(receipt.TLS, TLSEvidence{})
}

func lintSourceAndBuild(receipt Receipt) []Diagnostic {
	var out []Diagnostic
	out = addDiagnosticIf(out, !fullSHARe.MatchString(receipt.Source.GitSHA) || !fullSHARe.MatchString(receipt.Source.TreeSHA),
		"exact-sha-required", "source", "source git_sha and tree_sha must be full lowercase 40-character SHAs")
	out = addDiagnosticIf(out, receipt.Source.Dirty == nil || *receipt.Source.Dirty,
		"dirty-source", "source.dirty", "VERIFIED evidence requires an explicit clean source checkout")
	out = addDiagnosticIf(out, receipt.Build.ControlCommit != receipt.Source.GitSHA || receipt.Build.CLICommit != receipt.Source.GitSHA,
		"release-sha-mismatch", "build", "control and CLI release commits must both equal source.git_sha")
	out = addDiagnosticIf(out, !validImageID(receipt.Build.ControlImageID) || !digestRe.MatchString(receipt.Build.CLISHA256),
		"release-binary-unverified", "build", "release control image id and CLI sha256 are required")
	out = addDiagnosticIf(out, receipt.Build.DevAuth == nil || *receipt.Build.DevAuth,
		"devauth-build", "build.dev_auth", "release evidence must explicitly prove dev-auth was not compiled")
	out = addDiagnosticIf(out, receipt.Build.PlaceholderUI == nil || *receipt.Build.PlaceholderUI,
		"placeholder-ui", "build.placeholder_ui", "release evidence must explicitly prove the embedded UI is not the placeholder")
	out = addDiagnosticIf(out, invalidHarnessScope(receipt),
		"harness-scope-invalid", "harness_scope", "harness mode, real auth mode, provider claim, activation tier, and driver identities must form one supported governed path")
	out = addDiagnosticIf(out, receipt.HarnessScope.Mode == HarnessModeProviderPlane,
		"provider-mode-reserved", "harness_scope.mode", "provider_plane is typed but non-promotable until mounted license bytes, live license response, baked-key acceptance, provider boundary, and provider-session artifacts are independently cross-bound")
	return out
}

func lintHumanObservations(receipt Receipt, kinds map[string]ArtifactKind) []Diagnostic {
	var out []Diagnostic
	out = addDiagnosticIf(out, invalidIndependentAuditor(receipt.Auditor),
		"independent-auditor-required", "auditor", "auditor identity must be explicit and independent from the implementation owner")
	out = addDiagnosticIf(out, strings.TrimSpace(receipt.HumanPath.ID) == "" ||
		receipt.HumanPath.PathClass != HumanPathClassExecutableEndUser ||
		receipt.HumanPath.Coverage != HumanPathCoverageGovernedPath ||
		receipt.HumanPath.Reproduced == nil || !*receipt.HumanPath.Reproduced || strings.TrimSpace(receipt.HumanPath.Summary) == "",
		"human-path-not-reproduced", "human_path", "VERIFIED evidence must identify one reproduced governed executable end-user path; it never claims exhaustive dynamic surface coverage")
	out = addDiagnosticIf(out, len(receipt.CLI.Commands) == 0 || !allCommandsExecutable(receipt.CLI.Commands) || kinds[receipt.CLI.Transcript] != ArtifactCLITranscript,
		"cli-unobserved", "cli", "at least one probectl command and its hashed CLI transcript are required")
	out = addDiagnosticIf(out, invalidUIEvidence(receipt.UI, kinds),
		"ui-unobserved", "ui", "at least one product route and hashed rendered-UI screenshot are required")
	out = addDiagnosticIf(out, invalidBrowserEvidence(receipt, kinds),
		"browser-network-unobserved", "browser_network", "a non-intercepted live HTTPS browser request to the real API and its network artifact are required")
	out = addDiagnosticIf(out, !hasArtifactKind(receipt.Artifacts, ArtifactStackInventory),
		"stack-inventory-missing", "artifacts", "a hashed real-service stack inventory is required")
	out = addDiagnosticIf(out, invalidNegativeControlDeclarations(receipt.Artifacts),
		"negative-control-invalid", "artifacts", "VERIFIED receipt must declare one strict linter output, signed FAILED envelope, and planted fixture artifact")
	return out
}

func invalidNegativeControlDeclarations(artifacts []Artifact) bool {
	counts := map[ArtifactKind]int{}
	for _, artifact := range artifacts {
		counts[artifact.Kind]++
	}
	return counts[ArtifactLinterOutput] != 1 || counts[ArtifactNegativeReceipt] != 1 || counts[ArtifactNegativeFixture] != 1
}

func lintReachability(receipt Receipt, kinds map[string]ArtifactKind) []Diagnostic {
	var out []Diagnostic
	out = addDiagnosticIf(out, invalidBinaryReachability(receipt.Reachability, kinds),
		"binary-unreachable", "reachability", "a hashed static report must prove a named cmd/ entrypoint is reachable in the default non-test release build")
	out = addDiagnosticIf(out, !validAPIReachability(receipt.Reachability.API),
		"api-unreachable", "reachability.api", "an OpenAPI method/path is required; operationId is matched only when the source specification declares one")
	out = addDiagnosticIf(out, !containsExact(receipt.CLI.Commands, receipt.Reachability.CLIOperation),
		"cli-unreachable", "reachability.cli_operation", "the named CLI operation must appear in the real CLI transcript command list")
	out = addDiagnosticIf(out, !validUIRoute(receipt.Reachability.UIRoute) || !containsExact(receipt.UI.Routes, receipt.Reachability.UIRoute),
		"ui-unreachable", "reachability.ui_route", "the named UI route must appear in the rendered-browser route list")
	out = addDiagnosticIf(out, !validDocsPath(receipt.Reachability.DocsPath),
		"docs-unreachable", "reachability.docs_path", "a canonical in-repository Markdown documentation path is required")
	out = addDiagnosticIf(out, invalidActivationProof(receipt.Activation, kinds),
		"activation-unproven", "activation", "a hashed activation proof must record active runtime, default state, docs, license state, and exact build tags")
	out = addDiagnosticIf(out, defaultOffUnactivated(receipt),
		"default-off-unactivated", "activation", "a default-off feature must be activated through exact CLI and UI paths observed in this audit and backed by documentation")
	return out
}

func lintStoreIsolation(receipt Receipt, kinds map[string]ArtifactKind) []Diagnostic {
	var out []Diagnostic
	out = addDiagnosticIf(out, kinds[receipt.Stores.Artifact] != ArtifactStoreProbes,
		"store-probes-missing", "stores.artifact", "a hashed real-store proof artifact is required")
	if receipt.HarnessScope.Mode == HarnessModeProviderPlane {
		out = addDiagnosticIf(out, strings.TrimSpace(receipt.Stores.ProductPipelineArtifact) != "",
			"store-proof-overclaim", "stores.product_pipeline_artifact", "provider-boundary receipt must not claim the tenant OTLP product pipeline")
		out = addDiagnosticIf(out, invalidProviderBoundaryProbe(receipt.Stores.ProviderBoundary),
			"provider-boundary-unproven", "stores.provider_boundary", "provider role must prove allowed lifecycle/aggregate metadata, denied raw telemetry across applicable stores, no implicit tenant read, and separate provider audit")
		out = addDiagnosticIf(out, !reflect.DeepEqual(receipt.Stores.Postgres, PostgresIsolationProbe{}) ||
			!reflect.DeepEqual(receipt.Stores.ClickHouse, ClickHouseIsolationProbe{}) ||
			!reflect.DeepEqual(receipt.Stores.Kafka, KafkaIntegrityProbe{}) ||
			!reflect.DeepEqual(receipt.Stores.Prometheus, PrometheusIntegrityProbe{}),
			"store-proof-overclaim", "stores", "provider receipt must not present tenant-plane RLS/tag probes as provider-boundary proof")
		return out
	}
	out = addDiagnosticIf(out, kinds[receipt.Stores.ProductPipelineArtifact] != ArtifactProductPipeline,
		"product-pipeline-missing", "stores.product_pipeline_artifact", "tenant promotion requires a hashed OTLP -> Kafka -> Prometheus/ClickHouse release-product round-trip artifact")
	out = addDiagnosticIf(out, !reflect.DeepEqual(receipt.Stores.ProviderBoundary, ProviderBoundaryProbe{}),
		"store-proof-overclaim", "stores.provider_boundary", "tenant receipt must not claim provider-boundary validation")
	out = addDiagnosticIf(out, receipt.Stores.Postgres.ProofKind != PostgresProofKind,
		"store-proof-kind-invalid", "stores.postgres.proof_kind", "Postgres must use the bidirectional RLS/query-isolation proof kind")
	out = addDiagnosticIf(out, invalidPostgresProbe(receipt.Stores.Postgres),
		"store-probe-failed", "stores.postgres", "Postgres must non-vacuously prove storage/query-layer RLS in both tenant directions")
	out = addDiagnosticIf(out, receipt.Stores.ClickHouse.ProofKind != ClickHouseProofKind,
		"store-proof-kind-invalid", "stores.clickhouse.proof_kind", "ClickHouse must use the actual product-table setting-scoped reader-isolation proof kind")
	out = addDiagnosticIf(out, invalidClickHouseProbe(receipt.Stores.ClickHouse),
		"store-probe-failed", "stores.clickhouse", "ClickHouse must prove release-control roundtrip plus non-vacuous bidirectional and unset-fail-closed row-policy isolation on default.probectl_otel_spans as the release reader")
	out = addDiagnosticIf(out, receipt.Stores.Kafka.ProofKind != KafkaProofKind,
		"store-proof-kind-invalid", "stores.kafka.proof_kind", "Kafka must use the authenticated SASL_SSL tenant-tag-integrity proof kind")
	out = addDiagnosticIf(out, receipt.Stores.Kafka.ReaderIsolationClaimed == nil || *receipt.Stores.Kafka.ReaderIsolationClaimed,
		"store-proof-overclaim", "stores.kafka.reader_isolation_claimed", "Kafka evidence must explicitly avoid claiming tenant-reader isolation")
	out = addDiagnosticIf(out, invalidKafkaProbe(receipt.Stores.Kafka),
		"store-probe-failed", "stores.kafka", "Kafka must prove control broker configuration/readiness plus an authenticated SASL_SSL manual tenant-tag-integrity probe; product-emitted observations remain an explicit optional claim")
	out = addDiagnosticIf(out, receipt.Stores.Prometheus.ProofKind != PrometheusProofKind,
		"store-proof-kind-invalid", "stores.prometheus.proof_kind", "Prometheus must use the authenticated TLS tenant-label-integrity proof kind")
	out = addDiagnosticIf(out, receipt.Stores.Prometheus.IsolationClaimed == nil || *receipt.Stores.Prometheus.IsolationClaimed,
		"store-proof-overclaim", "stores.prometheus.isolation_claimed", "Prometheus evidence must explicitly avoid claiming query isolation")
	out = addDiagnosticIf(out, invalidPrometheusProbe(receipt.Stores.Prometheus),
		"store-probe-failed", "stores.prometheus", "Prometheus must prove release-control product-path configuration/roundtrip plus an unfiltered direct authenticated TLS tenant-label-integrity query")
	return out
}

func lintTrustAndSources(receipt Receipt, kinds map[string]ArtifactKind) []Diagnostic {
	var out []Diagnostic
	out = addDiagnosticIf(out, invalidTLSEvidence(receipt, kinds),
		"tls-trust-unverified", "tls", "TLS proof must fail without the CA, succeed with trust, use no bypass, and use a CA lifetime no longer than six hours")
	for _, listener := range requiredTLSListeners {
		probe, ok := receipt.TLS.Listeners[listener]
		out = addDiagnosticIf(out, !ok, "tls-listener-missing", "tls.listeners."+listener,
			fmt.Sprintf("required listener %s has no signed TLS evidence", listener))
		out = addDiagnosticIf(out, ok && invalidTLSListenerProbe(listener, probe), "tls-listener-failed", "tls.listeners."+listener,
			tlsListenerFailureProblem(listener))
	}
	fixture, mock, testdata := evidenceFlagsInvalid(receipt)
	out = addDiagnosticIf(out, fixture || mock || testdata || containsForbiddenEvidenceMarker(receipt),
		"fixture-only", "evidence_sources", "VERIFIED evidence cannot depend on fixtures, mocks, testdata, httptest, browser route fulfillment, or PROBECTL_WEB_FIXTURES")
	out = addDiagnosticIf(out, len(receipt.FailureReasons) != 0,
		"verified-has-failures", "failure_reasons", "VERIFIED receipt cannot carry failure reasons")
	return out
}

func addDiagnosticIf(out []Diagnostic, condition bool, code, field, problem string) []Diagnostic {
	if condition {
		return append(out, Diagnostic{Code: code, Field: field, Problem: problem})
	}
	return out
}

func indexArtifactKinds(artifacts []Artifact) map[string]ArtifactKind {
	kinds := make(map[string]ArtifactKind, len(artifacts))
	for _, artifact := range artifacts {
		kinds[artifact.Path] = artifact.Kind
	}
	return kinds
}

func invalidIndependentAuditor(auditor AuditorEvidence) bool {
	return auditor.IndependentFromImplementation == nil || !*auditor.IndependentFromImplementation ||
		strings.TrimSpace(auditor.Agent) == "" || strings.TrimSpace(auditor.ImplementationOwner) == "" ||
		strings.TrimSpace(auditor.Agent) == strings.TrimSpace(auditor.ImplementationOwner)
}

func invalidHarnessScope(receipt Receipt) bool {
	scope := receipt.HarnessScope
	if scope.ProviderCompatibilityValidated == nil || invalidHarnessDriver(scope.CapabilityDriver) || invalidHarnessDriver(scope.BrowserDriver) {
		return true
	}
	switch scope.Mode {
	case HarnessModeTenantPlane:
		return scope.BrowserAuthMode != HarnessAuthTenantOIDC || scope.CLIAuthMode != HarnessAuthTenantMCPBearer || *scope.ProviderCompatibilityValidated ||
			!validTenantHarnessDriver(receipt.CapabilityID, "capability", scope.CapabilityDriver) ||
			!validTenantHarnessDriver(receipt.CapabilityID, "browser", scope.BrowserDriver)
	case HarnessModeProviderPlane:
		return scope.BrowserAuthMode != HarnessAuthProviderSession || scope.CLIAuthMode != HarnessAuthProviderSessionBearer || !*scope.ProviderCompatibilityValidated ||
			scope.CapabilityDriver.Kind != HarnessDriverSourceBound || scope.BrowserDriver.Kind != HarnessDriverSourceBound ||
			!validProviderLicenseActivation(receipt.Activation)
	default:
		return true
	}
}

func validTenantHarnessDriver(capabilityID, role string, driver HarnessDriverEvidence) bool {
	if driver.Kind == HarnessDriverSourceBound {
		return !invalidHarnessDriver(driver)
	}
	if driver.Kind != HarnessDriverBuiltin || capabilityID != "F50" {
		return false
	}
	if role == "capability" {
		return driver.RuntimePath == "scripts/run_completeness_audit.sh#run_f50_capability"
	}
	return role == "browser" && driver.RuntimePath == "scripts/completeness_audit_browser.mjs"
}

func invalidHarnessDriver(driver HarnessDriverEvidence) bool {
	if driver.Kind == HarnessDriverNotApplicable {
		return driver.RuntimePath != "" || driver.SourcePath != "" || driver.SHA256 != "" || driver.GitBlobSHA != ""
	}
	if strings.TrimSpace(driver.RuntimePath) == "" {
		return true
	}
	switch driver.Kind {
	case HarnessDriverBuiltin:
		return driver.SourcePath != "" || driver.SHA256 != "" || driver.GitBlobSHA != ""
	case HarnessDriverSourceBound:
		return !validSourceRelativePath(driver.SourcePath) || !digestRe.MatchString(driver.SHA256) || !fullSHARe.MatchString(driver.GitBlobSHA)
	default:
		return true
	}
}

func validSourceRelativePath(value string) bool {
	value = strings.TrimSpace(value)
	clean := path.Clean(value)
	return value != "" && clean == value && clean != "." && clean != ".." &&
		!strings.HasPrefix(clean, "../") && !path.IsAbs(clean) && !strings.Contains(clean, "\\") && !strings.Contains(clean, ":")
}

func invalidUIEvidence(ui UIEvidence, kinds map[string]ArtifactKind) bool {
	return len(ui.Routes) == 0 || !allRoutesAbsolute(ui.Routes) || len(ui.Screenshots) == 0 ||
		!allArtifactsOfKind(ui.Screenshots, kinds, ArtifactUIScreenshot)
}

func invalidBrowserEvidence(receipt Receipt, kinds map[string]ArtifactKind) bool {
	browser := receipt.BrowserNetwork
	return kinds[browser.Artifact] != ArtifactBrowserNetwork || browser.LiveHTTPS == nil || !*browser.LiveHTTPS ||
		browser.RequestInterception == nil || *browser.RequestInterception || !hasLiveAPIRequest(browser.Requests, receipt.HarnessScope.Mode)
}

func invalidBinaryReachability(reach ReachabilityEvidence, kinds map[string]ArtifactKind) bool {
	return kinds[reach.Artifact] != ArtifactReachability || !validBinaryEntrypoint(reach.BinaryEntrypoint) ||
		!validDefaultBuildCommand(reach.DefaultBuildCommand) || reach.DefaultBuildReachable == nil || !*reach.DefaultBuildReachable
}

func invalidActivationProof(activation ActivationEvidence, kinds map[string]ArtifactKind) bool {
	return kinds[activation.Artifact] != ArtifactActivation || activation.RuntimeActive == nil || !*activation.RuntimeActive ||
		activation.EnabledByDefault == nil || !validDocsPath(activation.DocsPath) ||
		!validLicenseActivation(activation) || !validBuildTags(activation.BuildTags)
}

func defaultOffUnactivated(receipt Receipt) bool {
	activation := receipt.Activation
	return activation.EnabledByDefault != nil && !*activation.EnabledByDefault &&
		(!containsExact(receipt.CLI.Commands, activation.EnableCLICommand) ||
			!containsExact(receipt.UI.Routes, activation.EnableUIRoute) || !validDocsPath(activation.DocsPath))
}

func invalidPostgresProbe(probe PostgresIsolationProbe) bool {
	return probe.ProofKind != PostgresProofKind || invalidDirectionalCounts(
		probe.TenantA, probe.TenantB,
		probe.SeededTenantARows, probe.SeededTenantBRows,
		probe.TenantAOwnVisibleRows, probe.TenantBOwnVisibleRows,
		probe.TenantAToBVisibleRows, probe.TenantBToAVisibleRows,
	) || strings.TrimSpace(probe.Detail) == ""
}

func invalidClickHouseProbe(probe ClickHouseIsolationProbe) bool {
	return probe.ProofKind != ClickHouseProofKind || probe.ProductPathConfigured == nil || !*probe.ProductPathConfigured ||
		probe.ControlRoundTripObserved == nil || !*probe.ControlRoundTripObserved || probe.Database != "default" ||
		probe.Table != "probectl_otel_spans" || probe.ReaderUser != "probectl" || probe.TenantSetting != "SQL_probectl_tenant" ||
		probe.ReaderPolicyObserved == nil || !*probe.ReaderPolicyObserved || invalidDirectionalCounts(
		probe.TenantA, probe.TenantB,
		probe.SeededTenantARows, probe.SeededTenantBRows,
		probe.TenantAOwnVisibleRows, probe.TenantBOwnVisibleRows,
		probe.TenantAToBVisibleRows, probe.TenantBToAVisibleRows,
	) || probe.UnsetVisibleRows == nil || *probe.UnsetVisibleRows != 0 || strings.TrimSpace(probe.Detail) == ""
}

func invalidDirectionalCounts(tenantA, tenantB string, seededA, seededB, ownA, ownB, aToB, bToA *int64) bool {
	return strings.TrimSpace(tenantA) == "" || strings.TrimSpace(tenantB) == "" || tenantA == tenantB ||
		seededA == nil || *seededA <= 0 || seededB == nil || *seededB <= 0 ||
		ownA == nil || *ownA <= 0 || ownB == nil || *ownB <= 0 ||
		aToB == nil || *aToB != 0 || bToA == nil || *bToA != 0
}

func invalidKafkaProbe(probe KafkaIntegrityProbe) bool {
	return probe.ProofKind != KafkaProofKind || probe.SecurityProtocol != "SASL_SSL" ||
		strings.TrimSpace(probe.AuthenticationMechanism) == "" ||
		probe.ControlConfiguredForBroker == nil || !*probe.ControlConfiguredForBroker ||
		probe.ControlConnectivityProven == nil || !*probe.ControlConnectivityProven ||
		probe.AuthenticatedManualTagProbe == nil || !*probe.AuthenticatedManualTagProbe ||
		probe.TLSVerified == nil || !*probe.TLSVerified || probe.SASLAuthenticated == nil || !*probe.SASLAuthenticated ||
		strings.TrimSpace(probe.TenantA) == "" || strings.TrimSpace(probe.TenantB) == "" || probe.TenantA == probe.TenantB ||
		probe.ObservedTenantAMessages == nil || *probe.ObservedTenantAMessages <= 0 ||
		probe.ObservedTenantBMessages == nil || *probe.ObservedTenantBMessages <= 0 ||
		probe.MissingTenantTagMessages == nil || *probe.MissingTenantTagMessages != 0 ||
		probe.MismatchedTenantTagMessages == nil || *probe.MismatchedTenantTagMessages != 0 ||
		invalidProductMessageClaim(probe) ||
		probe.ReaderIsolationClaimed == nil || *probe.ReaderIsolationClaimed || strings.TrimSpace(probe.Detail) == ""
}

func invalidProductMessageClaim(probe KafkaIntegrityProbe) bool {
	if probe.ProductMessagesObserved == nil || probe.ObservedProductMessages == nil || *probe.ObservedProductMessages < 2 {
		return true
	}
	return !*probe.ProductMessagesObserved
}

func invalidPrometheusProbe(probe PrometheusIntegrityProbe) bool {
	return probe.ProofKind != PrometheusProofKind || probe.ProductPathConfigured == nil || !*probe.ProductPathConfigured ||
		probe.ControlRoundTripObserved == nil || !*probe.ControlRoundTripObserved || probe.DirectQuery == nil || !*probe.DirectQuery ||
		probe.UnfilteredSeriesQuery == nil || !*probe.UnfilteredSeriesQuery ||
		probe.TLSVerified == nil || !*probe.TLSVerified || probe.Authenticated == nil || !*probe.Authenticated ||
		strings.TrimSpace(probe.TenantA) == "" || strings.TrimSpace(probe.TenantB) == "" || probe.TenantA == probe.TenantB ||
		probe.ObservedTenantASeries == nil || *probe.ObservedTenantASeries <= 0 ||
		probe.ObservedTenantBSeries == nil || *probe.ObservedTenantBSeries <= 0 ||
		probe.TotalObservedSeries == nil || probe.ExpectedTenantLabeledSeries == nil ||
		*probe.TotalObservedSeries != *probe.ObservedTenantASeries+*probe.ObservedTenantBSeries ||
		*probe.ExpectedTenantLabeledSeries != *probe.TotalObservedSeries ||
		probe.MissingTenantLabelSeries == nil || *probe.MissingTenantLabelSeries != 0 ||
		probe.MismatchedTenantLabelSeries == nil || *probe.MismatchedTenantLabelSeries != 0 ||
		probe.IsolationClaimed == nil || *probe.IsolationClaimed || strings.TrimSpace(probe.Detail) == ""
}

func invalidProviderBoundaryProbe(probe ProviderBoundaryProbe) bool {
	return probe.ProofKind != ProviderBoundaryProofKind || strings.TrimSpace(probe.ProviderActor) == "" ||
		strings.TrimSpace(probe.TenantA) == "" || strings.TrimSpace(probe.TenantB) == "" || probe.TenantA == probe.TenantB ||
		probe.LifecycleMetadataRows == nil || *probe.LifecycleMetadataRows <= 0 ||
		probe.AggregateMetadataRows == nil || *probe.AggregateMetadataRows <= 0 ||
		probe.PostgresRawTelemetrySeededRows == nil || *probe.PostgresRawTelemetrySeededRows <= 0 ||
		probe.PostgresRawTelemetryAccessDenied == nil || !*probe.PostgresRawTelemetryAccessDenied ||
		probe.ClickHouseRawTelemetrySeededRows == nil || *probe.ClickHouseRawTelemetrySeededRows <= 0 ||
		probe.ClickHouseRawTelemetryAccessDenied == nil || !*probe.ClickHouseRawTelemetryAccessDenied ||
		probe.KafkaTenantPayloadSeededMessages == nil || *probe.KafkaTenantPayloadSeededMessages <= 0 ||
		probe.KafkaTenantPayloadAccessDenied == nil || !*probe.KafkaTenantPayloadAccessDenied ||
		probe.PrometheusRawTelemetrySeededSeries == nil || *probe.PrometheusRawTelemetrySeededSeries <= 0 ||
		probe.PrometheusRawTelemetryAccessDenied == nil || !*probe.PrometheusRawTelemetryAccessDenied ||
		probe.ImplicitTenantReadGranted == nil || *probe.ImplicitTenantReadGranted ||
		probe.ProviderAuditEventsObserved == nil || *probe.ProviderAuditEventsObserved <= 0 ||
		probe.TenantAuditEventsFromProviderAction == nil || *probe.TenantAuditEventsFromProviderAction != 0 ||
		strings.TrimSpace(probe.Detail) == ""
}

func invalidTLSEvidence(receipt Receipt, kinds map[string]ArtifactKind) bool {
	tls := receipt.TLS
	return kinds[tls.Artifact] != ArtifactTLSTrust || !digestRe.MatchString(tls.CAFingerprint) ||
		kinds[tls.CertificateManifest] != ArtifactCertManifest || kinds[tls.CACertificate] != ArtifactPublicCert ||
		len(tls.Listeners) != len(requiredTLSListeners) ||
		len(tls.ServiceCertificates) != len(requiredServiceInventories) || hasInvalidServiceCertificateKinds(tls.ServiceCertificates, kinds) ||
		tls.BrowserRejectedWithoutCA == nil || !*tls.BrowserRejectedWithoutCA ||
		tls.BrowserTrustedWithCA == nil || !*tls.BrowserTrustedWithCA ||
		invalidBrowserPretrustFailure(tls.BrowserPretrustFailure) ||
		tls.IgnoreHTTPSErrors == nil || *tls.IgnoreHTTPSErrors ||
		!validShortLivedCA(receipt)
}

func invalidBrowserPretrustFailure(failure BrowserPretrustFailure) bool {
	u, err := url.Parse(failure.URL)
	message := strings.ToLower(strings.TrimSpace(failure.SanitizedMessage))
	return failure.Browser != "webkit" || err != nil || u.Scheme != "https" || u.Host == "" ||
		failure.ErrorClass != "unknown_authority" || failure.Rejected == nil || !*failure.Rejected ||
		len(message) < 8 || len(message) > 512 || strings.Contains(message, "\n") ||
		(!strings.Contains(message, "certificate") && !strings.Contains(message, "ssl") && !strings.Contains(message, "tls")) ||
		strings.Contains(message, "token") || strings.Contains(message, "authorization")
}

func hasInvalidServiceCertificateKinds(paths map[string]string, kinds map[string]ArtifactKind) bool {
	for _, service := range requiredServiceInventories {
		if kinds[paths[service]] != ArtifactPublicCert {
			return true
		}
	}
	return false
}

func invalidTLSListenerProbe(listener string, probe TLSListenerProbe) bool {
	if !digestRe.MatchString(probe.PeerCertificateSHA256) || probe.TrustedTLS == nil || !*probe.TrustedTLS ||
		probe.PlaintextRejected == nil || !*probe.PlaintextRejected {
		return true
	}
	wantCertificateService := listener
	if listener == "otlp_http" {
		wantCertificateService = "control"
	}
	if probe.CertificateService != wantCertificateService {
		return true
	}
	if listener == "dex" {
		return probe.AuthModel != TLSAuthModelPublicOIDC || probe.UnauthenticatedRejected != nil ||
			probe.InvalidAuthenticationRejected != nil ||
			probe.MetadataPublic == nil || !*probe.MetadataPublic ||
			probe.MalformedAuthorizationRejected == nil || !*probe.MalformedAuthorizationRejected ||
			probe.RealCredentialedLoginSucceeded == nil || !*probe.RealCredentialedLoginSucceeded
	}
	return probe.AuthModel != TLSAuthModelProtected ||
		probe.UnauthenticatedRejected == nil || !*probe.UnauthenticatedRejected ||
		(listener == "otlp_http" && (probe.InvalidAuthenticationRejected == nil || !*probe.InvalidAuthenticationRejected)) ||
		(listener != "otlp_http" && probe.InvalidAuthenticationRejected != nil) ||
		probe.MetadataPublic != nil || probe.MalformedAuthorizationRejected != nil || probe.RealCredentialedLoginSucceeded != nil
}

func tlsListenerFailureProblem(listener string) string {
	if listener == "dex" {
		return "dex must bind the observed peer leaf fingerprint, accept trusted TLS, reject plaintext, expose public OIDC metadata, reject malformed authorization requests, and complete a real credentialed browser login"
	}
	return fmt.Sprintf("%s must bind the observed peer leaf fingerprint and accept trusted TLS while rejecting plaintext and unauthenticated access", listener)
}

func validImageID(value string) bool {
	value = strings.TrimSpace(value)
	return digestRe.MatchString(value) ||
		(strings.HasPrefix(value, "docker-image://sha256:") && digestRe.MatchString(strings.TrimPrefix(value, "docker-image://")))
}

func allCommandsExecutable(commands []string) bool {
	for _, command := range commands {
		if !strings.HasPrefix(strings.TrimSpace(command), "probectl ") {
			return false
		}
	}
	return true
}

func allRoutesAbsolute(routes []string) bool {
	for _, route := range routes {
		if !strings.HasPrefix(strings.TrimSpace(route), "/") {
			return false
		}
	}
	return true
}

func allArtifactsOfKind(paths []string, kinds map[string]ArtifactKind, want ArtifactKind) bool {
	for _, path := range paths {
		if kinds[path] != want {
			return false
		}
	}
	return true
}

func hasArtifactKind(artifacts []Artifact, want ArtifactKind) bool {
	for _, artifact := range artifacts {
		if artifact.Kind == want {
			return true
		}
	}
	return false
}

func hasLiveAPIRequest(requests []BrowserRequest, mode HarnessMode) bool {
	for _, request := range requests {
		u, err := url.Parse(request.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || request.Status < 200 || request.Status >= 400 {
			continue
		}
		if mode == HarnessModeTenantPlane && strings.HasPrefix(u.Path, "/v1/") ||
			mode == HarnessModeProviderPlane && strings.HasPrefix(u.Path, "/provider/v1/") {
			return true
		}
	}
	return false
}

func validBinaryEntrypoint(value string) bool {
	value = strings.TrimSpace(value)
	file, anchor, anchored := strings.Cut(value, "#")
	clean := path.Clean(file)
	return clean == file && strings.HasPrefix(clean, "cmd/") && strings.HasSuffix(clean, ".go") &&
		!strings.HasSuffix(clean, "_test.go") && !strings.Contains(clean, "/testdata/") && anchored && strings.TrimSpace(anchor) != ""
}

func validDefaultBuildCommand(value string) bool {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-tags") || strings.Contains(lower, "_test") || strings.Contains(lower, " test") {
		return false
	}
	return (fields[0] == "go" && fields[1] == "build") ||
		(fields[0] == "make" && (fields[1] == "build" || fields[1] == "release" || strings.HasPrefix(fields[1], "build-")))
}

func validAPIReachability(api APIReachability) bool {
	method := strings.ToUpper(strings.TrimSpace(api.Method))
	if !strings.HasPrefix(api.Path, "/") {
		return false
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return false
	}
	return strings.HasPrefix(api.Path, "/v1/") || strings.HasPrefix(api.Path, "/provider/v1/")
}

func containsExact(values []string, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func validUIRoute(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "/") && !strings.Contains(value, "..")
}

func validDocsPath(value string) bool {
	value = strings.TrimSpace(value)
	file, _, _ := strings.Cut(value, "#")
	clean := path.Clean(file)
	return clean == file && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") &&
		(strings.HasPrefix(clean, "docs/") || clean == "README.md") && strings.HasSuffix(strings.ToLower(clean), ".md")
}

func validLicenseActivation(activation ActivationEvidence) bool {
	switch strings.TrimSpace(activation.LicenseTier) {
	case "core":
		return activation.LicenseState == "not_applicable" && activation.ProviderFeatureEnabled == nil &&
			activation.ProviderLicenseObservation == nil
	case "enterprise", "msp":
		if activation.LicenseState != "active" && activation.LicenseState != "grace" && activation.LicenseState != "read_only" {
			return false
		}
		if activation.ProviderFeatureEnabled == nil && activation.ProviderLicenseObservation == nil {
			return true
		}
		return validProviderLicenseActivation(activation)
	default:
		return false
	}
}

func validProviderLicenseActivation(activation ActivationEvidence) bool {
	observation := activation.ProviderLicenseObservation
	return activation.LicenseTier == "msp" && activation.LicenseState == "active" &&
		activation.ProviderFeatureEnabled != nil && *activation.ProviderFeatureEnabled && observation != nil &&
		observation.LiveAuthenticated != nil && *observation.LiveAuthenticated && observation.Method == "GET" &&
		observation.Path == "/provider/v1/license" && observation.Status >= 200 && observation.Status < 300 &&
		digestRe.MatchString(observation.LicenseSHA256) && digestRe.MatchString(observation.SigningKeyFingerprint) &&
		observation.ProviderFeatureEnabled != nil && *observation.ProviderFeatureEnabled
}

func validBuildTags(tags []string) bool {
	if len(tags) > 32 {
		return false
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		parts := strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
		forbidden := false
		for _, part := range parts {
			if part == "test" || part == "testonly" || part == "dev" || part == "development" || part == "devauth" {
				forbidden = true
				break
			}
		}
		if !tagRe.MatchString(tag) || seen[tag] || forbidden || lower == "default" {
			return false
		}
		seen[tag] = true
	}
	return true
}

func validShortLivedCA(receipt Receipt) bool {
	if receipt.TLS.CANotBefore.IsZero() || receipt.TLS.CANotAfter.IsZero() ||
		receipt.TLS.CANotBefore.After(receipt.StartedAt) || !receipt.TLS.CANotAfter.After(receipt.CompletedAt) {
		return false
	}
	validity := receipt.TLS.CANotAfter.Sub(receipt.TLS.CANotBefore)
	return validity > 0 && validity <= 6*time.Hour
}

func evidenceFlagsInvalid(receipt Receipt) (fixture, mock, testdata bool) {
	return receipt.EvidenceSources.Fixture == nil || *receipt.EvidenceSources.Fixture,
		receipt.EvidenceSources.Mock == nil || *receipt.EvidenceSources.Mock,
		receipt.EvidenceSources.TestData == nil || *receipt.EvidenceSources.TestData
}

func containsForbiddenEvidenceMarker(receipt Receipt) bool {
	var values []string
	for _, artifact := range receipt.Artifacts {
		if artifact.Kind == ArtifactLinterOutput || artifact.Kind == ArtifactNegativeReceipt || artifact.Kind == ArtifactNegativeFixture {
			continue
		}
		values = append(values, artifact.Path)
	}
	values = append(values, receipt.CLI.Commands...)
	values = append(values,
		receipt.Reachability.Artifact,
		receipt.Reachability.BinaryEntrypoint,
		receipt.Reachability.DefaultBuildCommand,
		receipt.Reachability.API.OperationID,
		receipt.Reachability.API.Path,
		receipt.Reachability.CLIOperation,
		receipt.Reachability.UIRoute,
		receipt.Reachability.DocsPath,
		receipt.Activation.Artifact,
		receipt.Activation.EnableCLICommand,
		receipt.Activation.EnableUIRoute,
		receipt.Activation.DocsPath,
		receipt.Activation.LicenseState,
	)
	values = append(values, receipt.Activation.BuildTags...)
	for _, request := range receipt.BrowserNetwork.Requests {
		values = append(values, request.URL)
	}
	for _, value := range values {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "fixture") || strings.Contains(lower, "testdata") ||
			strings.Contains(lower, "httptest") || strings.Contains(lower, "route.fulfill") ||
			strings.Contains(lower, "probectl_web_fixtures") || mockRe.MatchString(lower) {
			return true
		}
	}
	return false
}
