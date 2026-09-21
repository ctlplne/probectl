// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image/png"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

const (
	maxSemanticArtifactBytes = 4 << 20
	maxScreenshotBytes       = 32 << 20
	reviewProtocolPath       = "docs/contract/delivery-audit-review-protocols.json"
)

type deliveryAuditAuthorityRegistry struct {
	Schema              string                    `json:"schema"`
	ExecutableProtocols []executableAuditProtocol `json:"executable_protocols"`
	ReviewProtocols     []governedReviewProtocol  `json:"review_protocols"`
}

type executableAuditProtocol struct {
	Item         string      `json:"item"`
	CapabilityID string      `json:"capability_id"`
	HumanPathID  string      `json:"human_path_id"`
	Mode         HarnessMode `json:"mode"`
}

type governedReviewProtocol struct {
	Item             string   `json:"item"`
	CapabilityID     string   `json:"capability_id"`
	Kinds            []string `json:"kinds"`
	MethodologyRoots []string `json:"methodology_roots"`
	SubjectRoots     []string `json:"subject_roots"`
}

// BrowserSession is one tenant-bound UI observation recorded by the browser
// harness. It lets the receipt's route summary be checked against the actual
// browser artifact rather than accepted as a self-assertion.
type BrowserSession struct {
	AuthMode                HarnessAuthMode `json:"auth_mode"`
	Tenant                  string          `json:"tenant,omitempty"`
	ProviderActor           string          `json:"provider_actor,omitempty"`
	Route                   string          `json:"route"`
	Screenshot              string          `json:"screenshot"`
	Rendered                *bool           `json:"rendered"`
	CredentialedLogin       *bool           `json:"credentialed_login"`
	TenantIndicatorVisible  *bool           `json:"tenant_indicator_visible,omitempty"`
	ProviderConsoleVisible  *bool           `json:"provider_console_visible,omitempty"`
	ExpectedEvidenceVisible *bool           `json:"expected_evidence_visible"`
	ForeignEvidenceAbsent   *bool           `json:"foreign_evidence_absent"`
}

// BrowserNetworkArtifact is the strict, bounded JSON contract for a browser
// network attachment.
type BrowserNetworkArtifact struct {
	Schema              string           `json:"schema"`
	Browser             string           `json:"browser"`
	LiveHTTPS           *bool            `json:"live_https"`
	RequestInterception *bool            `json:"request_interception"`
	IgnoreHTTPSErrors   *bool            `json:"ignore_https_errors"`
	Requests            []BrowserRequest `json:"requests"`
	Sessions            []BrowserSession `json:"sessions"`
}

// CLITranscriptArtifact records structured release-CLI observations. The
// command's mapped API is proven here, independently of natural browser API
// traffic, so the harness never needs a synthetic page-context fetch.
type CLITranscriptArtifact struct {
	Schema       string                  `json:"schema"`
	Redacted     *bool                   `json:"redacted"`
	Observations []CLICommandObservation `json:"observations"`
}

const (
	CLIExpectedSuccess           = "success"
	CLIExpectedRejected          = "rejected"
	CLIStatusFromCLIResponse     = "cli_structured_response"
	CLIStatusFromSameAuthHTTPS   = "same_auth_https_companion"
	APIObservationArtifactSchema = "probectl.delivery-audit-api-observation/v1"
)

type CLICommandObservation struct {
	AuthMode                 HarnessAuthMode `json:"auth_mode"`
	Tenant                   string          `json:"tenant,omitempty"`
	TargetTenant             string          `json:"target_tenant,omitempty"`
	ProviderActor            string          `json:"provider_actor,omitempty"`
	Command                  string          `json:"command"`
	Method                   string          `json:"method"`
	Path                     string          `json:"path"`
	Expected                 string          `json:"expected"`
	CLIExitStatus            int             `json:"cli_exit_status"`
	CLIOutputArtifact        string          `json:"cli_output_artifact"`
	CLIOutputSHA256          string          `json:"cli_output_sha256"`
	ResponseArtifact         string          `json:"response_artifact"`
	StatusProvenance         string          `json:"status_provenance"`
	CompanionRequestArtifact string          `json:"companion_request_artifact,omitempty"`
	CompanionRequestSHA256   string          `json:"companion_request_sha256,omitempty"`
	Status                   int             `json:"status"`
	Success                  *bool           `json:"success"`
	ExpectationMet           *bool           `json:"expectation_met"`
	ResponseSHA256           string          `json:"response_sha256"`
}

// APIObservationArtifact is the strict, redacted response companion for one
// CLI observation. It makes HTTP status and auth/tenant provenance
// independently cross-checkable instead of accepting a free-form digest.
type APIObservationArtifact struct {
	Schema        string          `json:"schema"`
	Redacted      *bool           `json:"redacted"`
	AuthMode      HarnessAuthMode `json:"auth_mode"`
	Tenant        string          `json:"tenant,omitempty"`
	TargetTenant  string          `json:"target_tenant,omitempty"`
	ProviderActor string          `json:"provider_actor,omitempty"`
	Command       string          `json:"command"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	Status        int             `json:"status"`
	ErrorCode     string          `json:"error_code,omitempty"`
	Body          json.RawMessage `json:"body"`
}

// ReachabilityArtifact is the strict, bounded JSON contract for static
// release-path reachability. Artifact is deliberately absent: the receipt is
// the object that binds this payload to a relative path and digest.
type ReachabilityArtifact struct {
	Schema                string          `json:"schema"`
	SourceGitSHA          string          `json:"source_git_sha"`
	SourceTreeSHA         string          `json:"source_tree_sha"`
	CapabilityID          string          `json:"capability_id"`
	RegistryPath          string          `json:"registry_path"`
	RegistrySHA256        string          `json:"registry_sha256"`
	StaticGate            string          `json:"static_gate"`
	ValidatorPassed       *bool           `json:"validator_passed"`
	BinaryEntrypoint      string          `json:"binary_entrypoint"`
	DefaultBuildCommand   string          `json:"default_build_command"`
	DefaultBuildReachable *bool           `json:"default_build_reachable"`
	API                   APIReachability `json:"api"`
	CLIOperation          string          `json:"cli_operation"`
	UIRoute               string          `json:"ui_route"`
	DocsPath              string          `json:"docs_path"`
	ObservedInRelease     *bool           `json:"observed_in_release"`
}

// ActivationArtifact is the strict, bounded JSON contract for observed
// runtime activation.
type ActivationArtifact struct {
	Schema                     string                      `json:"schema"`
	EnabledByDefault           *bool                       `json:"enabled_by_default"`
	RuntimeActive              *bool                       `json:"runtime_active"`
	EnableCLICommand           string                      `json:"enable_cli_command,omitempty"`
	EnableUIRoute              string                      `json:"enable_ui_route,omitempty"`
	DocsPath                   string                      `json:"docs_path"`
	LicenseTier                string                      `json:"license_tier"`
	LicenseState               string                      `json:"license_state"`
	ProviderFeatureEnabled     *bool                       `json:"provider_feature_enabled,omitempty"`
	ProviderLicenseObservation *ProviderLicenseObservation `json:"provider_license_observation,omitempty"`
	BuildTags                  []string                    `json:"build_tags"`
	ReleaseGoTags              []string                    `json:"release_go_tags"`
	DevAuth                    *bool                       `json:"dev_auth"`
}

// StoreProbesArtifact is the strict, bounded JSON contract for the distinct
// guarantees each real store honestly provides. PostgreSQL and ClickHouse
// prove query isolation; Kafka and Prometheus prove authenticated transport
// plus tenant metadata integrity without overclaiming reader/query isolation.
type StoreProbesArtifact struct {
	Schema                  string                   `json:"schema"`
	ProductPipelineArtifact string                   `json:"product_pipeline_artifact"`
	Postgres                PostgresIsolationProbe   `json:"postgres"`
	ClickHouse              ClickHouseIsolationProbe `json:"clickhouse"`
	Kafka                   KafkaIntegrityProbe      `json:"kafka"`
	Prometheus              PrometheusIntegrityProbe `json:"prometheus"`
	ProviderBoundary        ProviderBoundaryProbe    `json:"provider_boundary"`
}

// ProductPipelineArtifact binds two non-vacuous release-product round trips:
// authenticated OTLP metrics through Kafka into Prometheus, and authenticated
// OTLP traces through Kafka into ClickHouse. Both must be read back through the
// tenant-authenticated release CLI/API and independently cross-checked against
// the real store. A free-standing manual insert/query cannot satisfy this
// contract.
type ProductPipelineArtifact struct {
	Schema              string                   `json:"schema"`
	ReceiptID           string                   `json:"receipt_id"`
	SourceGitSHA        string                   `json:"source_git_sha"`
	SourceTreeSHA       string                   `json:"source_tree_sha"`
	ControlImageID      string                   `json:"control_image_id"`
	CLISHA256           string                   `json:"cli_sha256"`
	StartedAt           time.Time                `json:"started_at"`
	CompletedAt         time.Time                `json:"completed_at"`
	Tenants             []ProductTenantPipeline  `json:"tenants"`
	Integrity           ProductPipelineIntegrity `json:"integrity"`
	ClickHouseIsolation ProductArtifactRef       `json:"clickhouse_isolation"`
}

type ProductTenantPipeline struct {
	Tenant         string                    `json:"tenant"`
	Metrics        ProductMetricPipelineFlow `json:"metrics"`
	Traces         ProductTracePipelineFlow  `json:"traces"`
	ForeignQueries ProductForeignQueries     `json:"foreign_queries"`
}

type ProductForeignQueries struct {
	Metrics ProductControlQuery `json:"metrics"`
	Traces  ProductControlQuery `json:"traces"`
}

type ProductPipelineIntegrity struct {
	BeforeObservedAt time.Time          `json:"before_observed_at"`
	AfterObservedAt  time.Time          `json:"after_observed_at"`
	Before           ProductArtifactRef `json:"before"`
	After            ProductArtifactRef `json:"after"`
}

type ProductArtifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ProductIngestExchange struct {
	ObservedAt time.Time          `json:"observed_at"`
	URL        string             `json:"url"`
	AuthMode   string             `json:"auth_mode"`
	Method     string             `json:"method"`
	Status     int                `json:"status"`
	Request    ProductArtifactRef `json:"request"`
	Response   ProductArtifactRef `json:"response"`
}

type ProductKafkaObservation struct {
	Topic       string             `json:"topic"`
	Partition   int32              `json:"partition"`
	Offset      int64              `json:"offset"`
	Key         ProductArtifactRef `json:"key"`
	Payload     ProductArtifactRef `json:"payload"`
	GroupOffset ProductArtifactRef `json:"group_offset"`
}

type KafkaGroupOffsetArtifact struct {
	Schema            string             `json:"schema"`
	BrokerAuthority   string             `json:"broker_authority"`
	Source            string             `json:"source"`
	SecurityProtocol  string             `json:"security_protocol"`
	TLSVerified       *bool              `json:"tls_verified"`
	SASLAuthenticated *bool              `json:"sasl_authenticated"`
	ObservedAt        time.Time          `json:"observed_at"`
	Topic             string             `json:"topic"`
	Partition         int32              `json:"partition"`
	ConsumerGroup     string             `json:"consumer_group"`
	CommittedOffset   int64              `json:"committed_offset"`
	RawObservation    ProductArtifactRef `json:"raw_observation"`
}

type ProductControlQuery struct {
	ObservedAt     time.Time          `json:"observed_at"`
	Command        string             `json:"command"`
	Method         string             `json:"method"`
	Path           string             `json:"path"`
	APIObservation ProductArtifactRef `json:"api_observation"`
}

type ProductMetricPipelineFlow struct {
	CorrelationID    string                       `json:"correlation_id"`
	ServiceName      string                       `json:"service_name"`
	MetricName       string                       `json:"metric_name"`
	StoredMetricName string                       `json:"stored_metric_name"`
	Value            float64                      `json:"value"`
	TimeUnixNano     uint64                       `json:"time_unix_nano"`
	Ingest           ProductIngestExchange        `json:"ingest"`
	Kafka            ProductKafkaObservation      `json:"kafka"`
	ControlQuery     ProductControlQuery          `json:"control_query"`
	PrometheusDirect ProductPrometheusDirectQuery `json:"prometheus_direct"`
}

type ProductPrometheusDirectQuery struct {
	ObservedAt time.Time          `json:"observed_at"`
	User       string             `json:"user"`
	URL        string             `json:"url"`
	Query      string             `json:"query"`
	Response   ProductArtifactRef `json:"response"`
}

type ProductTracePipelineFlow struct {
	CorrelationID     string                       `json:"correlation_id"`
	TraceID           string                       `json:"trace_id"`
	SpanID            string                       `json:"span_id"`
	ServiceName       string                       `json:"service_name"`
	SpanName          string                       `json:"span_name"`
	StartTimeUnixNano uint64                       `json:"start_time_unix_nano"`
	EndTimeUnixNano   uint64                       `json:"end_time_unix_nano"`
	Ingest            ProductIngestExchange        `json:"ingest"`
	Kafka             ProductKafkaObservation      `json:"kafka"`
	ControlQuery      ProductControlQuery          `json:"control_query"`
	ClickHouseDirect  ProductClickHouseDirectQuery `json:"clickhouse_direct"`
}

type ProductClickHouseDirectQuery struct {
	ObservedAt         time.Time          `json:"observed_at"`
	User               string             `json:"user"`
	Database           string             `json:"database"`
	Table              string             `json:"table"`
	TenantSetting      string             `json:"tenant_setting"`
	TenantSettingValue string             `json:"tenant_setting_value"`
	SQL                string             `json:"sql"`
	Parameters         map[string]string  `json:"parameters"`
	Response           ProductArtifactRef `json:"response"`
}

type ClickHouseIsolationArtifact struct {
	Schema            string             `json:"schema"`
	User              string             `json:"user"`
	Database          string             `json:"database"`
	Table             string             `json:"table"`
	TenantSetting     string             `json:"tenant_setting"`
	SQL               string             `json:"sql"`
	Parameters        map[string]string  `json:"parameters"`
	TenantA           string             `json:"tenant_a"`
	TenantB           string             `json:"tenant_b"`
	TenantAObservedAt time.Time          `json:"tenant_a_observed_at"`
	TenantBObservedAt time.Time          `json:"tenant_b_observed_at"`
	UnsetObservedAt   time.Time          `json:"unset_observed_at"`
	TenantAResponse   ProductArtifactRef `json:"tenant_a_response"`
	TenantBResponse   ProductArtifactRef `json:"tenant_b_response"`
	UnsetResponse     ProductArtifactRef `json:"unset_response"`
}

// GovernedReviewArtifact repeats the signed review summary and binds it to the
// exact source revision. Subject digests are recomputed from sourceRoot.
type GovernedReviewArtifact struct {
	Schema          string                  `json:"schema"`
	SourceGitSHA    string                  `json:"source_git_sha"`
	SourceTreeSHA   string                  `json:"source_tree_sha"`
	Item            string                  `json:"item"`
	CapabilityID    string                  `json:"capability_id"`
	ReviewID        string                  `json:"review_id"`
	Kind            string                  `json:"kind"`
	AuthorityPath   string                  `json:"authority_path"`
	AuthorityAnchor string                  `json:"authority_anchor"`
	MethodologyPath string                  `json:"methodology_path"`
	Subjects        []GovernedReviewSubject `json:"subjects"`
	Checks          []GovernedReviewCheck   `json:"checks"`
	Conclusion      string                  `json:"conclusion"`
}

// LinterOutputArtifact proves the same linter rejected a separately signed
// FAILED envelope whose named artifact contains the planted forbidden marker.
type LinterOutputArtifact struct {
	Schema                string       `json:"schema"`
	Rejected              *bool        `json:"rejected"`
	FailedEnvelopePath    string       `json:"failed_envelope_path"`
	FailedEnvelopeSHA256  string       `json:"failed_envelope_sha256"`
	PlantedArtifactPath   string       `json:"planted_artifact_path"`
	PlantedArtifactSHA256 string       `json:"planted_artifact_sha256"`
	Diagnostics           []Diagnostic `json:"diagnostics"`
}

// StackInventoryArtifact is the strict contract for the actual services and
// release artifacts started by the independent harness.
type StackInventoryArtifact struct {
	Schema              string                           `json:"schema"`
	Source              Source                           `json:"source"`
	Release             StackReleaseInventory            `json:"release"`
	Services            map[string]StackServiceInventory `json:"services"`
	Network             StackNetworkInventory            `json:"network"`
	CredentialTransport map[string]string                `json:"credential_transport"`
	Runtime             StackRuntimeInventory            `json:"runtime"`
	Harness             HarnessScopeEvidence             `json:"harness"`
	Limitations         []string                         `json:"limitations"`
}

type StackReleaseInventory struct {
	Control StackControlInventory `json:"control"`
	CLI     StackCLIInventory     `json:"cli"`
	Browser StackBrowserInventory `json:"browser"`
}

type StackControlInventory struct {
	Image          string   `json:"image"`
	ImageID        string   `json:"image_id"`
	BuildTags      []string `json:"build_tags"`
	DevAuth        *bool    `json:"dev_auth"`
	EmbeddedViteUI *bool    `json:"embedded_vite_ui"`
}

type StackCLIInventory struct {
	Image     string   `json:"image"`
	ImageID   string   `json:"image_id"`
	SHA256    string   `json:"sha256"`
	BuildTags []string `json:"build_tags"`
	DevAuth   *bool    `json:"dev_auth"`
}

type StackBrowserInventory struct {
	Image   string `json:"image"`
	ImageID string `json:"image_id"`
	Engine  string `json:"engine"`
	Version string `json:"version"`
}

type StackServiceInventory struct {
	Version                  string `json:"version"`
	Running                  *bool  `json:"running"`
	RealService              *bool  `json:"real_service"`
	TLSConfigured            *bool  `json:"tls_configured"`
	AuthenticationConfigured *bool  `json:"authentication_configured"`
}

type StackNetworkInventory struct {
	Internal       *bool `json:"internal"`
	PublishedPorts *int  `json:"published_ports"`
}

type StackRuntimeInventory struct {
	TLSPrivateKeyFiles map[string]RuntimeCredentialFile `json:"tls_private_key_files"`
}

type RuntimeCredentialFile struct {
	Path       string `json:"path"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	Mode       string `json:"mode"`
	ConsumedBy string `json:"consumed_by"`
	Purpose    string `json:"purpose"`
}

// TLSTrustArtifact is the strict, bounded JSON contract for CA/browser and
// per-listener transport/authentication observations.
type TLSTrustArtifact struct {
	Schema                   string                      `json:"schema"`
	CAFingerprint            string                      `json:"ca_fingerprint"`
	CANotBefore              time.Time                   `json:"ca_not_before"`
	CANotAfter               time.Time                   `json:"ca_not_after"`
	BrowserRejectedWithoutCA *bool                       `json:"browser_rejected_without_ca"`
	BrowserTrustedWithCA     *bool                       `json:"browser_trusted_with_ca"`
	BrowserPretrustFailure   BrowserPretrustFailure      `json:"browser_pretrust_failure"`
	IgnoreHTTPSErrors        *bool                       `json:"ignore_https_errors"`
	Listeners                map[string]TLSListenerProbe `json:"listeners"`
	CertificateManifest      string                      `json:"certificate_manifest"`
	CACertificate            string                      `json:"ca_certificate"`
	ServiceCertificates      map[string]string           `json:"service_certificates"`
}

var requiredServiceInventories = []string{
	"clickhouse",
	"control",
	"dex",
	"kafka",
	"postgres",
	"prometheus",
}

var requiredTLSListeners = []string{
	"clickhouse",
	"control",
	"dex",
	"kafka",
	"otlp_http",
	"postgres",
	"prometheus",
}

// LintWithArtifacts applies receipt policy and then independently decodes the
// evidence bytes the receipt names. It is the semantic check used before a
// VERIFIED receipt is sealed and again before it can promote a backlog item.
func LintWithArtifacts(receipt Receipt, artifactRoot string) []Diagnostic {
	return LintWithArtifactsAtSource(receipt, artifactRoot, "")
}

// LintWithArtifactsAtSource additionally resolves static reachability against
// the supplied exact source archive or checkout.
func LintWithArtifactsAtSource(receipt Receipt, artifactRoot, sourceRoot string) []Diagnostic {
	_, snapshot, err := bindArtifactSnapshot(receipt, artifactRoot)
	if err != nil {
		diagnostics := append(Lint(receipt), Diagnostic{
			Code:    "artifact-unreadable",
			Field:   "artifacts",
			Problem: err.Error(),
		})
		return sortAndDedupeDiagnostics(diagnostics)
	}
	return lintWithArtifactSnapshot(receipt, snapshot, sourceRoot)
}

// LintVerifiedAtSource applies semantic policy to a verified byte snapshot and
// resolves reachability against the exact supplied source tree.
func LintVerifiedAtSource(verified *VerifiedEnvelope, sourceRoot string) []Diagnostic {
	if verified == nil {
		return []Diagnostic{{Code: "artifact-unreadable", Field: "artifacts", Problem: "verified envelope is nil"}}
	}
	return lintWithArtifactSnapshot(verified.Receipt, verified.artifacts, sourceRoot)
}

func lintWithArtifactSnapshot(receipt Receipt, snapshot map[string]semanticArtifactResult, sourceRoot string) []Diagnostic {
	diagnostics := Lint(receipt)
	loader := semanticArtifactLoader{cache: snapshot}
	diagnostics = append(diagnostics, lintArtifactMarkers(receipt, &loader)...)
	if receipt.Status == OutcomeFailed {
		return sortAndDedupeDiagnostics(diagnostics)
	}
	diagnostics = append(diagnostics, lintNegativeControlArtifact(receipt, &loader)...)
	if receipt.HumanPath.PathClass == HumanPathClassGovernedReview {
		diagnostics = append(diagnostics, lintGovernedReviewArtifact(receipt, &loader, sourceRoot)...)
		return sortAndDedupeDiagnostics(diagnostics)
	}
	diagnostics = append(diagnostics, lintScreenshotArtifacts(receipt, &loader)...)
	diagnostics = append(diagnostics, lintStackInventoryArtifact(receipt, &loader)...)
	diagnostics = append(diagnostics, lintCLIArtifact(receipt, &loader)...)
	diagnostics = append(diagnostics, lintBrowserArtifact(receipt, &loader)...)
	diagnostics = append(diagnostics, lintReachabilityArtifact(receipt, &loader, sourceRoot)...)
	diagnostics = append(diagnostics, lintActivationArtifact(receipt, &loader)...)
	diagnostics = append(diagnostics, lintStoreArtifact(receipt, &loader)...)
	diagnostics = append(diagnostics, lintProductPipelineArtifact(receipt, &loader)...)
	diagnostics = append(diagnostics, lintTLSArtifact(receipt, &loader)...)
	return sortAndDedupeDiagnostics(diagnostics)
}

type semanticArtifactResult struct {
	data []byte
	err  error
}

type semanticArtifactLoader struct {
	cache map[string]semanticArtifactResult
}

func (l *semanticArtifactLoader) read(relative string) ([]byte, error) {
	result, ok := l.cache[relative]
	if !ok {
		return nil, fmt.Errorf("semantic artifact %q was not retained from the verified byte snapshot", relative)
	}
	return result.data, result.err
}

func lintArtifactMarkers(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	var out []Diagnostic
	for _, artifact := range receipt.Artifacts {
		// Screenshots are binary. Linter output is allowed to name the planted
		// marker it successfully rejected; it is evidence about the negative
		// control, not evidence used to assert the product path passed.
		if artifact.Kind == ArtifactUIScreenshot || artifact.Kind == ArtifactLinterOutput ||
			artifact.Kind == ArtifactNegativeReceipt || artifact.Kind == ArtifactNegativeFixture ||
			artifact.Kind == ArtifactOTLPRequest || artifact.Kind == ArtifactOTLPResponse ||
			artifact.Kind == ArtifactKafkaKey || artifact.Kind == ArtifactKafkaPayload {
			continue
		}
		data, err := loader.read(artifact.Path)
		if err != nil {
			out = append(out, Diagnostic{
				Code:    "artifact-unreadable",
				Field:   "artifacts." + artifact.Path,
				Problem: fmt.Sprintf("semantic evidence cannot be read within the %d-byte limit: %v", maxSemanticArtifactBytes, err),
			})
			continue
		}
		if containsForbiddenArtifactMarker(data) {
			out = append(out, Diagnostic{
				Code:    "fixture-only",
				Field:   "artifacts." + artifact.Path,
				Problem: "evidence artifact contains a selftest, fixture, mock, or test-only marker",
			})
		}
	}
	return out
}

func lintNegativeControlArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	var linterPaths, envelopePaths, fixturePaths []string
	for _, artifact := range receipt.Artifacts {
		switch artifact.Kind {
		case ArtifactLinterOutput:
			linterPaths = append(linterPaths, artifact.Path)
		case ArtifactNegativeReceipt:
			envelopePaths = append(envelopePaths, artifact.Path)
		case ArtifactNegativeFixture:
			fixturePaths = append(fixturePaths, artifact.Path)
		}
	}
	if len(linterPaths) != 1 || len(envelopePaths) != 1 || len(fixturePaths) != 1 {
		return []Diagnostic{{Code: "negative-control-invalid", Field: "artifacts", Problem: "exactly one strict linter output, signed FAILED envelope, and planted fixture artifact are required"}}
	}
	data, err := loader.read(linterPaths[0])
	if err != nil {
		return nil
	}
	var report LinterOutputArtifact
	if err := decodeStrict(data, &report); err != nil || report.Schema != LinterOutputArtifactSchema {
		return []Diagnostic{{Code: "negative-control-invalid", Field: "artifacts." + linterPaths[0], Problem: "linter output must be strict probectl.delivery-audit-linter-output/v1 JSON"}}
	}
	failedEnvelope, envelopeErr := loader.read(envelopePaths[0])
	planted, plantedErr := loader.read(fixturePaths[0])
	invalid := report.Rejected == nil || !*report.Rejected || report.FailedEnvelopePath != envelopePaths[0] ||
		report.PlantedArtifactPath != fixturePaths[0] || envelopeErr != nil || plantedErr != nil ||
		report.FailedEnvelopeSHA256 != digestBytes(failedEnvelope) || report.PlantedArtifactSHA256 != digestBytes(planted) ||
		!containsForbiddenArtifactMarker(planted) || !hasExactNegativeDiagnostics(report.Diagnostics)
	if invalid {
		return []Diagnostic{{Code: "negative-control-invalid", Field: "artifacts." + linterPaths[0], Problem: "negative report must bind exact failed-envelope/fixture bytes and the fixture-only + status-failed rejection"}}
	}
	if err := verifyNestedFailedEnvelope(failedEnvelope, fixturePaths[0], planted); err != nil {
		return []Diagnostic{{Code: "negative-control-invalid", Field: "artifacts." + envelopePaths[0], Problem: err.Error()}}
	}
	return nil
}

func hasExactNegativeDiagnostics(diagnostics []Diagnostic) bool {
	if len(diagnostics) != 2 {
		return false
	}
	codes := []string{diagnostics[0].Code, diagnostics[1].Code}
	sort.Strings(codes)
	return reflect.DeepEqual(codes, []string{"fixture-only", "status-failed"})
}

func verifyNestedFailedEnvelope(raw []byte, plantedPath string, planted []byte) error {
	var envelope Envelope
	if err := decodeStrict(raw, &envelope); err != nil || envelope.Schema != EnvelopeSchema || envelope.Signing.Algorithm != SignatureAlgorithm ||
		len(envelope.Signing.Signature) != probcrypto.Ed25519SignatureSize ||
		envelope.Signing.Fingerprint != digestBytes([]byte(envelope.Signing.PublicKey)) {
		return fmt.Errorf("planted FAILED envelope has invalid strict schema/signing metadata")
	}
	ok, err := probcrypto.VerifyEd25519([]byte(envelope.Signing.PublicKey), envelope.Receipt, envelope.Signing.Signature)
	if err != nil || !ok {
		return fmt.Errorf("planted FAILED envelope signature does not verify")
	}
	receipt, err := DecodeReceipt(envelope.Receipt)
	if err != nil || receipt.Status != OutcomeFailed {
		return fmt.Errorf("planted envelope must contain a structurally valid FAILED receipt")
	}
	for _, artifact := range receipt.Artifacts {
		if artifact.Path == plantedPath && artifact.Bytes == int64(len(planted)) && artifact.SHA256 == digestBytes(planted) {
			diagnostics := lintWithArtifactSnapshot(receipt, map[string]semanticArtifactResult{
				plantedPath: {data: planted},
			}, "")
			if !hasExactNegativeDiagnostics(diagnostics) {
				return fmt.Errorf("FAILED receipt's artifact-aware linter diagnostics are not fixture-only + status-failed")
			}
			return nil
		}
	}
	return fmt.Errorf("FAILED receipt does not bind the exact planted fixture artifact")
}

func lintScreenshotArtifacts(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	var out []Diagnostic
	for i, path := range receipt.UI.Screenshots {
		data, err := loader.read(path)
		if err != nil {
			out = append(out, Diagnostic{
				Code: "ui-screenshot-invalid", Field: fmt.Sprintf("ui.screenshots.%d", i),
				Problem: fmt.Sprintf("rendered screenshot cannot be read: %v", err),
			})
			continue
		}
		if len(data) < 128 {
			out = append(out, Diagnostic{
				Code: "ui-screenshot-invalid", Field: fmt.Sprintf("ui.screenshots.%d", i),
				Problem: "rendered screenshot is implausibly small",
			})
			continue
		}
		config, err := png.DecodeConfig(bytes.NewReader(data))
		if err != nil || config.Width < 320 || config.Height < 200 || config.Width > 16384 || config.Height > 16384 {
			out = append(out, Diagnostic{
				Code: "ui-screenshot-invalid", Field: fmt.Sprintf("ui.screenshots.%d", i),
				Problem: "rendered screenshot must be a valid PNG with sane nontrivial dimensions",
			})
		}
	}
	return out
}

func lintStackInventoryArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	var paths []string
	for _, artifact := range receipt.Artifacts {
		if artifact.Kind == ArtifactStackInventory {
			paths = append(paths, artifact.Path)
		}
	}
	if len(paths) != 1 {
		return []Diagnostic{{
			Code: "stack-inventory-invalid", Field: "artifacts",
			Problem: "exactly one strict stack-inventory artifact is required",
		}}
	}
	var artifact StackInventoryArtifact
	if diagnostic := decodeSemanticJSON(loader, paths[0], StackInventoryArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	var out []Diagnostic
	out = addDiagnosticIf(out,
		artifact.Source.GitSHA != receipt.Source.GitSHA || artifact.Source.TreeSHA != receipt.Source.TreeSHA ||
			artifact.Source.Dirty == nil || *artifact.Source.Dirty,
		"stack-inventory-invalid", "stack_inventory.source", "stack inventory must match the receipt's exact clean source")
	out = addDiagnosticIf(out,
		artifact.Release.Control.ImageID != receipt.Build.ControlImageID ||
			artifact.Release.CLI.SHA256 != receipt.Build.CLISHA256 ||
			!reflect.DeepEqual(artifact.Release.Control.BuildTags, receipt.Activation.BuildTags) ||
			!reflect.DeepEqual(artifact.Release.CLI.BuildTags, receipt.Activation.BuildTags) ||
			artifact.Release.Control.DevAuth == nil || *artifact.Release.Control.DevAuth ||
			artifact.Release.CLI.DevAuth == nil || *artifact.Release.CLI.DevAuth ||
			artifact.Release.Control.EmbeddedViteUI == nil || !*artifact.Release.Control.EmbeddedViteUI ||
			strings.TrimSpace(artifact.Release.Control.Image) == "" || !validImageID(artifact.Release.Control.ImageID) ||
			strings.TrimSpace(artifact.Release.CLI.Image) == "" || !validImageID(artifact.Release.CLI.ImageID) ||
			strings.TrimSpace(artifact.Release.Browser.Image) == "" || !validImageID(artifact.Release.Browser.ImageID) ||
			artifact.Release.Browser.Engine != "webkit" || strings.TrimSpace(artifact.Release.Browser.Version) == "",
		"stack-inventory-invalid", "stack_inventory.release", "stack release inventory must match signed release digests, empty build tags, no dev-auth, real embedded UI, and WebKit")
	out = addDiagnosticIf(out, !reflect.DeepEqual(artifact.Harness, receipt.HarnessScope),
		"artifact-summary-mismatch", "stack_inventory.harness", "stack inventory must repeat the signed harness mode, auth mode, provider claim, and exact driver identities")
	out = addDiagnosticIf(out,
		artifact.Network.Internal == nil || !*artifact.Network.Internal ||
			artifact.Network.PublishedPorts == nil || *artifact.Network.PublishedPorts != 0,
		"stack-inventory-invalid", "stack_inventory.network", "audit stack must use an internal network with zero published ports")
	out = addDiagnosticIf(out, len(artifact.Services) != len(requiredServiceInventories),
		"stack-inventory-invalid", "stack_inventory.services", "stack inventory must contain exactly the six required real services")
	wantVersions := map[string]string{
		"control": receipt.Source.GitSHA, "dex": "2.45.1", "postgres": "16",
		"kafka": "3.9.0", "clickhouse": "24.8", "prometheus": "3.1.0",
	}
	wantCredentials := map[string]RuntimeCredentialFile{
		"control":    {Path: "/audit/pki/control/tls.key", UID: 65532, GID: 65532, Mode: "0600", ConsumedBy: "control", Purpose: "server_tls_private_key"},
		"dex":        {Path: "/audit/pki/dex/tls.key", UID: 65532, GID: 65532, Mode: "0600", ConsumedBy: "dex", Purpose: "server_tls_private_key"},
		"postgres":   {Path: "/audit/pki/postgres/tls.key", UID: 999, GID: 999, Mode: "0600", ConsumedBy: "postgres", Purpose: "server_tls_private_key"},
		"kafka":      {Path: "/etc/kafka/secrets/kafka.keystore.p12", UID: 1000, GID: 1000, Mode: "0600", ConsumedBy: "kafka", Purpose: "server_tls_private_key"},
		"clickhouse": {Path: "/audit/pki/clickhouse/tls.key", UID: 101, GID: 101, Mode: "0600", ConsumedBy: "clickhouse", Purpose: "server_tls_private_key"},
		"prometheus": {Path: "/audit/pki/prometheus/tls.key", UID: 65534, GID: 65534, Mode: "0600", ConsumedBy: "prometheus", Purpose: "server_tls_private_key"},
	}
	for _, service := range requiredServiceInventories {
		inventory, ok := artifact.Services[service]
		out = addDiagnosticIf(out, !ok, "stack-service-missing", "stack_inventory.services."+service,
			fmt.Sprintf("required real service %s is absent from stack inventory", service))
		out = addDiagnosticIf(out, ok && (invalidStackService(inventory) || inventory.Version != wantVersions[service] ||
			invalidTLSListenerProbe(service, receipt.TLS.Listeners[service])), "stack-service-invalid", "stack_inventory.services."+service,
			fmt.Sprintf("%s must be running, real, TLS-configured, and authentication-configured", service))
		credential, credentialOK := artifact.Runtime.TLSPrivateKeyFiles[service]
		out = addDiagnosticIf(out, !credentialOK || !reflect.DeepEqual(credential, wantCredentials[service]),
			"stack-service-invalid", "stack_inventory.runtime.tls_private_key_files."+service,
			fmt.Sprintf("%s consumed TLS credential path/owner/mode observation is missing or false", service))
	}
	out = addDiagnosticIf(out, len(artifact.Runtime.TLSPrivateKeyFiles) != len(requiredServiceInventories),
		"stack-inventory-invalid", "stack_inventory.runtime.tls_private_key_files", "runtime TLS private-key inventory must contain exactly the six consumed service keys")
	for _, name := range []string{"database", "kafka", "clickhouse", "prometheus"} {
		out = addDiagnosticIf(out, strings.TrimSpace(artifact.CredentialTransport[name]) == "",
			"stack-security-missing", "stack_inventory.credential_transport."+name,
			fmt.Sprintf("%s credential transport fact is missing", name))
	}
	return out
}

func invalidStackService(service StackServiceInventory) bool {
	return strings.TrimSpace(service.Version) == "" || service.Running == nil || !*service.Running ||
		service.RealService == nil || !*service.RealService || service.TLSConfigured == nil || !*service.TLSConfigured ||
		service.AuthenticationConfigured == nil || !*service.AuthenticationConfigured
}

func lintCLIArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.CLI.Transcript] != ArtifactCLITranscript {
		return nil
	}
	var transcript CLITranscriptArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.CLI.Transcript, CLITranscriptArtifactSchema, &transcript); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	var out []Diagnostic
	if transcript.Redacted == nil || !*transcript.Redacted || len(transcript.Observations) == 0 {
		out = append(out, Diagnostic{
			Code: "artifact-invalid", Field: "cli.transcript",
			Problem: "CLI transcript must be explicitly redacted and contain structured observations",
		})
	}
	usedArtifacts := make(map[string]bool)
	for _, observation := range transcript.Observations {
		if !validCLIObservation(observation, receipt.HarnessScope) ||
			!validCLIObservationArtifacts(receipt, observation, loader, usedArtifacts) {
			out = append(out, Diagnostic{
				Code: "artifact-invalid", Field: "cli.transcript",
				Problem: "every CLI observation must have a mode-matching auth context, explicit expected outcome, matching observed result, and response digest",
			})
			break
		}
	}
	for _, command := range receipt.CLI.Commands {
		observed := false
		for _, observation := range transcript.Observations {
			if validSuccessfulCLIObservation(observation, receipt.HarnessScope) && observation.Command == strings.TrimSpace(command) {
				observed = true
				break
			}
		}
		if !observed {
			out = append(out, Diagnostic{
				Code:    "artifact-summary-mismatch",
				Field:   "cli.commands",
				Problem: "signed CLI command summary has no successful structured observation in the CLI transcript artifact",
			})
		}
	}
	apiSubjects := make(map[string]bool)
	rejections := make(map[string]bool)
	for _, observation := range transcript.Observations {
		if validSuccessfulCLIObservation(observation, receipt.HarnessScope) && observation.Command == receipt.Reachability.CLIOperation &&
			strings.EqualFold(observation.Method, receipt.Reachability.API.Method) && observation.Path == receipt.Reachability.API.Path {
			apiSubjects[cliObservationSubject(observation, receipt.HarnessScope.Mode)] = true
		}
		if validRejectedCLIObservation(observation, receipt.HarnessScope) {
			rejections[observation.Tenant+"\x00"+observation.TargetTenant] = true
		}
	}
	requiredSubjects := 1
	if receipt.HarnessScope.Mode == HarnessModeTenantPlane {
		requiredSubjects = 2
	}
	if len(apiSubjects) < requiredSubjects {
		out = append(out, Diagnostic{
			Code:    "api-unreachable",
			Field:   "reachability.api",
			Problem: fmt.Sprintf("named API/CLI mapping needs successful structured release-CLI observations for %d distinct mode-appropriate subject(s)", requiredSubjects),
		})
	}
	if receipt.HarnessScope.Mode == HarnessModeTenantPlane && !hasBidirectionalCLIRejections(apiSubjects, rejections) {
		out = append(out, Diagnostic{
			Code:    "cli-isolation-unproven",
			Field:   "cli.transcript",
			Problem: "tenant-plane CLI evidence must explicitly record expectation-met 401/403/404 foreign-object rejection in both tenant directions",
		})
	}
	return out
}

func validCLIObservation(observation CLICommandObservation, scope HarnessScopeEvidence) bool {
	if !validCLIObservationBase(observation) {
		return false
	}
	switch scope.Mode {
	case HarnessModeTenantPlane:
		if observation.AuthMode != scope.CLIAuthMode || strings.TrimSpace(observation.Tenant) == "" || strings.TrimSpace(observation.ProviderActor) != "" {
			return false
		}
	case HarnessModeProviderPlane:
		if observation.AuthMode != scope.CLIAuthMode || strings.TrimSpace(observation.Tenant) != "" ||
			strings.TrimSpace(observation.TargetTenant) != "" || strings.TrimSpace(observation.ProviderActor) == "" {
			return false
		}
	default:
		return false
	}
	return validSuccessfulCLIObservation(observation, scope) || validRejectedCLIObservation(observation, scope)
}

func validCLIObservationBase(observation CLICommandObservation) bool {
	return strings.HasPrefix(strings.TrimSpace(observation.Command), "probectl ") &&
		strings.TrimSpace(observation.Method) != "" && strings.HasPrefix(observation.Path, "/") &&
		observation.Success != nil && observation.ExpectationMet != nil && *observation.ExpectationMet &&
		strings.TrimSpace(observation.CLIOutputArtifact) != "" && digestRe.MatchString(observation.CLIOutputSHA256) &&
		strings.TrimSpace(observation.ResponseArtifact) != "" && digestRe.MatchString(observation.ResponseSHA256)
}

func validCLIObservationArtifacts(receipt Receipt, observation CLICommandObservation, loader *semanticArtifactLoader, used map[string]bool) bool {
	kinds := indexArtifactKinds(receipt.Artifacts)
	if kinds[observation.CLIOutputArtifact] != ArtifactCLIOutput || kinds[observation.ResponseArtifact] != ArtifactAPIObservation ||
		used[observation.CLIOutputArtifact] || used[observation.ResponseArtifact] {
		return false
	}
	used[observation.CLIOutputArtifact] = true
	used[observation.ResponseArtifact] = true
	cliOutput, cliErr := loader.read(observation.CLIOutputArtifact)
	response, responseErr := loader.read(observation.ResponseArtifact)
	if cliErr != nil || responseErr != nil || digestBytes(cliOutput) != observation.CLIOutputSHA256 || digestBytes(response) != observation.ResponseSHA256 {
		return false
	}
	var artifact APIObservationArtifact
	if decodeStrict(response, &artifact) != nil || artifact.Schema != APIObservationArtifactSchema || artifact.Redacted == nil || !*artifact.Redacted ||
		artifact.AuthMode != observation.AuthMode || artifact.Tenant != observation.Tenant || artifact.TargetTenant != observation.TargetTenant ||
		artifact.ProviderActor != observation.ProviderActor || artifact.Command != observation.Command ||
		!strings.EqualFold(artifact.Method, observation.Method) || artifact.Path != observation.Path || artifact.Status != observation.Status ||
		len(bytes.TrimSpace(artifact.Body)) == 0 || bytes.Equal(bytes.TrimSpace(artifact.Body), []byte("null")) {
		return false
	}
	if observation.StatusProvenance == CLIStatusFromCLIResponse && !equivalentJSON(cliOutput, artifact.Body) {
		return false
	}
	if observation.StatusProvenance == CLIStatusFromSameAuthHTTPS && len(bytes.TrimSpace(cliOutput)) == 0 {
		return false
	}
	if observation.Expected == CLIExpectedRejected {
		return strings.TrimSpace(artifact.ErrorCode) != ""
	}
	return artifact.ErrorCode == ""
}

func equivalentJSON(a, b []byte) bool {
	var left, right any
	if decodeStrict(a, &left) != nil || decodeStrict(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func validSuccessfulCLIObservation(observation CLICommandObservation, scope HarnessScopeEvidence) bool {
	if !validCLIObservationBase(observation) || observation.Expected != CLIExpectedSuccess ||
		observation.CLIExitStatus != 0 || observation.StatusProvenance != CLIStatusFromCLIResponse ||
		observation.CompanionRequestSHA256 != "" || observation.Status < 200 || observation.Status >= 400 ||
		!*observation.Success || strings.TrimSpace(observation.TargetTenant) != "" {
		return false
	}
	if scope.Mode == HarnessModeTenantPlane {
		return observation.AuthMode == scope.CLIAuthMode && strings.TrimSpace(observation.Tenant) != "" && strings.TrimSpace(observation.ProviderActor) == ""
	}
	return scope.Mode == HarnessModeProviderPlane && observation.AuthMode == scope.CLIAuthMode &&
		strings.TrimSpace(observation.Tenant) == "" && strings.TrimSpace(observation.ProviderActor) != ""
}

func validRejectedCLIObservation(observation CLICommandObservation, scope HarnessScopeEvidence) bool {
	if scope.Mode != HarnessModeTenantPlane || !validCLIObservationBase(observation) ||
		observation.AuthMode != scope.CLIAuthMode || observation.Expected != CLIExpectedRejected || *observation.Success ||
		observation.CLIExitStatus == 0 || !validRejectedStatusProvenance(observation) ||
		strings.TrimSpace(observation.Tenant) == "" || strings.TrimSpace(observation.TargetTenant) == "" ||
		observation.Tenant == observation.TargetTenant || strings.TrimSpace(observation.ProviderActor) != "" {
		return false
	}
	return observation.Status == 401 || observation.Status == 403 || observation.Status == 404
}

func validRejectedStatusProvenance(observation CLICommandObservation) bool {
	switch observation.StatusProvenance {
	case CLIStatusFromCLIResponse:
		return observation.CompanionRequestArtifact == "" && observation.CompanionRequestSHA256 == ""
	case CLIStatusFromSameAuthHTTPS:
		return observation.CompanionRequestArtifact == observation.ResponseArtifact &&
			observation.CompanionRequestSHA256 == observation.ResponseSHA256 && digestRe.MatchString(observation.CompanionRequestSHA256)
	default:
		return false
	}
}

func cliObservationSubject(observation CLICommandObservation, mode HarnessMode) string {
	if mode == HarnessModeProviderPlane {
		return observation.ProviderActor
	}
	return observation.Tenant
}

func hasBidirectionalCLIRejections(subjects, rejections map[string]bool) bool {
	for a := range subjects {
		for b := range subjects {
			if a != b && rejections[a+"\x00"+b] && rejections[b+"\x00"+a] {
				return true
			}
		}
	}
	return false
}

func lintBrowserArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.BrowserNetwork.Artifact] != ArtifactBrowserNetwork {
		return nil
	}
	var artifact BrowserNetworkArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.BrowserNetwork.Artifact, BrowserNetworkArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	want := BrowserNetworkArtifact{
		Schema:              BrowserNetworkArtifactSchema,
		Browser:             artifact.Browser,
		LiveHTTPS:           receipt.BrowserNetwork.LiveHTTPS,
		RequestInterception: receipt.BrowserNetwork.RequestInterception,
		IgnoreHTTPSErrors:   receipt.TLS.IgnoreHTTPSErrors,
		Requests:            receipt.BrowserNetwork.Requests,
		Sessions:            artifact.Sessions,
	}
	var out []Diagnostic
	if strings.TrimSpace(artifact.Browser) == "" || artifact.IgnoreHTTPSErrors == nil || *artifact.IgnoreHTTPSErrors ||
		!reflect.DeepEqual(artifact, want) {
		out = append(out, Diagnostic{
			Code:    "artifact-summary-mismatch",
			Field:   "browser_network",
			Problem: "signed browser-network summary does not match the strict browser artifact",
		})
	}
	successfulSubjects := make(map[string]bool)
	for _, session := range artifact.Sessions {
		if successfulBrowserSession(session, receipt.HarnessScope) && containsExact(receipt.UI.Screenshots, session.Screenshot) {
			successfulSubjects[browserSessionSubject(session, receipt.HarnessScope.Mode)] = true
		}
	}
	requiredSubjects := 1
	if receipt.HarnessScope.Mode == HarnessModeTenantPlane {
		requiredSubjects = 2
	}
	if len(successfulSubjects) < requiredSubjects {
		out = append(out, Diagnostic{
			Code:    "browser-isolation-unproven",
			Field:   "browser_network.sessions",
			Problem: fmt.Sprintf("browser/API evidence must contain successful mode-appropriate credentialed sessions for %d distinct subject(s)", requiredSubjects),
		})
	}
	for _, route := range receipt.UI.Routes {
		observed := false
		for _, session := range artifact.Sessions {
			if session.Route == route && successfulBrowserSession(session, receipt.HarnessScope) {
				observed = true
				break
			}
		}
		if !observed {
			out = append(out, Diagnostic{
				Code:    "artifact-summary-mismatch",
				Field:   "ui.routes",
				Problem: fmt.Sprintf("signed UI route %q has no successful tenant-bound browser session", route),
			})
		}
	}
	for _, screenshot := range receipt.UI.Screenshots {
		observed := false
		for _, session := range artifact.Sessions {
			if session.Screenshot == screenshot && successfulBrowserSession(session, receipt.HarnessScope) {
				observed = true
				break
			}
		}
		if !observed {
			out = append(out, Diagnostic{
				Code:    "artifact-summary-mismatch",
				Field:   "ui.screenshots",
				Problem: fmt.Sprintf("signed screenshot %q is not bound to a successful tenant browser session", screenshot),
			})
		}
	}
	return out
}

func successfulBrowserSession(session BrowserSession, scope HarnessScopeEvidence) bool {
	if !validUIRoute(session.Route) || strings.TrimSpace(session.Screenshot) == "" ||
		session.Rendered == nil || !*session.Rendered || session.CredentialedLogin == nil || !*session.CredentialedLogin ||
		session.ExpectedEvidenceVisible == nil || !*session.ExpectedEvidenceVisible ||
		session.ForeignEvidenceAbsent == nil || !*session.ForeignEvidenceAbsent {
		return false
	}
	switch scope.Mode {
	case HarnessModeTenantPlane:
		return session.AuthMode == scope.BrowserAuthMode && strings.TrimSpace(session.Tenant) != "" &&
			strings.TrimSpace(session.ProviderActor) == "" && session.TenantIndicatorVisible != nil && *session.TenantIndicatorVisible &&
			session.ProviderConsoleVisible == nil && !strings.HasPrefix(session.Route, "/provider")
	case HarnessModeProviderPlane:
		return session.AuthMode == scope.BrowserAuthMode && strings.TrimSpace(session.Tenant) == "" &&
			strings.TrimSpace(session.ProviderActor) != "" &&
			(session.TenantIndicatorVisible == nil || !*session.TenantIndicatorVisible) &&
			session.ProviderConsoleVisible != nil && *session.ProviderConsoleVisible && strings.HasPrefix(session.Route, "/provider")
	default:
		return false
	}
}

func browserSessionSubject(session BrowserSession, mode HarnessMode) string {
	if mode == HarnessModeProviderPlane {
		return session.ProviderActor
	}
	return session.Tenant
}

func lintReachabilityArtifact(receipt Receipt, loader *semanticArtifactLoader, sourceRoot string) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.Reachability.Artifact] != ArtifactReachability {
		return nil
	}
	var artifact ReachabilityArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.Reachability.Artifact, ReachabilityArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	want := reachabilityArtifact(receipt, artifact.RegistrySHA256)
	if !reflect.DeepEqual(artifact, want) {
		return []Diagnostic{{
			Code:    "artifact-summary-mismatch",
			Field:   "reachability",
			Problem: "signed reachability summary does not match the strict reachability artifact",
		}}
	}
	return lintReachabilitySource(receipt, artifact, sourceRoot)
}

func lintActivationArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.Activation.Artifact] != ArtifactActivation {
		return nil
	}
	var artifact ActivationArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.Activation.Artifact, ActivationArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	want := activationArtifact(receipt)
	if !reflect.DeepEqual(artifact, want) {
		return []Diagnostic{{
			Code:    "artifact-summary-mismatch",
			Field:   "activation",
			Problem: "signed activation summary does not match the strict activation artifact",
		}}
	}
	return nil
}

func lintGovernedReviewArtifact(receipt Receipt, loader *semanticArtifactLoader, sourceRoot string) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.GovernedReview.Artifact] != ArtifactGovernedReview {
		return nil
	}
	var artifact GovernedReviewArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.GovernedReview.Artifact, GovernedReviewArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	want := governedReviewArtifact(receipt)
	if !reflect.DeepEqual(artifact, want) {
		return []Diagnostic{{
			Code: "artifact-summary-mismatch", Field: "governed_review",
			Problem: "signed governed-review summary does not match the strict review artifact",
		}}
	}
	if strings.TrimSpace(sourceRoot) == "" {
		return []Diagnostic{{Code: "review-source-unverified", Field: "governed_review", Problem: "exact source root is required for a governed review"}}
	}
	var out []Diagnostic
	protocol, protocolErr := loadGovernedReviewProtocol(sourceRoot, receipt.Item, receipt.CapabilityID)
	out = addDiagnosticIf(out, protocolErr != nil || artifact.AuthorityPath != reviewProtocolPath || artifact.AuthorityAnchor != receipt.Item ||
		!containsExact(protocol.Kinds, artifact.Kind) || !pathWithinAnyRoot(artifact.MethodologyPath, protocol.MethodologyRoots),
		"review-authority-mismatch", "governed_review.authority_path", "review must match the exact checked-in item/capability protocol and allowed methodology root")
	subjects := make(map[string]GovernedReviewSubject, len(artifact.Subjects))
	for i, subject := range artifact.Subjects {
		subjects[subject.Path] = subject
		data, readErr := readTrackedSourceFile(sourceRoot, receipt.Source.GitSHA, subject.Path, subject.GitBlobSHA, maxArtifactBytes)
		out = addDiagnosticIf(out, readErr != nil || digestBytes(data) != subject.SHA256,
			"review-source-mismatch", fmt.Sprintf("governed_review.subjects.%d", i), "reviewed subject digest does not match exact source bytes")
		out = addDiagnosticIf(out, subject.Path != reviewProtocolPath && !pathWithinAnyRoot(subject.Path, protocol.SubjectRoots),
			"review-authority-mismatch", fmt.Sprintf("governed_review.subjects.%d", i), "review subject is outside the roots authorized for this exact item/capability protocol")
	}
	methodology := subjects[artifact.MethodologyPath]
	out = addDiagnosticIf(out, methodology.Path == "", "review-source-unverified", "governed_review.methodology_path", "methodology must be one of the exact tracked reviewed subjects")
	authority := subjects[artifact.AuthorityPath]
	authorityData, authorityErr := readTrackedSourceFile(sourceRoot, receipt.Source.GitSHA, authority.Path, authority.GitBlobSHA, maxSemanticArtifactBytes)
	out = addDiagnosticIf(out, authority.Path == "" || authorityErr != nil || !bytes.Contains(authorityData, []byte(artifact.AuthorityAnchor)),
		"review-authority-mismatch", "governed_review.authority_path", "tracked authority file must contain the signed item/capability protocol anchor")
	return out
}

func loadGovernedReviewProtocol(sourceRoot, item, capabilityID string) (governedReviewProtocol, error) {
	data, err := readSourceFile(sourceRoot, reviewProtocolPath, maxSemanticArtifactBytes)
	if err != nil {
		return governedReviewProtocol{}, err
	}
	var registry deliveryAuditAuthorityRegistry
	if err := decodeStrict(data, &registry); err != nil || registry.Schema != "probectl.delivery-audit-authority/v1" {
		return governedReviewProtocol{}, fmt.Errorf("invalid governed-review protocol registry")
	}
	var matches []governedReviewProtocol
	for _, protocol := range registry.ReviewProtocols {
		if protocol.Item == item && protocol.CapabilityID == capabilityID {
			matches = append(matches, protocol)
		}
	}
	if len(matches) != 1 {
		return governedReviewProtocol{}, fmt.Errorf("no unique governed-review protocol for %s/%s", item, capabilityID)
	}
	return matches[0], nil
}

func pathWithinAnyRoot(candidate string, roots []string) bool {
	for _, root := range roots {
		if strings.HasSuffix(root, "/") && strings.HasPrefix(candidate, root) {
			return true
		}
	}
	return false
}

func lintStoreArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.Stores.Artifact] != ArtifactStoreProbes {
		return nil
	}
	var artifact StoreProbesArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.Stores.Artifact, StoreProbesArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	want := StoreProbesArtifact{
		Schema:                  StoreProbesArtifactSchema,
		ProductPipelineArtifact: receipt.Stores.ProductPipelineArtifact,
		Postgres:                receipt.Stores.Postgres,
		ClickHouse:              receipt.Stores.ClickHouse,
		Kafka:                   receipt.Stores.Kafka,
		Prometheus:              receipt.Stores.Prometheus,
		ProviderBoundary:        receipt.Stores.ProviderBoundary,
	}
	if !reflect.DeepEqual(artifact, want) {
		return []Diagnostic{{
			Code:    "artifact-summary-mismatch",
			Field:   "stores",
			Problem: "signed store-probe summary does not match the strict directional store artifact",
		}}
	}
	return nil
}

func lintTLSArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	if indexArtifactKinds(receipt.Artifacts)[receipt.TLS.Artifact] != ArtifactTLSTrust {
		return nil
	}
	var artifact TLSTrustArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.TLS.Artifact, TLSTrustArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	want := tlsTrustArtifact(receipt.TLS)
	if !reflect.DeepEqual(artifact, want) {
		return []Diagnostic{{
			Code:    "artifact-summary-mismatch",
			Field:   "tls",
			Problem: "signed TLS summary does not match the strict per-listener TLS artifact",
		}}
	}
	return lintPublicCertificateArtifacts(receipt, loader)
}

func lintPublicCertificateArtifacts(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	kinds := indexArtifactKinds(receipt.Artifacts)
	tls := receipt.TLS
	if kinds[tls.CertificateManifest] != ArtifactCertManifest || kinds[tls.CACertificate] != ArtifactPublicCert ||
		len(tls.ServiceCertificates) != len(requiredServiceInventories) {
		return []Diagnostic{{Code: "tls-certificate-invalid", Field: "tls.certificate_manifest", Problem: "TLS evidence must bind one strict public manifest, CA certificate, and six public service certificates; the OTLP HTTP listener reuses the control leaf"}}
	}
	manifestData, err := loader.read(tls.CertificateManifest)
	if err != nil {
		return nil
	}
	var manifest CertificateManifest
	if err := decodeStrict(manifestData, &manifest); err != nil || manifest.Schema != CertificateManifestSchema {
		return []Diagnostic{{Code: "tls-certificate-invalid", Field: "tls.certificate_manifest", Problem: "public certificate manifest is not strict probectl.delivery-audit-ca/v1 JSON"}}
	}
	manifestDir := path.Dir(tls.CertificateManifest)
	resolveRef := func(relative string) (string, bool) {
		if !validSourceRelativePath(relative) {
			return "", false
		}
		resolved := path.Clean(path.Join(manifestDir, relative))
		return resolved, resolved == tls.CACertificate || artifactPathInMap(resolved, tls.ServiceCertificates)
	}
	caPath, ok := resolveRef(manifest.CACertificate.Path)
	if !ok || caPath != tls.CACertificate {
		return []Diagnostic{{Code: "tls-certificate-invalid", Field: "tls.ca_certificate", Problem: "manifest CA path is not the signed public CA artifact"}}
	}
	caPEM, err := loader.read(caPath)
	if err != nil {
		return nil
	}
	ca, err := probcrypto.InspectPublicCertificatePEM(caPEM)
	if err != nil {
		return []Diagnostic{{Code: "tls-certificate-invalid", Field: "tls.ca_certificate", Problem: err.Error()}}
	}
	var out []Diagnostic
	out = addDiagnosticIf(out, !ca.IsCA || manifest.CACertificate.SHA256 != digestBytes(caPEM) ||
		tls.CAFingerprint != "sha256:"+ca.FingerprintSHA256 || !tls.CANotBefore.Equal(ca.NotBefore) || !tls.CANotAfter.Equal(ca.NotAfter) ||
		!manifest.ValidFrom.Equal(ca.NotBefore) || !manifest.ExpiresAt.Equal(ca.NotAfter) ||
		manifest.TTLSeconds <= 0 || manifest.TTLSeconds > int64(MaxDisposableCATTL/time.Second),
		"tls-certificate-invalid", "tls.ca_certificate", "CA PEM digest, DER fingerprint, validity, CA flag, and manifest summary must agree exactly")
	manifestServices := make(map[string]ServiceCertificate, len(manifest.Services))
	leafFingerprints := make(map[string]string, len(manifest.Services))
	for _, service := range manifest.Services {
		if _, duplicate := manifestServices[service.Name]; duplicate {
			out = append(out, Diagnostic{Code: "tls-certificate-invalid", Field: "tls.certificate_manifest", Problem: "certificate manifest contains a duplicate service"})
		}
		manifestServices[service.Name] = service
	}
	for _, spec := range disposableServiceCertificates {
		service, exists := manifestServices[spec.name]
		signedPath, signed := tls.ServiceCertificates[spec.name]
		resolved, refOK := resolveRef(service.Certificate.Path)
		if !exists || !signed || !refOK || resolved != signedPath || kinds[signedPath] != ArtifactPublicCert {
			out = append(out, Diagnostic{Code: "tls-certificate-invalid", Field: "tls.service_certificates." + spec.name, Problem: "service leaf path is missing or not bound by the public manifest"})
			continue
		}
		leafPEM, readErr := loader.read(signedPath)
		leaf, parseErr := probcrypto.InspectPublicCertificatePEM(leafPEM)
		out = addDiagnosticIf(out, readErr != nil || parseErr != nil || service.Certificate.SHA256 != digestBytes(leafPEM),
			"tls-certificate-invalid", "tls.service_certificates."+spec.name, "service certificate PEM cannot be parsed or does not match its manifest digest")
		if readErr != nil || parseErr != nil {
			continue
		}
		leafFingerprints[spec.name] = "sha256:" + leaf.FingerprintSHA256
		out = addDiagnosticIf(out, leaf.IsCA || probcrypto.VerifyPublicCertificateIssuedByPEM(leafPEM, caPEM) != nil || !equalStringSets(service.Hosts, spec.hosts) ||
			!equalStringSets(leaf.Hosts, spec.hosts) || leaf.NotBefore.Before(ca.NotBefore) || leaf.NotAfter.After(ca.NotAfter) ||
			!certificateCoversReceipt(leaf.NotBefore, leaf.NotAfter, receipt.StartedAt, receipt.CompletedAt),
			"tls-certificate-invalid", "tls.service_certificates."+spec.name, "service leaf must chain to the signed CA, match the exact named SAN inventory, and remain valid across the complete receipt window")
	}
	for _, listener := range requiredTLSListeners {
		service := listener
		if listener == "otlp_http" {
			service = "control"
		}
		probe, probeExists := tls.Listeners[listener]
		expected, leafExists := leafFingerprints[service]
		out = addDiagnosticIf(out, !probeExists || !leafExists || probe.CertificateService != service || probe.PeerCertificateSHA256 != expected,
			"tls-certificate-invalid", "tls.listeners."+listener+".peer_certificate_sha256",
			"observed peer certificate fingerprint must match the parsed DER SHA-256 of the exact declared service leaf")
	}
	out = addDiagnosticIf(out, len(manifestServices) != len(requiredServiceInventories),
		"tls-certificate-invalid", "tls.certificate_manifest", "certificate manifest must contain exactly the six required service leaves")
	return out
}

func certificateCoversReceipt(notBefore, notAfter, startedAt, completedAt time.Time) bool {
	return !notBefore.After(startedAt) && notAfter.After(completedAt)
}

func artifactPathInMap(want string, paths map[string]string) bool {
	for _, candidate := range paths {
		if candidate == want {
			return true
		}
	}
	return false
}

func equalStringSets(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}

func decodeSemanticJSON(loader *semanticArtifactLoader, path, schema string, target any) *Diagnostic {
	data, err := loader.read(path)
	if err != nil {
		return nil // lintArtifactMarkers already reports the bounded read failure.
	}
	if len(data) > maxSemanticArtifactBytes {
		return &Diagnostic{
			Code:    "artifact-invalid",
			Field:   "artifacts." + path,
			Problem: fmt.Sprintf("strict JSON artifact exceeds %d-byte limit", maxSemanticArtifactBytes),
		}
	}
	if err := decodeStrict(data, target); err != nil {
		return &Diagnostic{
			Code:    "artifact-invalid",
			Field:   "artifacts." + path,
			Problem: fmt.Sprintf("strict JSON evidence is invalid: %v", err),
		}
	}
	var got string
	switch value := target.(type) {
	case *BrowserNetworkArtifact:
		got = value.Schema
	case *CLITranscriptArtifact:
		got = value.Schema
	case *ReachabilityArtifact:
		got = value.Schema
	case *ActivationArtifact:
		got = value.Schema
	case *StoreProbesArtifact:
		got = value.Schema
	case *ProductPipelineArtifact:
		got = value.Schema
	case *StackInventoryArtifact:
		got = value.Schema
	case *TLSTrustArtifact:
		got = value.Schema
	case *GovernedReviewArtifact:
		got = value.Schema
	default:
		return &Diagnostic{Code: "artifact-invalid", Field: "artifacts." + path, Problem: "unsupported semantic artifact type"}
	}
	if got != schema {
		return &Diagnostic{
			Code:    "artifact-invalid",
			Field:   "artifacts." + path,
			Problem: fmt.Sprintf("artifact schema %q does not match required %q", got, schema),
		}
	}
	return nil
}

func reachabilityArtifact(receipt Receipt, registrySHA256 string) ReachabilityArtifact {
	evidence := receipt.Reachability
	return ReachabilityArtifact{
		Schema:                ReachabilityArtifactSchema,
		SourceGitSHA:          receipt.Source.GitSHA,
		SourceTreeSHA:         receipt.Source.TreeSHA,
		CapabilityID:          receipt.CapabilityID,
		RegistryPath:          "capabilities.yaml",
		RegistrySHA256:        registrySHA256,
		StaticGate:            "internal/completeness.Validator",
		ValidatorPassed:       boolPointer(true),
		BinaryEntrypoint:      evidence.BinaryEntrypoint,
		DefaultBuildCommand:   evidence.DefaultBuildCommand,
		DefaultBuildReachable: evidence.DefaultBuildReachable,
		API:                   evidence.API,
		CLIOperation:          evidence.CLIOperation,
		UIRoute:               evidence.UIRoute,
		DocsPath:              evidence.DocsPath,
		ObservedInRelease:     boolPointer(true),
	}
}

func boolPointer(value bool) *bool { return &value }

func int64Pointer(value int64) *int64 { return &value }

func activationArtifact(receipt Receipt) ActivationArtifact {
	evidence := receipt.Activation
	return ActivationArtifact{
		Schema:                     ActivationArtifactSchema,
		EnabledByDefault:           evidence.EnabledByDefault,
		RuntimeActive:              evidence.RuntimeActive,
		EnableCLICommand:           evidence.EnableCLICommand,
		EnableUIRoute:              evidence.EnableUIRoute,
		DocsPath:                   evidence.DocsPath,
		LicenseTier:                evidence.LicenseTier,
		LicenseState:               evidence.LicenseState,
		ProviderFeatureEnabled:     evidence.ProviderFeatureEnabled,
		ProviderLicenseObservation: evidence.ProviderLicenseObservation,
		BuildTags:                  evidence.BuildTags,
		ReleaseGoTags:              evidence.BuildTags,
		DevAuth:                    receipt.Build.DevAuth,
	}
}

func governedReviewArtifact(receipt Receipt) GovernedReviewArtifact {
	review := receipt.GovernedReview
	return GovernedReviewArtifact{
		Schema: GovernedReviewArtifactSchema, SourceGitSHA: receipt.Source.GitSHA, SourceTreeSHA: receipt.Source.TreeSHA,
		Item: receipt.Item, CapabilityID: receipt.CapabilityID, ReviewID: receipt.HumanPath.ID, Kind: review.Kind,
		AuthorityPath: review.AuthorityPath, AuthorityAnchor: review.AuthorityAnchor, MethodologyPath: review.MethodologyPath,
		Subjects: review.Subjects, Checks: review.Checks, Conclusion: review.Conclusion,
	}
}

func tlsTrustArtifact(evidence TLSEvidence) TLSTrustArtifact {
	return TLSTrustArtifact{
		Schema:                   TLSTrustArtifactSchema,
		CAFingerprint:            evidence.CAFingerprint,
		CANotBefore:              evidence.CANotBefore,
		CANotAfter:               evidence.CANotAfter,
		BrowserRejectedWithoutCA: evidence.BrowserRejectedWithoutCA,
		BrowserTrustedWithCA:     evidence.BrowserTrustedWithCA,
		BrowserPretrustFailure:   evidence.BrowserPretrustFailure,
		IgnoreHTTPSErrors:        evidence.IgnoreHTTPSErrors,
		Listeners:                evidence.Listeners,
		CertificateManifest:      evidence.CertificateManifest,
		CACertificate:            evidence.CACertificate,
		ServiceCertificates:      evidence.ServiceCertificates,
	}
}

func containsForbiddenArtifactMarker(data []byte) bool {
	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "selftest:") || strings.Contains(lower, "fixture-only") ||
		strings.Contains(lower, "test-only") || strings.Contains(lower, "test_only") ||
		strings.Contains(lower, "testdata") || strings.Contains(lower, "httptest") ||
		strings.Contains(lower, "route.fulfill") || strings.Contains(lower, "probectl_web_fixtures") {
		return true
	}
	return mockRe.MatchString(lower)
}

func sortAndDedupeDiagnostics(diagnostics []Diagnostic) []Diagnostic {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		if diagnostics[i].Code != diagnostics[j].Code {
			return diagnostics[i].Code < diagnostics[j].Code
		}
		if diagnostics[i].Field != diagnostics[j].Field {
			return diagnostics[i].Field < diagnostics[j].Field
		}
		return diagnostics[i].Problem < diagnostics[j].Problem
	})
	if len(diagnostics) < 2 {
		return diagnostics
	}
	out := diagnostics[:1]
	for _, diagnostic := range diagnostics[1:] {
		last := out[len(out)-1]
		if diagnostic != last {
			out = append(out, diagnostic)
		}
	}
	return out
}
