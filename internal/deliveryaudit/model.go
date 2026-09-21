// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package deliveryaudit defines the signed, offline-verifiable receipt used by
// the completeness loop's independent delivery audit. A receipt binds one
// capability to one exact source revision and to the concrete CLI, rendered
// browser, TLS, and real-store artifacts produced by the audit run.
package deliveryaudit

import (
	"encoding/json"
	"time"
)

const (
	// ReceiptSchema is the versioned contract for the signed manifest.
	ReceiptSchema = "probectl.delivery-audit-receipt/v1"
	// EnvelopeSchema is the versioned contract for the signature wrapper.
	EnvelopeSchema = "probectl.delivery-audit-envelope/v1"
	// CertificateManifestSchema is the non-secret inventory written beside a
	// disposable audit CA and its named service leaves.
	CertificateManifestSchema = "probectl.delivery-audit-ca/v1"
	// BrowserNetworkArtifactSchema identifies the strict JSON browser trace
	// whose observations are summarized in BrowserNetworkEvidence.
	BrowserNetworkArtifactSchema = "probectl.delivery-audit-browser-network/v1"
	// CLITranscriptArtifactSchema identifies the strict structured release-CLI
	// transcript whose API observations are separate from browser traffic.
	CLITranscriptArtifactSchema = "probectl.delivery-audit-cli-transcript/v1"
	// ReachabilityArtifactSchema identifies the strict static reachability JSON
	// whose observations are summarized in ReachabilityEvidence.
	ReachabilityArtifactSchema = "probectl.delivery-audit-static-reachability/v1"
	// StackInventoryArtifactSchema identifies the strict real-service inventory
	// used to reject placeholder or partial audit stacks.
	StackInventoryArtifactSchema = "probectl.delivery-audit-stack/v1"
	// ActivationArtifactSchema identifies the strict runtime activation JSON
	// whose observations are summarized in ActivationEvidence.
	ActivationArtifactSchema = "probectl.delivery-audit-activation/v1"
	// StoreProbesArtifactSchema identifies the strict directional real-store
	// isolation JSON whose observations are summarized in StoreEvidence.
	StoreProbesArtifactSchema = "probectl.delivery-audit-store-probes/v1"
	// ProductPipelineArtifactSchema identifies exact, correlated release-product
	// OTLP -> Kafka -> Prometheus/ClickHouse round trips. Direct store probes by
	// themselves are never sufficient to prove that the shipped control plane
	// is actually wired to those stores.
	ProductPipelineArtifactSchema = "probectl.delivery-audit-product-pipeline/v1"
	// KafkaGroupOffsetArtifactSchema binds the release consumer group's actual
	// broker-admin committed-offset row to a product record.
	KafkaGroupOffsetArtifactSchema = "probectl.delivery-audit-kafka-group-offset/v1"
	// ClickHouseIsolationArtifactSchema binds predicate-free product-table
	// reads under tenant A, tenant B, and no setting to the actual release
	// reader policy rather than an audit-only table.
	ClickHouseIsolationArtifactSchema = "probectl.delivery-audit-clickhouse-isolation/v1"
	// TLSTrustArtifactSchema identifies the strict per-listener TLS JSON whose
	// observations are summarized in TLSEvidence.
	TLSTrustArtifactSchema = "probectl.delivery-audit-tls-trust/v1"
	// GovernedReviewArtifactSchema identifies the non-runtime review profile.
	GovernedReviewArtifactSchema = "probectl.delivery-audit-governed-review/v1"
	// LinterOutputArtifactSchema binds the planted negative control to VERIFIED evidence.
	LinterOutputArtifactSchema = "probectl.delivery-audit-linter-output/v1"
	// SignatureAlgorithm is the only supported receipt signature algorithm.
	SignatureAlgorithm = "Ed25519"
)

// HarnessMode identifies the privilege plane exercised by one receipt. One
// receipt proves one governed human path; it is not a claim that every path in
// the capability registry was exercised dynamically.
type HarnessMode string

const (
	HarnessModeTenantPlane    HarnessMode = "tenant_plane"
	HarnessModeProviderPlane  HarnessMode = "provider_plane"
	HarnessModeGovernedReview HarnessMode = "governed_review"
)

// HarnessAuthMode names the real session mechanism used by the audited path.
// The provider plane deliberately does not reuse tenant OIDC or dev-auth.
type HarnessAuthMode string

const (
	HarnessAuthTenantOIDC            HarnessAuthMode = "tenant_oidc"
	HarnessAuthTenantMCPBearer       HarnessAuthMode = "tenant_mcp_bearer"
	HarnessAuthProviderSession       HarnessAuthMode = "provider_session"
	HarnessAuthProviderSessionBearer HarnessAuthMode = "provider_session_bearer"
	HarnessAuthNotApplicable         HarnessAuthMode = "not_applicable"
)

// HarnessDriverKind distinguishes the fixed built-in path from an extension
// whose bytes must be resolved in the exact source tree before promotion.
type HarnessDriverKind string

const (
	HarnessDriverBuiltin       HarnessDriverKind = "builtin"
	HarnessDriverSourceBound   HarnessDriverKind = "source_bound"
	HarnessDriverNotApplicable HarnessDriverKind = "not_applicable"
)

const (
	TLSAuthModelProtected  = "protected"
	TLSAuthModelPublicOIDC = "public_oidc"
)

const (
	HumanPathClassExecutableEndUser = "executable_end_user"
	HumanPathClassGovernedReview    = "governed_artifact_review"
	HumanPathCoverageGovernedPath   = "one_governed_end_user_path"
	HumanPathCoverageGovernedReview = "one_governed_artifact_review"
)

// Outcome is the auditor's conclusion. FAILED receipts remain signed and
// verifiable, but can never promote a backlog item.
type Outcome string

const (
	OutcomeVerified Outcome = "VERIFIED"
	OutcomeFailed   Outcome = "FAILED"
)

// ArtifactKind gives every attachment a machine-checkable purpose. The
// receipt signs metadata and hashes; artifact bytes stay beside the receipt so
// screenshots and transcripts remain easy for a human to inspect.
type ArtifactKind string

const (
	ArtifactCLITranscript          ArtifactKind = "cli_transcript"
	ArtifactUIScreenshot           ArtifactKind = "ui_screenshot"
	ArtifactBrowserNetwork         ArtifactKind = "browser_network"
	ArtifactStoreProbes            ArtifactKind = "store_probes"
	ArtifactTLSTrust               ArtifactKind = "tls_trust"
	ArtifactStackInventory         ArtifactKind = "stack_inventory"
	ArtifactLinterOutput           ArtifactKind = "linter_output"
	ArtifactReachability           ArtifactKind = "static_reachability"
	ArtifactActivation             ArtifactKind = "activation_proof"
	ArtifactGovernedReview         ArtifactKind = "governed_review"
	ArtifactCertManifest           ArtifactKind = "certificate_manifest"
	ArtifactPublicCert             ArtifactKind = "public_certificate"
	ArtifactNegativeReceipt        ArtifactKind = "negative_receipt"
	ArtifactNegativeFixture        ArtifactKind = "negative_fixture"
	ArtifactCLIOutput              ArtifactKind = "cli_output"
	ArtifactAPIObservation         ArtifactKind = "api_observation"
	ArtifactProductPipeline        ArtifactKind = "product_pipeline"
	ArtifactOTLPRequest            ArtifactKind = "otlp_request"
	ArtifactOTLPResponse           ArtifactKind = "otlp_response"
	ArtifactKafkaKey               ArtifactKind = "kafka_key"
	ArtifactKafkaPayload           ArtifactKind = "kafka_payload"
	ArtifactStoreObservation       ArtifactKind = "store_observation"
	ArtifactPipelineCounters       ArtifactKind = "pipeline_counters"
	ArtifactKafkaGroupOffset       ArtifactKind = "kafka_group_offset"
	ArtifactKafkaGroupRaw          ArtifactKind = "kafka_group_offset_raw"
	ArtifactClickHouseIsolation    ArtifactKind = "clickhouse_isolation"
	ArtifactClickHouseIsolationRaw ArtifactKind = "clickhouse_isolation_raw"
	ArtifactOther                  ArtifactKind = "other"
)

// Receipt is the exact JSON document covered by the detached signature in an
// Envelope. Pointer booleans make security-sensitive yes/no claims explicit:
// omitted is different from false and is rejected for VERIFIED evidence.
type Receipt struct {
	Schema          string                 `json:"schema"`
	ReceiptID       string                 `json:"receipt_id"`
	Item            string                 `json:"item"`
	CapabilityID    string                 `json:"capability_id"`
	Status          Outcome                `json:"status"`
	StartedAt       time.Time              `json:"started_at"`
	CompletedAt     time.Time              `json:"completed_at"`
	Source          Source                 `json:"source"`
	Build           BuildEvidence          `json:"build"`
	Auditor         AuditorEvidence        `json:"auditor"`
	HarnessScope    HarnessScopeEvidence   `json:"harness_scope"`
	HumanPath       HumanPathEvidence      `json:"human_path"`
	CLI             CLIEvidence            `json:"cli"`
	UI              UIEvidence             `json:"ui"`
	BrowserNetwork  BrowserNetworkEvidence `json:"browser_network"`
	Reachability    ReachabilityEvidence   `json:"reachability"`
	Activation      ActivationEvidence     `json:"activation"`
	Stores          StoreEvidence          `json:"stores"`
	TLS             TLSEvidence            `json:"tls"`
	EvidenceSources EvidenceSources        `json:"evidence_sources"`
	GovernedReview  GovernedReviewEvidence `json:"governed_review"`
	Artifacts       []Artifact             `json:"artifacts"`
	FailureReasons  []string               `json:"failure_reasons,omitempty"`
}

type Source struct {
	GitSHA  string `json:"git_sha"`
	TreeSHA string `json:"tree_sha"`
	Dirty   *bool  `json:"dirty"`
}

type BuildEvidence struct {
	ControlCommit  string `json:"control_commit"`
	CLICommit      string `json:"cli_commit"`
	ControlImageID string `json:"control_image_id"`
	CLISHA256      string `json:"cli_sha256"`
	DevAuth        *bool  `json:"dev_auth"`
	PlaceholderUI  *bool  `json:"placeholder_ui"`
}

type AuditorEvidence struct {
	Agent                         string `json:"agent"`
	ImplementationOwner           string `json:"implementation_owner"`
	IndependentFromImplementation *bool  `json:"independent_from_implementation"`
}

// HarnessScopeEvidence prevents a tenant-plane audit from being presented as
// proof of provider-plane compatibility.
type HarnessScopeEvidence struct {
	Mode                           HarnessMode           `json:"mode"`
	BrowserAuthMode                HarnessAuthMode       `json:"browser_auth_mode"`
	CLIAuthMode                    HarnessAuthMode       `json:"cli_auth_mode"`
	ProviderCompatibilityValidated *bool                 `json:"provider_compatibility_validated"`
	CapabilityDriver               HarnessDriverEvidence `json:"capability_driver"`
	BrowserDriver                  HarnessDriverEvidence `json:"browser_driver"`
}

// HarnessDriverEvidence binds extension code to a regular file in the exact
// audited source tree. Built-in drivers use a stable logical runtime_path and
// leave source_path/sha256 empty; provider/custom drivers are source_bound.
type HarnessDriverEvidence struct {
	Kind        HarnessDriverKind `json:"kind"`
	RuntimePath string            `json:"runtime_path"`
	SourcePath  string            `json:"source_path,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	GitBlobSHA  string            `json:"git_blob_sha,omitempty"`
}

type HumanPathEvidence struct {
	ID         string `json:"id"`
	PathClass  string `json:"path_class"`
	Coverage   string `json:"coverage"`
	Reproduced *bool  `json:"reproduced_as_human_path"`
	Summary    string `json:"summary"`
}

type CLIEvidence struct {
	Transcript string   `json:"transcript"`
	Commands   []string `json:"commands"`
}

type UIEvidence struct {
	Screenshots []string `json:"screenshots"`
	Routes      []string `json:"routes"`
}

type BrowserRequest struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
}

type BrowserNetworkEvidence struct {
	Artifact            string           `json:"artifact"`
	Requests            []BrowserRequest `json:"requests"`
	LiveHTTPS           *bool            `json:"live_https"`
	RequestInterception *bool            `json:"request_interception"`
}

// ReachabilityEvidence binds the runtime observations to a static reachability
// report for the default release build. The artifact is required so these
// fields cannot promote a receipt as unsupported self-assertions.
type ReachabilityEvidence struct {
	Artifact              string          `json:"artifact"`
	BinaryEntrypoint      string          `json:"binary_entrypoint"`
	DefaultBuildCommand   string          `json:"default_build_command"`
	DefaultBuildReachable *bool           `json:"default_build_reachable"`
	API                   APIReachability `json:"api"`
	CLIOperation          string          `json:"cli_operation"`
	UIRoute               string          `json:"ui_route"`
	DocsPath              string          `json:"docs_path"`
}

type APIReachability struct {
	OperationID string `json:"operation_id"`
	Method      string `json:"method"`
	Path        string `json:"path"`
}

// ActivationEvidence proves how the audited release path became active. A
// default-off feature must name the exact CLI, UI, and documentation path used
// to enable it, plus the observed license/build-tag state. The hashed artifact
// records that observation independently of these summary fields.
type ActivationEvidence struct {
	Artifact                   string                      `json:"artifact"`
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
}

// ProviderLicenseObservation binds provider promotion to a live authenticated
// read of public license posture. No private key or license secret belongs in
// this structure.
type ProviderLicenseObservation struct {
	LiveAuthenticated      *bool  `json:"live_authenticated"`
	Method                 string `json:"method"`
	Path                   string `json:"path"`
	Status                 int    `json:"status"`
	LicenseSHA256          string `json:"license_sha256"`
	SigningKeyFingerprint  string `json:"signing_key_fingerprint"`
	ProviderFeatureEnabled *bool  `json:"provider_feature_enabled"`
}

type StoreEvidence struct {
	Artifact                string                   `json:"artifact"`
	ProductPipelineArtifact string                   `json:"product_pipeline_artifact"`
	Postgres                PostgresIsolationProbe   `json:"postgres"`
	ClickHouse              ClickHouseIsolationProbe `json:"clickhouse"`
	Kafka                   KafkaIntegrityProbe      `json:"kafka"`
	Prometheus              PrometheusIntegrityProbe `json:"prometheus"`
	ProviderBoundary        ProviderBoundaryProbe    `json:"provider_boundary"`
}

const (
	PostgresProofKind         = "postgres_bidirectional_rls_query_isolation"
	ClickHouseProofKind       = "clickhouse_product_otel_setting_scoped_reader_isolation"
	KafkaProofKind            = "kafka_authenticated_sasl_ssl_tenant_tag_integrity"
	PrometheusProofKind       = "prometheus_authenticated_tls_tenant_label_integrity"
	ProviderBoundaryProofKind = "provider_role_metadata_allow_raw_telemetry_deny_separate_audit"
)

// PostgresIsolationProbe proves real storage/query-layer RLS in both
// directions. Positive seed and own-visible counts make a zero cross-tenant
// result non-vacuous.
type PostgresIsolationProbe struct {
	ProofKind             string `json:"proof_kind"`
	TenantA               string `json:"tenant_a"`
	TenantB               string `json:"tenant_b"`
	SeededTenantARows     *int64 `json:"seeded_tenant_a_rows"`
	SeededTenantBRows     *int64 `json:"seeded_tenant_b_rows"`
	TenantAOwnVisibleRows *int64 `json:"tenant_a_own_visible_rows"`
	TenantBOwnVisibleRows *int64 `json:"tenant_b_own_visible_rows"`
	TenantAToBVisibleRows *int64 `json:"tenant_a_to_b_visible_rows"`
	TenantBToAVisibleRows *int64 `json:"tenant_b_to_a_visible_rows"`
	Detail                string `json:"detail"`
}

// ClickHouseIsolationProbe proves two distinct database users are constrained
// by tenant row policies in both directions.
type ClickHouseIsolationProbe struct {
	ProofKind                string `json:"proof_kind"`
	ProductPathConfigured    *bool  `json:"product_path_configured"`
	ControlRoundTripObserved *bool  `json:"control_round_trip_observed"`
	Database                 string `json:"database"`
	Table                    string `json:"table"`
	ReaderUser               string `json:"reader_user"`
	TenantSetting            string `json:"tenant_setting"`
	ReaderPolicyObserved     *bool  `json:"reader_policy_observed"`
	TenantA                  string `json:"tenant_a"`
	TenantB                  string `json:"tenant_b"`
	SeededTenantARows        *int64 `json:"seeded_tenant_a_rows"`
	SeededTenantBRows        *int64 `json:"seeded_tenant_b_rows"`
	TenantAOwnVisibleRows    *int64 `json:"tenant_a_own_visible_rows"`
	TenantBOwnVisibleRows    *int64 `json:"tenant_b_own_visible_rows"`
	TenantAToBVisibleRows    *int64 `json:"tenant_a_to_b_visible_rows"`
	TenantBToAVisibleRows    *int64 `json:"tenant_b_to_a_visible_rows"`
	UnsetVisibleRows         *int64 `json:"unset_visible_rows"`
	Detail                   string `json:"detail"`
}

// KafkaIntegrityProbe intentionally proves transport/authentication and
// tenant-tag integrity, not per-tenant reader isolation. The latter is not a
// property of the audited shared product path and must be explicitly false.
type KafkaIntegrityProbe struct {
	ProofKind                   string `json:"proof_kind"`
	SecurityProtocol            string `json:"security_protocol"`
	AuthenticationMechanism     string `json:"authentication_mechanism"`
	ControlConfiguredForBroker  *bool  `json:"control_configured_for_broker"`
	ControlConnectivityProven   *bool  `json:"control_connectivity_proven"`
	AuthenticatedManualTagProbe *bool  `json:"authenticated_manual_tag_probe"`
	TLSVerified                 *bool  `json:"tls_verified"`
	SASLAuthenticated           *bool  `json:"sasl_authenticated"`
	TenantA                     string `json:"tenant_a"`
	TenantB                     string `json:"tenant_b"`
	ObservedTenantAMessages     *int64 `json:"observed_tenant_a_messages"`
	ObservedTenantBMessages     *int64 `json:"observed_tenant_b_messages"`
	MissingTenantTagMessages    *int64 `json:"missing_tenant_tag_messages"`
	MismatchedTenantTagMessages *int64 `json:"mismatched_tenant_tag_messages"`
	ProductMessagesObserved     *bool  `json:"product_emitted_messages_observed"`
	ObservedProductMessages     *int64 `json:"observed_product_messages"`
	ReaderIsolationClaimed      *bool  `json:"reader_isolation_claimed"`
	Detail                      string `json:"detail"`
}

// PrometheusIntegrityProbe intentionally proves direct authenticated TLS and
// non-vacuous tenant-label integrity, not tenant query isolation.
type PrometheusIntegrityProbe struct {
	ProofKind                   string `json:"proof_kind"`
	ProductPathConfigured       *bool  `json:"product_path_configured"`
	ControlRoundTripObserved    *bool  `json:"control_round_trip_observed"`
	DirectQuery                 *bool  `json:"direct_query"`
	UnfilteredSeriesQuery       *bool  `json:"unfiltered_series_query"`
	TLSVerified                 *bool  `json:"tls_verified"`
	Authenticated               *bool  `json:"authenticated"`
	TenantA                     string `json:"tenant_a"`
	TenantB                     string `json:"tenant_b"`
	ObservedTenantASeries       *int64 `json:"observed_tenant_a_series"`
	ObservedTenantBSeries       *int64 `json:"observed_tenant_b_series"`
	TotalObservedSeries         *int64 `json:"total_observed_series"`
	ExpectedTenantLabeledSeries *int64 `json:"expected_tenant_labeled_series"`
	MissingTenantLabelSeries    *int64 `json:"missing_tenant_label_series"`
	MismatchedTenantLabelSeries *int64 `json:"mismatched_tenant_label_series"`
	IsolationClaimed            *bool  `json:"isolation_claimed"`
	Detail                      string `json:"detail"`
}

// ProviderBoundaryProbe proves a provider operator can read lifecycle and
// aggregate metadata while raw tenant telemetry remains inaccessible and the
// action lands only in the separate provider audit stream.
type ProviderBoundaryProbe struct {
	ProofKind                           string `json:"proof_kind"`
	ProviderActor                       string `json:"provider_actor"`
	TenantA                             string `json:"tenant_a"`
	TenantB                             string `json:"tenant_b"`
	LifecycleMetadataRows               *int64 `json:"lifecycle_metadata_rows"`
	AggregateMetadataRows               *int64 `json:"aggregate_metadata_rows"`
	PostgresRawTelemetrySeededRows      *int64 `json:"postgres_raw_telemetry_seeded_rows"`
	PostgresRawTelemetryAccessDenied    *bool  `json:"postgres_raw_telemetry_access_denied"`
	ClickHouseRawTelemetrySeededRows    *int64 `json:"clickhouse_raw_telemetry_seeded_rows"`
	ClickHouseRawTelemetryAccessDenied  *bool  `json:"clickhouse_raw_telemetry_access_denied"`
	KafkaTenantPayloadSeededMessages    *int64 `json:"kafka_tenant_payload_seeded_messages"`
	KafkaTenantPayloadAccessDenied      *bool  `json:"kafka_tenant_payload_access_denied"`
	PrometheusRawTelemetrySeededSeries  *int64 `json:"prometheus_raw_telemetry_seeded_series"`
	PrometheusRawTelemetryAccessDenied  *bool  `json:"prometheus_raw_telemetry_access_denied"`
	ImplicitTenantReadGranted           *bool  `json:"implicit_tenant_read_granted"`
	ProviderAuditEventsObserved         *int64 `json:"provider_audit_events_observed"`
	TenantAuditEventsFromProviderAction *int64 `json:"tenant_audit_events_from_provider_action"`
	Detail                              string `json:"detail"`
}

type TLSEvidence struct {
	Artifact                 string                      `json:"artifact"`
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

type BrowserPretrustFailure struct {
	Browser          string `json:"browser"`
	URL              string `json:"url"`
	ErrorClass       string `json:"error_class"`
	SanitizedMessage string `json:"sanitized_message"`
	Rejected         *bool  `json:"rejected"`
}

// TLSListenerProbe records protocol-aware positive and negative checks for one
// required audit listener. Protected listeners reject unauthenticated access.
// Dex is different: OIDC metadata and authorization are intentionally public,
// so it proves public metadata, malformed-request rejection, and a real
// credentialed browser login without making a false unauthenticated claim.
type TLSListenerProbe struct {
	AuthModel                      string `json:"auth_model"`
	CertificateService             string `json:"certificate_service"`
	PeerCertificateSHA256          string `json:"peer_certificate_sha256"`
	TrustedTLS                     *bool  `json:"trusted_tls"`
	PlaintextRejected              *bool  `json:"plaintext_rejected"`
	UnauthenticatedRejected        *bool  `json:"unauthenticated_rejected,omitempty"`
	InvalidAuthenticationRejected  *bool  `json:"invalid_authentication_rejected,omitempty"`
	MetadataPublic                 *bool  `json:"metadata_public,omitempty"`
	MalformedAuthorizationRejected *bool  `json:"malformed_authorization_rejected,omitempty"`
	RealCredentialedLoginSucceeded *bool  `json:"real_credentialed_login_succeeded,omitempty"`
}

const (
	GovernedReviewKindArtifact    = "artifact"
	GovernedReviewKindMethodology = "methodology"
	GovernedReviewKindLegal       = "legal"
	GovernedReviewKindRelease     = "release"
	GovernedReviewConclusionPass  = "passed"
	GovernedReviewCheckPass       = "passed"
)

// GovernedReviewEvidence is the non-runtime receipt profile for a source- and
// artifact-bound methodology, legal, release, or other governed review. It is
// intentionally disjoint from executable API/CLI/UI/store proof.
type GovernedReviewEvidence struct {
	Artifact        string                  `json:"artifact"`
	Kind            string                  `json:"kind"`
	AuthorityPath   string                  `json:"authority_path"`
	AuthorityAnchor string                  `json:"authority_anchor"`
	MethodologyPath string                  `json:"methodology_path"`
	Subjects        []GovernedReviewSubject `json:"subjects"`
	Checks          []GovernedReviewCheck   `json:"checks"`
	Conclusion      string                  `json:"conclusion"`
}

type GovernedReviewSubject struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	GitBlobSHA string `json:"git_blob_sha"`
}

type GovernedReviewCheck struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

type EvidenceSources struct {
	Fixture  *bool `json:"fixture"`
	Mock     *bool `json:"mock"`
	TestData *bool `json:"testdata"`
}

type Artifact struct {
	Path   string       `json:"path"`
	Kind   ArtifactKind `json:"kind"`
	Bytes  int64        `json:"bytes"`
	SHA256 string       `json:"sha256"`
}

// Signing describes the public half and detached signature. The private key
// never enters either the receipt or an evidence artifact.
type Signing struct {
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key_pem"`
	Fingerprint string `json:"public_key_fingerprint"`
	Signature   []byte `json:"signature"`
}

// Envelope preserves the receipt as raw JSON so verification checks the exact
// bytes the auditor signed.
type Envelope struct {
	Schema  string          `json:"schema"`
	Receipt json.RawMessage `json:"receipt"`
	Signing Signing         `json:"signing"`
}

// CertificateManifest intentionally inventories only public certificates.
// Named private-key paths and private-key bytes are deliberately absent.
type CertificateManifest struct {
	Schema        string               `json:"schema"`
	GeneratedAt   time.Time            `json:"generated_at"`
	ValidFrom     time.Time            `json:"valid_from"`
	ExpiresAt     time.Time            `json:"expires_at"`
	TTLSeconds    int64                `json:"ttl_seconds"`
	CACertificate CertificateReference `json:"ca_certificate"`
	Services      []ServiceCertificate `json:"services"`
}

type CertificateReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ServiceCertificate struct {
	Name        string               `json:"name"`
	Hosts       []string             `json:"hosts"`
	Certificate CertificateReference `json:"certificate"`
}
