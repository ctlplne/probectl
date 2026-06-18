// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package config loads and validates the probectl control-plane configuration
// from PROBECTL_-prefixed environment variables. Every key is documented in
// docs/configuration.md (CLAUDE.md §6). Load reports all validation problems at
// once so a misconfiguration is fixed in a single pass.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Config is the fully resolved, validated control-plane configuration.
type Config struct {
	// HTTP server.
	HTTPAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Database.
	DatabaseURL         string
	DatabaseReadURL     string // optional read-replica endpoint (S-EE2); empty = reads use the writer
	DatabaseMaxConns    int32
	DatabaseMinConns    int32
	DatabaseConnTimeout time.Duration

	// Multi-region / HA (S-EE2). All optional; a single-region deployment
	// leaves Region empty and the cluster layer is inert (writes always
	// allowed). Region is THIS replica's region; Regions is the full set.
	Region          string
	Regions         []string
	Residency       string  // default data-residency region (governance)
	ReplicationMode string  // sync | async (descriptive; sets achievable RPO)
	RPOSeconds      float64 // provisional target (human sign-off)
	RTOSeconds      float64 // provisional target (human sign-off)

	// Migrations.
	MigrateOnBoot bool

	// Logging.
	LogLevel  string
	LogFormat string

	// Security posture / TLS. When TLSCertFile and TLSKeyFile are both set, the
	// API serves HTTPS directly; otherwise TLS terminates at the ingress. HSTS is
	// always set so it is correct the moment the API is served over HTTPS
	// (CLAUDE.md §7 guardrail 12).
	HSTSEnabled bool
	HSTSMaxAge  time.Duration
	TLSCertFile string
	TLSKeyFile  string

	// Envelope encryption (at rest). Optional; consumed by sensitive-column
	// owners from S18. EnvelopeKey is a base64-encoded 32-byte KEK.
	EnvelopeKey   string
	EnvelopeKeyID string
	// EnvelopeOpenerKeys is a comma-separated keyID=base64-KEK keyring for old
	// deployment envelope keys during rotation overlap. The active key above is
	// still the only key used for new writes.
	EnvelopeOpenerKeys string
	// EnvelopeKeyFile (SEC-002) makes encryption the shipped default: when
	// EnvelopeKey is empty and this path is set, the control plane loads the
	// KEK from the file — GENERATING and persisting one (0600) on first boot.
	// The compose recipe points it at a named volume; back the file up like
	// any key material. An explicit EnvelopeKey (KMS/secret-manager injected)
	// always wins. See docs/hardening.md.
	EnvelopeKeyFile string
	// PublicTLS (SEC-009) asserts the DEPLOYMENT EDGE serves TLS even when
	// this process's own listener is plaintext (TLS-terminating ingress) —
	// it drives the Secure attribute on cookies. The Helm chart sets it.
	PublicTLS bool
	// AllowPlaintextHTTP (WIRE-004) is the explicit, loud, non-default opt-in
	// for a plaintext control-API listener — REQUIRED to start without TLS
	// unless the listener binds loopback. The Helm chart sets it (plaintext
	// in-cluster listener behind the TLS-terminating ingress); everything
	// else should serve TLS (the compose recipe does).
	AllowPlaintextHTTP bool
	// BusWorkers parallelizes each bus subscription's consume path
	// (SCALE-001): poll batches dispatch across this many key-sharded
	// workers (per-key order preserved). 0/1 = serial.
	BusWorkers int
	// RequireAtRestEncryption (TENANT-106) makes keyless passthrough a FATAL
	// startup error instead of a silent plaintext degrade: when true, the
	// control plane refuses to run without a resolvable envelope key (or the
	// licensed per-tenant keyring). Off by default (keyless dev); set in the
	// hardened/regulated profiles.
	RequireAtRestEncryption bool

	// RequireMFA (SEC-005): when true, every authenticated /v1 request must
	// carry a session the IdP asserted a SECOND factor for (amr/acr) — a
	// single-factor session gets 403. Off by default (no change for
	// single-factor deployments); set in hardened/regulated profiles.
	RequireMFA bool

	// Agent transport (gRPC). Enabled when the address and all three TLS files
	// are set; the transport is mTLS-only (never plaintext).
	AgentGRPCAddr    string
	AgentTLSCertFile string
	AgentTLSKeyFile  string
	AgentTLSCAFile   string

	// Version-skew policy (S34): the control plane rejects agents outside the
	// supported window at registration, so a rolling upgrade never admits an
	// incompatible agent. AgentSkewWindow is the allowed minor-version skew on
	// either side (default 1 = N/N-1). AgentMinVersion, when set, is an explicit
	// floor that retires older agents regardless of the window.
	AgentSkewWindow int
	AgentMinVersion string

	// Result pipeline (S6): message bus + time-series writer. BusMode is memory
	// (default, lightweight) or kafka; TSDBMode is memory (default) or prometheus
	// (remote-write to TSDBURL). The control plane consumes the result bus and
	// writes to the TSDB.
	BusMode    string
	BusBrokers []string
	// In-memory bus tuning (lightweight mode, U-079): per-subscriber channel
	// depth and the overflow policy (block | drop) when a subscriber lags.
	// RESIL-002: the default is "block" so the agent is never ACKed after a
	// known in-process drop. "drop" remains available as an explicit isolation
	// policy, but dropped publishes return an error and keep upstream buffers.
	BusMemoryBuffer   int
	BusMemoryOverflow string
	// Kafka transport policy (U-010): TLS by default in kafka mode; plaintext
	// requires the explicit dev-only BusAllowPlaintext flag. SASL optional.
	BusTLSEnabled     bool
	BusTLSCAFile      string
	BusTLSCertFile    string
	BusTLSKeyFile     string
	BusSASLMechanism  string
	BusSASLUser       string
	BusSASLPassword   string
	BusAllowPlaintext bool
	// BusMaxBuffered bounds the async producer's in-flight buffer (U-004);
	// 0 = the bus default (65536). Full buffer = shed + counted, never block.
	BusMaxBuffered int
	// Ingest cardinality caps (U-017): active series identities per agent /
	// per tenant; new identities past the cap are rejected + counted.
	// 0 = defaults (1000 / 50000).
	IngestMaxSeriesPerAgent  int
	IngestMaxSeriesPerTenant int
	// In-memory TSDB bounds (U-018): retention window + byte wall for the
	// lightweight mode (0 = defaults 1h / 256MiB). Oldest-first eviction.
	TSDBMemoryRetention time.Duration
	TSDBMemoryMaxBytes  int
	// Audit WORM export (U-041): when AuditWORMDir is set, the provider
	// audit chain is periodically exported as Ed25519-signed segments to
	// that filesystem object store (mount an object-locked bucket for true
	// WORM) and chain-verified; gaps alert loudly.
	AuditWORMDir      string
	AuditWORMInterval time.Duration
	// AuditRetention (EXC-ORG-01) is how long audit events are kept before the
	// retention pruner is eligible to remove them. 0 (the default) keeps audit
	// history forever — pruning never runs. A positive window prunes only events
	// that are BOTH older than it AND already durably WORM/SIEM-exported (fail
	// closed; the in-DB hash chain a verifier walks is never gapped). Set per the
	// org's SOC2 CC7 / ISO A.12.4 evidence-retention requirement.
	AuditRetention time.Duration
	// WORM signing key (KEYS-002 / D2): the Ed25519 key that signs WORM
	// segments. WormSigningKey is a base64-encoded PKCS#8 PEM private key
	// (KMS/secret-manager injected, like EnvelopeKey); WormSigningKeyFile is a
	// PEM path the control plane loads — generating + persisting one on first
	// boot like the envelope KEK, so the key is STABLE across restarts. When
	// WORM export is enabled (AuditWORMDir) but neither resolves, the control
	// plane FAILS CLOSED rather than minting an ephemeral per-boot key (which
	// breaks cross-restart chain verification). Back it up like the envelope key.
	WormSigningKey     string
	WormSigningKeyFile string
	// TestSyncSigningKeyFile (ARCH-001) is the Ed25519 PKCS#8 PEM the control
	// plane signs pull-able test bundles with (generated + persisted on first
	// boot, like the WORM key). Empty = central test distribution is off
	// (GET /v1/tests/bundle reports 503). Agents verify against the build-baked
	// public half.
	TestSyncSigningKeyFile string
	TSDBMode               string
	TSDBURL                string
	// RemoteWriteBatch* (SCALE-001): coalesce concurrent remote-writes into one
	// POST per <=Series (default 500) / <=Wait (default 50ms) window, preserving
	// per-message DLQ attribution. Enabled gates it; off = one POST per result.
	RemoteWriteBatchEnabled bool
	RemoteWriteBatchSeries  int
	RemoteWriteBatchWait    time.Duration

	// Alerting (S16): how often the engine evaluates enabled rules over the TSDB.
	AlertEvalInterval time.Duration

	// Incidents (S17): the time window within which related signals correlate
	// into one incident.
	IncidentWindow time.Duration

	// SecurityContact (S19) is advertised at /.well-known/security.txt (RFC 9116)
	// as this deployment's vulnerability-disclosure contact (e.g.
	// "mailto:security@your-org.example"). Operator-configured.
	SecurityContact string

	// Identity & access (S18). AuthMode: "session" (real OIDC SSO + RBAC — the
	// default; without a session every /v1 request is refused, U-001
	// fail-closed) or "dev" (LOCAL EVALUATION ONLY, RED-001: the dev-principal
	// code path exists only in -tags devauth builds — release binaries refuse
	// this mode at boot — and even tagged builds additionally require
	// PROBECTL_DEV_AUTH_ACK=i-understand plus a loopback-only bind).
	AuthMode   string
	SessionTTL time.Duration
	// SessionHMACKey is the 32-byte key used to HMAC session tokens before
	// storing their digest in the DB (PROBECTL_SESSION_HMAC_KEY, hex-encoded
	// 64-char string). Session auth in multi-tenant/regulated profiles refuses
	// to start without it; single-profile dev/test may omit it only when the
	// served path is not production session auth (KEYS-002/OPS-006/SEC-003).
	SessionHMACKey []byte
	// Auth brute-force guard (U-024): failures per window before a lockout,
	// the window, and the base lockout (doubles per consecutive lockout,
	// capped at 1h). Zero values use the limiter's safe defaults (5 / 1m / 1m).
	AuthRateMaxFailures int
	AuthRateWindow      time.Duration
	AuthRateLockout     time.Duration
	OIDCIssuer          string
	OIDCClientID        string
	OIDCClientSecret    string
	OIDCRedirectURL     string

	// Path store (S10/S11): where discovered network paths are persisted and
	// served. memory (default) or clickhouse (a ClickHouse HTTP URL).
	PathStoreMode string
	PathStoreURL  string

	// Flow store (S38): where device-flow records (NetFlow/IPFIX/sFlow) land and
	// the flow analytics are served from. memory (default) or clickhouse.
	// FlowRetentionDays > 0 applies a ClickHouse delete-TTL (high-volume
	// retention). FlowEnrichASN opts in to ASN/geo enrichment via the S15
	// opendata sources (Team Cymru DNS lookups — an OUTBOUND dependency, so it
	// is off by default per the no-phone-home guardrail; device-asserted AS
	// numbers always pass through).
	FlowStoreMode string
	FlowStoreURL  string
	// OTelStoreMode/URL/RetentionDays (ARCH-001): where externally-ingested
	// OTLP traces + logs live (memory | clickhouse; retention in days).
	OTelStoreMode     string
	OTelStoreURL      string
	OTelRetentionDays int
	FlowRetentionDays int
	// EBPFStore{Mode,URL,RetentionDays} (ARCH-008): durable eBPF flow/L7
	// service-edge aggregates. memory (default) keeps the prior in-RAM-only
	// behavior; clickhouse persists them so the differentiator plane has history
	// and survives restarts.
	EBPFStoreMode     string
	EBPFStoreURL      string
	EBPFRetentionDays int
	// PathRetentionDays bounds the path/traceroute tables (SCALE-006).
	PathRetentionDays int
	FlowEnrichASN     bool
	// FlowCHTenantScoping (TENANT-102) attaches a per-request tenant custom
	// setting to ClickHouse reads so a reader row policy can constrain the
	// query path at the DB. Requires server-side custom_settings_prefixes=SQL_
	// and a reader user; off by default. FlowCHReaderUser names that user (the
	// setting-scoped row policy is installed on it at boot).
	FlowCHTenantScoping bool
	FlowCHReaderUser    string

	// DeploymentProfile (TENANT-004) selects the isolation posture:
	//   single       — single-tenant / sovereign: app-layer WHERE scoping is
	//                   the boundary (the deployment IS the tenant boundary).
	//   multi-tenant  — pooled multi-tenant: DB-enforced row policies default ON
	//                   across ALL ClickHouse planes (defense-in-depth above app
	//                   code — guardrail 7.1).
	//   regulated     — multi-tenant + the strictest profile: same as
	//                   multi-tenant for the CH planes (siloing/BYOK are
	//                   selected separately).
	// The per-plane CHTenantScoping flags below default to true under
	// multi-tenant/regulated unless an explicit env value overrides them.
	DeploymentProfile string

	// {OTel,EBPF,Path}CHTenantScoping + readers (TENANT-003/004 parity): each
	// ClickHouse plane attaches the per-request tenant custom setting and
	// installs a setting-scoped reader row policy on its reader user, so the
	// query path cannot cross tenants even if app-layer WHERE scoping is
	// bypassed. Defaulted ON by the multi-tenant/regulated profile.
	OTelCHTenantScoping bool
	OTelCHReaderUser    string
	EBPFCHTenantScoping bool
	EBPFCHReaderUser    string
	PathCHTenantScoping bool
	PathCHReaderUser    string

	// IngestStrictTenantLanes (WIRE-001): refuse agent-published collector
	// planes (flow/eBPF/device/endpoint) on the SHARED pooled bus lane, forcing
	// them onto tenant-namespaced lanes (broker-ACL isolated, single-tenant by
	// construction) where a forged payload tenant_id cannot be honored. Closes
	// the residual shared-lane forgery surface. Defaulted ON under
	// multi-tenant/regulated; OFF under single (one tenant, no forgery risk).
	IngestStrictTenantLanes bool

	// CMDB integration (S40): read-only CI correlation. CMDBProvider "" keeps
	// the feature off; "servicenow" requires CMDBURL (https, or http loopback
	// for tests) and CMDBSecret ("user:password" — env only, never logged).
	CMDBProvider string
	CMDBURL      string
	CMDBSecret   string
	CMDBTable    string
	CMDBCacheTTL time.Duration

	// OTLP receiver (S22): TLS-only, authenticated, tenant-scoped ingest of
	// external OTLP. Enabled when an address + TLS cert/key + tokens are all set.
	OTLPGRPCAddr    string
	OTLPHTTPAddr    string
	OTLPTLSCertFile string
	OTLPTLSKeyFile  string
	OTLPTokens      map[string]string // bearer token -> tenant id

	// OTLP EXPORT (ARCH-007): forward ingested OTLP metrics on to an external
	// collector/backend. Dormant until an endpoint is set. Protocol grpc|http;
	// a remote endpoint must be https (Insecure is dev/loopback only — refused
	// for a non-loopback host, guardrail 12).
	OTLPExportEndpoint string
	OTLPExportToken    string
	OTLPExportProtocol string // "grpc" (default) | "http"
	OTLPExportInsecure bool

	// AI assistant (S24): the RCA model backend. Provider "builtin" (default) is
	// the in-process, fully air-gapped synthesizer — no network, no phone-home.
	// "ollama"/"openai"/"anthropic" call a model endpoint; a remote endpoint must
	// be https (enforced when the adapter is built — guardrail 12), while loopback
	// may be http for a co-located local model. AIMaxEvidence caps how many
	// signals an answer may gather (cost guard).
	AIModelProvider string
	AIModelEndpoint string
	AIModelName     string
	AIModelToken    string
	AIModelTimeout  time.Duration
	AIMaxEvidence   int
	// AIMaxConcurrent (U-048) caps concurrent RCA analyses process-wide — a
	// fail-fast (429) backstop that holds even when no per-tenant fairness
	// gate is configured.
	AIMaxConcurrent int
	// AIPersistAnswers + AIAnswerRetention (U-093): optionally persist every
	// RCA answer (full cited JSON + model + config hash) for reproducibility
	// and dispute resolution, pruned past the retention window.
	AIPersistAnswers  bool
	AIAnswerRetention time.Duration
	// AIRedactIPs / AIRedactHostnames (U-013/C8): the pre-egress redaction
	// pass for REMOTE models — IPs masked by default, hostnames per policy;
	// obvious secrets are always masked. Local paths are never redacted.
	AIRedactIPs       bool
	AIRedactHostnames bool
	// AIRedactPII (AIRCA-002): mask emails, phone numbers, and MAC
	// addresses in anything leaving to an external AI (default true).
	AIRedactPII bool
	// AIRedactCustom (AIRCA-002): operator regexes (";;"-separated) masked
	// as [custom:xxxx]; compile-checked at load (fail closed).
	AIRedactCustom string
	// AIEgressAck (U-013): a REMOTE (non-loopback) model endpoint sends
	// tenant telemetry off-network. The operator must acknowledge that
	// explicitly — the server refuses to start otherwise. Loopback local
	// models and the air-gapped builtin need no acknowledgment.
	AIEgressAck string

	// MCP server (S25): the Model Context Protocol HTTP transport (network-
	// exposed). Enabled when an address + TLS cert/key are all set; it is TLS-only
	// and bearer-authenticated (guardrail 12). The stdio transport is local
	// (probectl-control mcp-stdio) and reads its token from PROBECTL_MCP_TOKEN.
	// MCPRatePerMin caps per-tenant tool-call volume.
	MCPHTTPAddr    string
	MCPTLSCertFile string
	MCPTLSKeyFile  string
	MCPRatePerMin  int

	// Security / threat (S27): TLS/cert posture over already-captured TLS (S13/S21).
	// TrustctlURL deep-links cert findings to trustctl for renewal; TLSExpiryWarning
	// is the expiring-soon window. CT correlation is OPT-IN (CTEnabled) — an
	// external fetch (AUP / sovereignty / no-phone-home), off by default.
	TrustctlURL      string
	TLSExpiryWarning time.Duration
	CTEnabled        bool
	CTEndpoint       string

	// Threat-intel enrichment (S28): match flows/connections/certs/JA3 against
	// public IOC feeds. OFF by default — enabling it makes outbound fetches to the
	// configured feeds (AUP / sovereignty / no-phone-home). ThreatIntelFeeds names
	// the feeds to load (empty → all built-in feeds); ThreatIntelRefresh is the
	// refresh cadence. Several feeds restrict commercial redistribution (MSP
	// resale) — provenance/AUP is tracked per feed.
	ThreatIntelEnabled bool
	ThreatIntelRefresh time.Duration
	ThreatIntelFeeds   []string

	// NDR-lite behavioral detection (S42, F37): DGA/exfil/beaconing/egress/
	// lateral detectors over the locally-collected flow/eBPF/DNS substrate.
	// ON by default — it makes no outbound calls (sovereignty-safe) and its
	// detections are SIGNALS, never blocks (guardrail 9). NDRRulesDir overlays
	// the embedded detection-as-code ruleset (tune/disable/add without code).
	NDREnabled  bool
	NDRRulesDir string

	// Topology graph engine (S43, F40): "indexed" (default — adjacency-indexed,
	// the L/XL dedicated engine) or "memory" (the S30 reference store). Both
	// sit behind the same query API; the switch is transparent to callers.
	TopologyEngine string

	// FinOps / egress cost (S44, F41): volume × public pricing over the local
	// flow stream — no cloud-billing API calls (sovereignty-safe; ON by
	// default). CostZones maps CIDRs to cloud zones ("cidr=zone[/region],...");
	// CostServices attributes CIDRs to service:team (showback); CostBudgets
	// caps monthly spend ("team:payments=500,..."); CostPricesFile overrides
	// the embedded public list rates (JSON); CostPriced=false runs volume-only.
	CostEnabled    bool
	CostZones      string
	CostServices   string
	CostBudgets    string
	CostPricesFile string
	CostPriced     bool

	// SLO engine (S45, F42): OpenSLO v1 definitions loaded from SLODir
	// (*.yaml; multi-document files allowed), evaluated per tenant over the
	// synthetic-result stream with error budgets + multi-window burn-rate
	// alerts. ON by default (local-only); a malformed dir fails startup.
	SLOEnabled bool
	SLODir     string

	// Compliance / segmentation validation (S46, F43): declared policies
	// validated against OBSERVED flow/eBPF traffic — verdicts + audit-grade
	// evidence; never enforcement. ON by default (local-only); a malformed
	// policy dir fails startup.
	ComplianceEnabled   bool
	CompliancePolicyDir string

	// Collective internet-outage view (S47a, F19). OutageEnabled gates the
	// LOCAL engine (vantage detection + correlation over the result stream —
	// no outbound calls; ON by default). OutageFeedsEnabled separately gates
	// the public feeds (IODA / Cloudflare Radar) — OFF by default because
	// enabling it makes outbound fetches (sovereignty / no-phone-home).
	// OutageFeeds names the feeds to load (empty → all built-in);
	// OutageRadarToken is the Cloudflare API token the radar feed requires
	// (secret-ref resolvable); OutageRetention bounds the event window.
	OutageEnabled      bool
	OutageFeedsEnabled bool
	OutageFeeds        []string
	OutageRefresh      time.Duration
	OutageRetention    time.Duration
	OutageRadarToken   string

	// RUM convergence (S47b, F20). OFF by default: enabling opens the beacon
	// ingest (an unauthenticated-session inbound surface — each beacon
	// authenticates via its app key). RUMApps maps app keys to
	// "tenant/app" bindings (the key in a page is an identifier, not a
	// secret); RUMRatePerMin bounds each key's beacon rate. Privacy
	// (consent, URL redaction, no IP storage) is enforced server-side in
	// internal/rum regardless of configuration.
	RUMEnabled    bool
	RUMApps       map[string]string
	RUMRatePerMin int

	// Carbon/power observability (S48, F48): coefficient-based estimation of
	// network transmission energy/carbon over the local flow stream — served
	// as ESTIMATES with the methodology block. ON by default (local-only; no
	// outbound calls). CarbonGridGCO2E is the operator's grid carbon
	// intensity in gCO2e/kWh (defaults to the world average — set yours).
	// Attribution reuses PROBECTL_COST_ZONES / PROBECTL_COST_SERVICES.
	CarbonEnabled   bool
	CarbonGridGCO2E int

	// Editions (S-T0): the path to the offline-signed license file. Empty =
	// Community (the full core, default-open). A configured-but-invalid file
	// FAILS STARTUP; an expired one degrades per the grace ladder — it never
	// breaks running telemetry. Verification is local math against
	// build-time-baked public keys (never phone-home).
	LicenseFile string

	// Provider plane (S-T1, ee/; active only with a provider-tier license).
	// ProviderBootstrapToken creates the FIRST operator (single-use: inert once
	// any operator exists). ProviderBreakGlassMaxTTLMinutes caps break-glass
	// grant lifetimes (default 240 = 4h).
	ProviderBootstrapToken          string
	ProviderBreakGlassMaxTTLMinutes int

	// Guarded remediation (S-EE5). ApprovalsEnabled is the advisory-only
	// master switch — OFF by default (proposals + dry-run work; the Approve
	// action is inert until an operator turns it on). MaxBlastRadius caps the
	// simulated impact an approvable proposal may have (provisional; human-owned).
	RemediationApprovalsEnabled bool
	RemediationMaxBlastRadius   int

	// Fairness deployment defaults (S-T7): per-tenant bounds applied to
	// every tenant absent a stored override. Zero = unlimited (fairness is
	// opt-in per bound; small/single-tenant deployments enforce nothing
	// unless configured).
	FairnessResultsPerSec     float64
	FairnessFlowEventsPerSec  float64
	FairnessIngestBytesPerSec float64
	// FairnessDeviceMetricsPerSec bounds the SNMP/gNMI plane (SCALE-005).
	FairnessDeviceMetricsPerSec float64
	// FairnessOTLPSeriesPerSec bounds the OTLP metric/trace/log planes (SCALE-003).
	FairnessOTLPSeriesPerSec float64
	FairnessBurstSeconds     float64
	FairnessQueryConcurrency int
	FairnessQueriesPerMin    float64
	// FairnessTenantIdleTTL bounds the fairness gate's per-tenant state map
	// (SCALE-002): a tenant idle this long is evicted by the amortized sweep so
	// tenant churn can't grow the map without bound. Default 24h.
	FairnessTenantIdleTTL time.Duration

	// BackupRetentionNote (S-T5): the operator's backup-TTL statement,
	// included verbatim in every deletion attestation (the explicit
	// backup-retention story — live-store deletion is attested; snapshots
	// expire per this stated policy).
	BackupRetentionNote string
	// BackupRetentionDays (COMPLY-002): the concrete backup TTL in days.
	// When > 0, tenant-erasure attestations quantify a bounded backup-
	// coverage window (erased_at + this). 0 = note-only (unquantified).
	BackupRetentionDays int

	// DataPlanes (S-T2, ee/; siloed_isolation): named residency targets for
	// siloed/hybrid tenants — "name=clickhouseURL[;name=clickhouseURL...]".
	// Residency pins a tenant's ClickHouse data plane; see docs/isolation.md
	// for exactly what is and is not pinned in this release.
	DataPlanes string

	// SIEM export (S32, F26): forward the audit stream + threat-plane signals to the
	// SOC's SIEM. OFF by default — enabling it makes an outbound connection to the
	// operator-supplied endpoint (sovereignty / no-phone-home). SIEMPreset adapts the
	// auth scheme (splunk/sentinel/elastic/chronicle/generic); SIEMFormat pins the
	// wire format (syslog/cef/ecs/otlp; empty → the preset's native default).
	// SIEMPollInterval is the audit-drain cadence; SIEMRedactKeys are audit data keys
	// scrubbed before export (PII/secret governance) on top of the built-in denylist.
	SIEMEnabled      bool
	SIEMPreset       string
	SIEMFormat       string
	SIEMEndpoint     string
	SIEMToken        string
	SIEMPollInterval time.Duration
	SIEMBufferSize   int
	SIEMRedactKeys   []string

	// Change intelligence (S29): inbound, per-provider-signed change webhooks. Each
	// entry maps a public webhook id (the URL selector) to a tenant + provider +
	// HMAC/token secret. The tenant is bound to the credential, never the payload,
	// so a verified delivery can only write its own tenant's changes.
	// ChangeCorrelationWindow is how far before an incident a change is considered a
	// candidate cause.
	ChangeWebhooks          map[string]ChangeWebhook
	ChangeCorrelationWindow time.Duration

	// On-call + ITSM integration (S33): outbound connectors that mirror incidents
	// into PagerDuty/Opsgenie/Slack/Teams/ServiceNow/Jira (per-tenant routing), and
	// inbound webhook credentials that let ITSM/on-call sync status back. OFF unless
	// configured (an outbound connection to the operator's tooling). The connector
	// endpoint contains ':' (a URL), so connectors are pipe-delimited; inbound
	// credentials carry no endpoint, so they mirror the change-webhook colon form.
	NotifyConnectors []NotifyConnector
	NotifyInbound    map[string]NotifyInbound
}

// ChangeWebhook is one configured inbound change-webhook credential (S29).
type ChangeWebhook struct {
	TenantID string
	Provider string // "generic" | "github" | "gitlab"
	Secret   string
}

// NotifyConnector is one configured outbound on-call/ITSM connector (S33). Secret
// is the provider credential (PagerDuty routing key, Opsgenie API key, ServiceNow
// "user:password", Jira "email:token"; unused for chat). Endpoint is the provider
// API/webhook URL.
type NotifyConnector struct {
	TenantID string
	Provider string // pagerduty|opsgenie|slack|teams|servicenow|jira
	Endpoint string
	Secret   string
}

// NotifyInbound is one configured inbound status-sync webhook credential (S33):
// an ITSM/on-call system posts a resolve/ack to /ingest/itsm/{provider}/{id},
// authenticated by Secret (HMAC or token) and bound to the tenant here.
type NotifyInbound struct {
	TenantID string
	Provider string
	Secret   string
}

// Load resolves configuration using the supplied getenv function (use
// LoadFromEnv for the process environment). All validation errors are joined
// and returned together.
func Load(getenv func(string) string) (*Config, error) {
	l := &loader{getenv: getenv}
	// TENANT-004: the deployment profile decides whether DB-enforced ClickHouse
	// tenant isolation is ON by default. multi-tenant/regulated turn it on for
	// every CH plane (defense-in-depth above app code, guardrail 7.1); single
	// keeps app-layer WHERE scoping as the boundary. Resolved BEFORE the
	// per-plane scoping flags so they can default off it.
	deploymentProfile := l.enum("PROBECTL_DEPLOYMENT_PROFILE", "single", "single", "multi-tenant", "regulated")
	chScopeDefault := deploymentProfile == "multi-tenant" || deploymentProfile == "regulated"
	cfg := &Config{
		HTTPAddr:        l.str("PROBECTL_HTTP_ADDR", ":8080"),
		ReadTimeout:     l.dur("PROBECTL_HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:    l.dur("PROBECTL_HTTP_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:     l.dur("PROBECTL_HTTP_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout: l.dur("PROBECTL_SHUTDOWN_TIMEOUT", 15*time.Second),
		DatabaseURL:     l.str("PROBECTL_DATABASE_URL", "postgres://probectl:probectl@localhost:5432/probectl?sslmode=require"),
		DatabaseReadURL: l.str("PROBECTL_DATABASE_READ_URL", ""),
		// SCALE-009: a higher default pool ceiling and a warm floor. The old
		// MaxConns=10 / MinConns=0 was tight for high fan-in (API + every
		// consumer share the pool) and made the first request after idle pay a
		// connect+TLS+SET-ROLE cold-start. 25/2 is a saner single-node default;
		// docs/configuration.md gives per-tier sizing.
		DatabaseMaxConns:         int32(l.intRange("PROBECTL_DATABASE_MAX_CONNS", 25, 1, 1000)),
		DatabaseMinConns:         int32(l.intRange("PROBECTL_DATABASE_MIN_CONNS", 2, 0, 1000)),
		Region:                   l.str("PROBECTL_REGION", ""),
		Regions:                  l.list("PROBECTL_REGIONS"),
		Residency:                l.str("PROBECTL_RESIDENCY", ""),
		ReplicationMode:          l.enum("PROBECTL_REPLICATION_MODE", "async", "async", "sync"),
		RPOSeconds:               l.float("PROBECTL_RPO_SECONDS", 0),
		RTOSeconds:               l.float("PROBECTL_RTO_SECONDS", 60),
		DatabaseConnTimeout:      l.dur("PROBECTL_DATABASE_CONNECT_TIMEOUT", 5*time.Second),
		MigrateOnBoot:            l.boolean("PROBECTL_MIGRATE_ON_BOOT", false),
		LogLevel:                 l.enum("PROBECTL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:                l.enum("PROBECTL_LOG_FORMAT", "json", "json", "text"),
		RequireMFA:               l.boolean("PROBECTL_REQUIRE_MFA", false),
		HSTSEnabled:              l.boolean("PROBECTL_HSTS_ENABLED", true),
		HSTSMaxAge:               l.dur("PROBECTL_HSTS_MAX_AGE", 365*24*time.Hour),
		TLSCertFile:              l.str("PROBECTL_TLS_CERT_FILE", ""),
		TLSKeyFile:               l.str("PROBECTL_TLS_KEY_FILE", ""),
		EnvelopeKey:              l.str("PROBECTL_ENVELOPE_KEY", ""),
		EnvelopeKeyID:            l.str("PROBECTL_ENVELOPE_KEY_ID", "dev"),
		EnvelopeOpenerKeys:       l.str("PROBECTL_ENVELOPE_OPENER_KEYS", ""),
		EnvelopeKeyFile:          l.str("PROBECTL_ENVELOPE_KEY_FILE", ""),
		PublicTLS:                l.boolean("PROBECTL_PUBLIC_TLS", false),
		AllowPlaintextHTTP:       l.boolean("PROBECTL_ALLOW_PLAINTEXT_HTTP", false),
		BusWorkers:               l.intRange("PROBECTL_BUS_WORKERS", 4, 0, 256),
		RequireAtRestEncryption:  l.boolean("PROBECTL_REQUIRE_AT_REST_ENCRYPTION", false),
		AgentGRPCAddr:            l.str("PROBECTL_AGENT_GRPC_ADDR", ""),
		AgentSkewWindow:          l.intRange("PROBECTL_AGENT_SKEW_WINDOW", 1, 0, 100),
		AgentMinVersion:          l.str("PROBECTL_AGENT_MIN_VERSION", ""),
		AgentTLSCertFile:         l.str("PROBECTL_AGENT_TLS_CERT_FILE", ""),
		AgentTLSKeyFile:          l.str("PROBECTL_AGENT_TLS_KEY_FILE", ""),
		AgentTLSCAFile:           l.str("PROBECTL_AGENT_TLS_CA_FILE", ""),
		BusMode:                  l.enum("PROBECTL_BUS_MODE", "memory", "memory", "kafka"),
		BusBrokers:               l.list("PROBECTL_BUS_BROKERS"),
		BusMemoryBuffer:          l.intRange("PROBECTL_BUS_MEMORY_BUFFER", 1024, 1, 1<<20),
		BusMemoryOverflow:        l.enum("PROBECTL_BUS_MEMORY_OVERFLOW", "block", "block", "drop"),
		BusTLSEnabled:            l.boolean("PROBECTL_BUS_TLS_ENABLED", false),
		BusTLSCAFile:             l.str("PROBECTL_BUS_TLS_CA_FILE", ""),
		BusTLSCertFile:           l.str("PROBECTL_BUS_TLS_CERT_FILE", ""),
		BusTLSKeyFile:            l.str("PROBECTL_BUS_TLS_KEY_FILE", ""),
		BusSASLMechanism:         l.str("PROBECTL_BUS_SASL_MECHANISM", ""),
		BusSASLUser:              l.str("PROBECTL_BUS_SASL_USER", ""),
		BusSASLPassword:          l.str("PROBECTL_BUS_SASL_PASSWORD", ""),
		BusAllowPlaintext:        l.boolean("PROBECTL_BUS_ALLOW_PLAINTEXT", false),
		BusMaxBuffered:           l.intRange("PROBECTL_BUS_MAX_BUFFERED", 0, 0, 10_000_000),
		IngestMaxSeriesPerAgent:  l.intRange("PROBECTL_INGEST_MAX_SERIES_PER_AGENT", 0, 0, 10_000_000),
		IngestMaxSeriesPerTenant: l.intRange("PROBECTL_INGEST_MAX_SERIES_PER_TENANT", 0, 0, 100_000_000),
		TSDBMemoryRetention:      l.dur("PROBECTL_TSDB_MEMORY_RETENTION", 0),
		TSDBMemoryMaxBytes:       l.intRange("PROBECTL_TSDB_MEMORY_MAX_BYTES", 0, 0, 1<<31-1),
		AuditWORMDir:             l.str("PROBECTL_AUDIT_WORM_DIR", ""),
		AuditWORMInterval:        l.dur("PROBECTL_AUDIT_WORM_INTERVAL", time.Hour),
		AuditRetention:           l.dur("PROBECTL_AUDIT_RETENTION", 0),
		WormSigningKey:           l.str("PROBECTL_WORM_SIGNING_KEY", ""),
		WormSigningKeyFile:       l.str("PROBECTL_WORM_SIGNING_KEY_FILE", ""),
		TestSyncSigningKeyFile:   l.str("PROBECTL_TESTSYNC_SIGNING_KEY_FILE", ""),
		TSDBMode:                 l.enum("PROBECTL_TSDB_MODE", "memory", "memory", "prometheus"),
		TSDBURL:                  l.str("PROBECTL_TSDB_URL", ""),
		// SCALE-001: batching defaults ON for prometheus remote-write so the
		// default production ingest path coalesces results instead of doing one
		// HTTP POST per probe result. The default is resolved below (it depends
		// on TSDBMode, set on the line above); an explicit env still wins.
		RemoteWriteBatchEnabled: l.boolean("PROBECTL_REMOTE_WRITE_BATCH_ENABLED", false),
		RemoteWriteBatchSeries:  l.intRange("PROBECTL_REMOTE_WRITE_BATCH_SERIES", 500, 1, 100000),
		RemoteWriteBatchWait:    l.dur("PROBECTL_REMOTE_WRITE_BATCH_WAIT", 50*time.Millisecond),
		PathStoreMode:           l.enum("PROBECTL_PATHSTORE_MODE", "memory", "memory", "clickhouse"),
		PathStoreURL:            l.str("PROBECTL_PATHSTORE_URL", ""),
		FlowStoreMode:           l.enum("PROBECTL_FLOWSTORE_MODE", "memory", "memory", "clickhouse"),
		FlowStoreURL:            l.str("PROBECTL_FLOWSTORE_URL", ""),
		OTelStoreMode:           l.enum("PROBECTL_OTELSTORE_MODE", "memory", "memory", "clickhouse"),
		OTelStoreURL:            l.str("PROBECTL_OTELSTORE_URL", ""),
		OTelRetentionDays:       l.intRange("PROBECTL_OTEL_RETENTION_DAYS", 30, 0, 3650),
		EBPFStoreMode:           l.enum("PROBECTL_EBPFSTORE_MODE", "memory", "memory", "clickhouse"),
		EBPFStoreURL:            l.str("PROBECTL_EBPFSTORE_URL", ""),
		EBPFRetentionDays:       l.intRange("PROBECTL_EBPF_RETENTION_DAYS", 30, 0, 3650),
		// SCALE-016: default to a FINITE 90-day flow retention rather than the
		// old keep-forever (0) default, which silently let the highest-volume
		// table on the platform grow without bound. 0 still means keep-forever,
		// but it is now an EXPLICIT opt-out the operator chooses (and main.go
		// logs loudly when set), not the silent default.
		FlowRetentionDays: l.intRange("PROBECTL_FLOW_RETENTION_DAYS", 90, 0, 3650),
		PathRetentionDays: l.intRange("PROBECTL_PATH_RETENTION_DAYS", 90, 0, 3650),
		FlowEnrichASN:     l.boolean("PROBECTL_FLOW_ENRICH_ASN", false),
		// TENANT-004: profile-defaulted (multi-tenant/regulated => ON) so the
		// DB-level row policy is the boundary by default, not just app WHERE.
		DeploymentProfile:   deploymentProfile,
		FlowCHTenantScoping: l.boolean("PROBECTL_FLOWSTORE_TENANT_SCOPING", chScopeDefault),
		FlowCHReaderUser:    l.str("PROBECTL_FLOWSTORE_READER_USER", ""),
		OTelCHTenantScoping: l.boolean("PROBECTL_OTELSTORE_TENANT_SCOPING", chScopeDefault),
		OTelCHReaderUser:    l.str("PROBECTL_OTELSTORE_READER_USER", ""),
		EBPFCHTenantScoping: l.boolean("PROBECTL_EBPFSTORE_TENANT_SCOPING", chScopeDefault),
		EBPFCHReaderUser:    l.str("PROBECTL_EBPFSTORE_READER_USER", ""),
		PathCHTenantScoping: l.boolean("PROBECTL_PATHSTORE_TENANT_SCOPING", chScopeDefault),
		PathCHReaderUser:    l.str("PROBECTL_PATHSTORE_READER_USER", ""),
		// WIRE-001: profile-defaulted (multi-tenant/regulated => ON) so the
		// shared pooled lane cannot be used to forge another tenant's telemetry.
		IngestStrictTenantLanes: l.boolean("PROBECTL_INGEST_STRICT_TENANT_LANES", chScopeDefault),
		CMDBProvider:            l.enum("PROBECTL_CMDB_PROVIDER", "", "", "servicenow"),
		CMDBURL:                 l.str("PROBECTL_CMDB_URL", ""),
		CMDBSecret:              l.str("PROBECTL_CMDB_SECRET", ""),
		CMDBTable:               l.str("PROBECTL_CMDB_TABLE", "cmdb_ci"),
		CMDBCacheTTL:            l.dur("PROBECTL_CMDB_CACHE_TTL", 10*time.Minute),
		AlertEvalInterval:       l.dur("PROBECTL_ALERT_EVAL_INTERVAL", 30*time.Second),
		IncidentWindow:          l.dur("PROBECTL_INCIDENT_WINDOW", 10*time.Minute),
		AuthMode:                l.enum("PROBECTL_AUTH_MODE", "session", "dev", "session"),
		SessionTTL:              l.dur("PROBECTL_SESSION_TTL", 12*time.Hour),
		SessionHMACKey:          l.hexBytes("PROBECTL_SESSION_HMAC_KEY", 32),
		AuthRateMaxFailures:     l.intRange("PROBECTL_AUTH_RATE_MAX_FAILURES", 5, 1, 1000),
		AuthRateWindow:          l.dur("PROBECTL_AUTH_RATE_WINDOW", time.Minute),
		AuthRateLockout:         l.dur("PROBECTL_AUTH_RATE_LOCKOUT", time.Minute),
		OIDCIssuer:              l.str("PROBECTL_OIDC_ISSUER", ""),
		OIDCClientID:            l.str("PROBECTL_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:        l.str("PROBECTL_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:         l.str("PROBECTL_OIDC_REDIRECT_URL", ""),
		SecurityContact:         l.str("PROBECTL_SECURITY_CONTACT", ""),
		OTLPExportEndpoint:      l.str("PROBECTL_OTLP_EXPORT_ENDPOINT", ""),
		OTLPExportToken:         l.str("PROBECTL_OTLP_EXPORT_TOKEN", ""),
		OTLPExportProtocol:      l.enum("PROBECTL_OTLP_EXPORT_PROTOCOL", "grpc", "grpc", "http"),
		OTLPExportInsecure:      l.boolean("PROBECTL_OTLP_EXPORT_INSECURE", false),
		OTLPGRPCAddr:            l.str("PROBECTL_OTLP_GRPC_ADDR", ""),
		OTLPHTTPAddr:            l.str("PROBECTL_OTLP_HTTP_ADDR", ""),
		OTLPTLSCertFile:         l.str("PROBECTL_OTLP_TLS_CERT_FILE", ""),
		OTLPTLSKeyFile:          l.str("PROBECTL_OTLP_TLS_KEY_FILE", ""),
		OTLPTokens:              l.tokenMap("PROBECTL_OTLP_TOKENS"),
		AIModelProvider:         l.enum("PROBECTL_AI_MODEL_PROVIDER", "builtin", "builtin", "ollama", "openai", "anthropic"),
		AIModelEndpoint:         l.str("PROBECTL_AI_MODEL_ENDPOINT", ""),
		AIModelName:             l.str("PROBECTL_AI_MODEL_NAME", ""),
		AIModelToken:            l.str("PROBECTL_AI_MODEL_TOKEN", ""),
		AIModelTimeout:          l.dur("PROBECTL_AI_MODEL_TIMEOUT", 60*time.Second),
		AIMaxEvidence:           l.intRange("PROBECTL_AI_MAX_EVIDENCE", 50, 1, 1000),
		AIMaxConcurrent:         l.intRange("PROBECTL_AI_MAX_CONCURRENT", 8, 1, 1024),
		AIPersistAnswers:        l.boolean("PROBECTL_AI_PERSIST_ANSWERS", false),
		AIAnswerRetention:       l.dur("PROBECTL_AI_ANSWER_RETENTION", 90*24*time.Hour),
		AIEgressAck:             l.str("PROBECTL_AI_EGRESS_ACK", ""),
		AIRedactIPs:             l.boolean("PROBECTL_AI_REDACT_IPS", true),
		AIRedactHostnames:       l.boolean("PROBECTL_AI_REDACT_HOSTNAMES", false),
		AIRedactPII:             l.boolean("PROBECTL_AI_REDACT_PII", true),
		AIRedactCustom:          l.str("PROBECTL_AI_REDACT_PATTERNS", ""),
		MCPHTTPAddr:             l.str("PROBECTL_MCP_HTTP_ADDR", ""),
		MCPTLSCertFile:          l.str("PROBECTL_MCP_TLS_CERT_FILE", ""),
		MCPTLSKeyFile:           l.str("PROBECTL_MCP_TLS_KEY_FILE", ""),
		MCPRatePerMin:           l.intRange("PROBECTL_MCP_RATE_PER_MIN", 120, 0, 100000),
		TrustctlURL:             l.str("PROBECTL_TRUSTCTL_URL", ""),
		TLSExpiryWarning:        l.dur("PROBECTL_TLS_EXPIRY_WARNING", 21*24*time.Hour),
		CTEnabled:               l.boolean("PROBECTL_CT_ENABLED", false),
		CTEndpoint:              l.str("PROBECTL_CT_ENDPOINT", "https://crt.sh"),
		ThreatIntelEnabled:      l.boolean("PROBECTL_THREATINTEL_ENABLED", false),
		ThreatIntelRefresh:      l.dur("PROBECTL_THREATINTEL_REFRESH", 6*time.Hour),
		ThreatIntelFeeds:        l.list("PROBECTL_THREATINTEL_FEEDS"),
		NDREnabled:              l.boolean("PROBECTL_NDR_ENABLED", true),
		NDRRulesDir:             l.str("PROBECTL_NDR_RULES_DIR", ""),
		TopologyEngine:          l.str("PROBECTL_TOPOLOGY_ENGINE", "indexed"),
		CostEnabled:             l.boolean("PROBECTL_COST_ENABLED", true),
		CostZones:               l.str("PROBECTL_COST_ZONES", ""),
		CostServices:            l.str("PROBECTL_COST_SERVICES", ""),
		CostBudgets:             l.str("PROBECTL_COST_BUDGETS", ""),
		CostPricesFile:          l.str("PROBECTL_COST_PRICES_FILE", ""),
		CostPriced:              l.boolean("PROBECTL_COST_PRICED", true),
		SLOEnabled:              l.boolean("PROBECTL_SLO_ENABLED", true),
		SLODir:                  l.str("PROBECTL_SLO_DIR", ""),
		ComplianceEnabled:       l.boolean("PROBECTL_COMPLIANCE_ENABLED", true),
		CompliancePolicyDir:     l.str("PROBECTL_COMPLIANCE_POLICY_DIR", ""),

		OutageEnabled:      l.boolean("PROBECTL_OUTAGE_ENABLED", true),
		OutageFeedsEnabled: l.boolean("PROBECTL_OUTAGE_FEEDS_ENABLED", false),
		OutageFeeds:        l.list("PROBECTL_OUTAGE_FEEDS"),
		OutageRefresh:      l.dur("PROBECTL_OUTAGE_REFRESH", 10*time.Minute),
		OutageRetention:    l.dur("PROBECTL_OUTAGE_RETENTION", 48*time.Hour),
		OutageRadarToken:   l.str("PROBECTL_OUTAGE_RADAR_TOKEN", ""),

		RUMEnabled:    l.boolean("PROBECTL_RUM_ENABLED", false),
		RUMApps:       l.tokenMap("PROBECTL_RUM_APPS"),
		RUMRatePerMin: l.intRange("PROBECTL_RUM_RATE_PER_MIN", 300, 0, 1_000_000),

		CarbonEnabled:   l.boolean("PROBECTL_CARBON_ENABLED", true),
		CarbonGridGCO2E: l.intRange("PROBECTL_CARBON_GRID_GCO2E", 436, 1, 5000),

		LicenseFile: l.str("PROBECTL_LICENSE_FILE", ""),

		ProviderBootstrapToken:          l.str("PROBECTL_PROVIDER_BOOTSTRAP_TOKEN", ""),
		ProviderBreakGlassMaxTTLMinutes: l.intRange("PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES", 240, 5, 1440),
		DataPlanes:                      l.str("PROBECTL_DATAPLANES", ""),
		BackupRetentionNote:             l.str("PROBECTL_BACKUP_RETENTION_NOTE", ""),
		BackupRetentionDays:             l.intRange("PROBECTL_BACKUP_RETENTION_DAYS", 0, 0, 3650),

		RemediationApprovalsEnabled: l.boolean("PROBECTL_REMEDIATION_APPROVALS_ENABLED", false),
		RemediationMaxBlastRadius:   l.intRange("PROBECTL_REMEDIATION_MAX_BLAST_RADIUS", 50, 1, 100000),
		// SCALE-004: bounded by DEFAULT; these env values must be >= 0 —
		// l.float REJECTS negatives at boot (fail closed). Unlimited is not
		// an env option: it exists only as an explicit per-tenant override
		// at the fairness engine (rate<=0 in take()). Defaults mirror
		// fairness.DefaultPolicy.
		FairnessResultsPerSec:       l.float("PROBECTL_FAIRNESS_RESULTS_PER_SEC", 1000),
		FairnessFlowEventsPerSec:    l.float("PROBECTL_FAIRNESS_FLOW_EVENTS_PER_SEC", 10000),
		FairnessIngestBytesPerSec:   l.float("PROBECTL_FAIRNESS_INGEST_BYTES_PER_SEC", 2<<20),
		FairnessDeviceMetricsPerSec: l.float("PROBECTL_FAIRNESS_DEVICE_METRICS_PER_SEC", 2000),
		FairnessOTLPSeriesPerSec:    l.float("PROBECTL_FAIRNESS_OTLP_SERIES_PER_SEC", 5000),
		FairnessBurstSeconds:        l.float("PROBECTL_FAIRNESS_BURST_SECONDS", 10),
		// SCALE-011: bound query load by DEFAULT (was 0/0 = unbounded, so one
		// tenant could monopolize the query path). 4 concurrent queries and 120
		// queries/min per tenant are generous for interactive + dashboard use
		// while capping a runaway client; 0 still means unbounded for operators
		// who deliberately opt out.
		FairnessQueryConcurrency: l.intRange("PROBECTL_FAIRNESS_QUERY_CONCURRENCY", 4, 0, 100000),
		FairnessQueriesPerMin:    l.float("PROBECTL_FAIRNESS_QUERIES_PER_MIN", 120),
		// SCALE-002: evict per-tenant fairness state idle past this window so the
		// gate's map stays bounded under tenant churn. 24h default; 0 falls back
		// to the engine default (also 24h).
		FairnessTenantIdleTTL: l.dur("PROBECTL_FAIRNESS_TENANT_IDLE_TTL", 24*time.Hour),

		SIEMEnabled:      l.boolean("PROBECTL_SIEM_ENABLED", false),
		SIEMPreset:       l.enum("PROBECTL_SIEM_PRESET", "generic", "generic", "splunk", "sentinel", "elastic", "chronicle"),
		SIEMFormat:       l.enum("PROBECTL_SIEM_FORMAT", "", "", "syslog", "cef", "ecs", "otlp"),
		SIEMEndpoint:     l.str("PROBECTL_SIEM_ENDPOINT", ""),
		SIEMToken:        l.str("PROBECTL_SIEM_TOKEN", ""),
		SIEMPollInterval: l.dur("PROBECTL_SIEM_POLL_INTERVAL", 30*time.Second),
		SIEMBufferSize:   l.intRange("PROBECTL_SIEM_BUFFER", 1024, 1, 1_000_000),
		SIEMRedactKeys:   l.list("PROBECTL_SIEM_REDACT_KEYS"),

		ChangeWebhooks:          l.changeWebhooks("PROBECTL_CHANGE_WEBHOOKS"),
		ChangeCorrelationWindow: l.dur("PROBECTL_CHANGE_CORRELATION_WINDOW", 24*time.Hour),

		NotifyConnectors: l.notifyConnectors("PROBECTL_NOTIFY_CONNECTORS"),
		NotifyInbound:    l.notifyInbound("PROBECTL_NOTIFY_INBOUND"),
	}

	// SCALE-001: when running the production prometheus ingest path, default
	// remote-write batching ON (coalesce results into one POST instead of one
	// POST per result). The boolean default above is false; flip it to true for
	// prometheus mode unless the operator set the env explicitly (explicit
	// always wins). Batching preserves per-message DLQ attribution.
	if cfg.TSDBMode == "prometheus" && l.getenv("PROBECTL_REMOTE_WRITE_BATCH_ENABLED") == "" {
		cfg.RemoteWriteBatchEnabled = true
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		l.errf("PROBECTL_TLS_CERT_FILE and PROBECTL_TLS_KEY_FILE must be set together")
	}
	if cfg.AuthMode == "session" && cfg.DeploymentProfile != "single" && len(cfg.SessionHMACKey) != crypto.KeySize {
		l.errf("PROBECTL_SESSION_HMAC_KEY is required and must be exactly %d bytes (%d hex chars) when PROBECTL_AUTH_MODE=session under the %s deployment profile", crypto.KeySize, crypto.KeySize*2, cfg.DeploymentProfile)
	}
	// AIRCA-002: a bad custom redaction pattern refuses START — never
	// silently redact less than the operator asked for.
	for _, part := range strings.Split(cfg.AIRedactCustom, ";;") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		if _, err := regexp.Compile(part); err != nil {
			l.errf("PROBECTL_AI_REDACT_PATTERNS: bad pattern %q: %v", part, err)
		}
	}
	if cfg.AgentGRPCAddr != "" && !cfg.AgentTransportEnabled() {
		l.errf("PROBECTL_AGENT_GRPC_ADDR requires mTLS: also set PROBECTL_AGENT_TLS_CERT_FILE, PROBECTL_AGENT_TLS_KEY_FILE, and PROBECTL_AGENT_TLS_CA_FILE")
	}
	if cfg.BusMode == "kafka" && len(cfg.BusBrokers) == 0 {
		l.errf("PROBECTL_BUS_MODE=kafka requires PROBECTL_BUS_BROKERS (a comma-separated host:port list)")
	}
	if cfg.BusMode == "kafka" {
		// U-010 fail-closed: kafka without TLS needs the explicit dev flag.
		if err := cfg.BusSecurity().Validate(); err != nil {
			l.errf("%s", err.Error())
		}
	}
	if cfg.TSDBMode == "prometheus" && cfg.TSDBURL == "" {
		l.errf("PROBECTL_TSDB_MODE=prometheus requires PROBECTL_TSDB_URL")
	}
	if cfg.PathStoreMode == "clickhouse" && cfg.PathStoreURL == "" {
		l.errf("PROBECTL_PATHSTORE_MODE=clickhouse requires PROBECTL_PATHSTORE_URL")
	}
	if cfg.FlowStoreMode == "clickhouse" && cfg.FlowStoreURL == "" {
		l.errf("PROBECTL_FLOWSTORE_MODE=clickhouse requires PROBECTL_FLOWSTORE_URL")
	}
	if cfg.OTelStoreMode == "clickhouse" && cfg.OTelStoreURL == "" {
		l.errf("PROBECTL_OTELSTORE_MODE=clickhouse requires PROBECTL_OTELSTORE_URL")
	}
	if cfg.CMDBProvider != "" {
		if cfg.CMDBURL == "" || cfg.CMDBSecret == "" {
			l.errf("PROBECTL_CMDB_PROVIDER=%s requires PROBECTL_CMDB_URL and PROBECTL_CMDB_SECRET", cfg.CMDBProvider)
		} else if !strings.HasPrefix(cfg.CMDBURL, "https://") && !isLoopbackURL(cfg.CMDBURL) {
			l.errf("PROBECTL_CMDB_URL must be https (plain http is allowed only for loopback test instances)")
		}
	}
	if (cfg.OTLPGRPCAddr != "" || cfg.OTLPHTTPAddr != "") && !cfg.OTLPEnabled() {
		l.errf("the OTLP receiver is TLS-only and authenticated: set PROBECTL_OTLP_TLS_CERT_FILE, PROBECTL_OTLP_TLS_KEY_FILE, and PROBECTL_OTLP_TOKENS (token=tenant,...) alongside an address")
	}
	// WIRE-002: the OTLP export path egresses confidential customer telemetry
	// (and a bearer token). It MUST be encrypted to a non-loopback collector
	// (guardrail 12). For protocol=http an http:// endpoint is cleartext POST;
	// for protocol=grpc the Insecure flag disables TLS. Fail closed unless the
	// operator has explicitly opted into insecure transport AND the target is
	// loopback (a co-located dev collector). Mirrors the CMDB https check.
	if cfg.OTLPExportEnabled() && !isLoopbackOTLPEndpoint(cfg.OTLPExportEndpoint) {
		switch cfg.OTLPExportProtocol {
		case "http":
			if !strings.HasPrefix(cfg.OTLPExportEndpoint, "https://") {
				l.errf("PROBECTL_OTLP_EXPORT_ENDPOINT must be https:// for a remote OTLP/HTTP collector — plaintext http:// would egress tenant telemetry + the bearer token in the clear (guardrail 12). Plain http is allowed only for a loopback endpoint.")
			}
		default: // grpc
			if cfg.OTLPExportInsecure {
				l.errf("PROBECTL_OTLP_EXPORT_INSECURE is only allowed for a loopback OTLP/gRPC collector, not %q (guardrail 12)", cfg.OTLPExportEndpoint)
			}
		}
	}
	if cfg.AIModelEnabled() && cfg.AIModelEndpoint == "" {
		l.errf("PROBECTL_AI_MODEL_PROVIDER=%s requires PROBECTL_AI_MODEL_ENDPOINT (a remote endpoint must be https; loopback may be http for a local model)", cfg.AIModelProvider)
	}
	if remoteAIEndpoint(cfg) && cfg.AIEgressAck != AIEgressAckPhrase {
		l.errf("PROBECTL_AI_MODEL_ENDPOINT is a REMOTE endpoint: tenant telemetry would leave the network (U-013). "+
			"Acknowledge explicitly with PROBECTL_AI_EGRESS_ACK=%q (see docs/ai-egress.md), or use a loopback local model / the builtin", AIEgressAckPhrase)
	}
	if cfg.MCPHTTPAddr != "" && !cfg.MCPEnabled() {
		l.errf("the MCP HTTP transport is TLS-only and authenticated: set PROBECTL_MCP_TLS_CERT_FILE and PROBECTL_MCP_TLS_KEY_FILE alongside PROBECTL_MCP_HTTP_ADDR")
	}

	if cfg.DatabaseMinConns > cfg.DatabaseMaxConns {
		l.errf("PROBECTL_DATABASE_MIN_CONNS (%d) must be <= PROBECTL_DATABASE_MAX_CONNS (%d)",
			cfg.DatabaseMinConns, cfg.DatabaseMaxConns)
	}
	if _, err := url.Parse(cfg.DatabaseURL); err != nil {
		l.errf("PROBECTL_DATABASE_URL: invalid URL: %v", err)
	}

	if err := l.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// BusSecurity renders the Kafka transport policy (U-010) for bus.New.
func (c *Config) BusSecurity() bus.Security {
	return bus.Security{
		TLSEnabled:         c.BusTLSEnabled,
		CAFile:             c.BusTLSCAFile,
		CertFile:           c.BusTLSCertFile,
		KeyFile:            c.BusTLSKeyFile,
		SASLMechanism:      c.BusSASLMechanism,
		SASLUser:           c.BusSASLUser,
		SASLPassword:       c.BusSASLPassword,
		AllowPlaintext:     c.BusAllowPlaintext,
		MaxBufferedRecords: c.BusMaxBuffered,
	}
}

// AIEgressAckPhrase is the exact operator acknowledgment required to run a
// REMOTE model endpoint (U-013): proof the off-network data flow is a
// deliberate decision, not a default.
const AIEgressAckPhrase = "yes-send-tenant-data-to-the-remote-model"

// remoteAIEndpoint reports whether the configured model endpoint leaves the
// host (non-loopback). The builtin provider and loopback Ollama/vLLM do not.
func remoteAIEndpoint(c *Config) bool {
	if !c.AIModelEnabled() || c.AIModelEndpoint == "" {
		return false
	}
	u, err := url.Parse(c.AIModelEndpoint)
	if err != nil || u.Hostname() == "" {
		return false // unparseable endpoints fail other validations
	}
	host := u.Hostname()
	if host == "localhost" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return false
	}
	return true
}

// LoadFromEnv resolves configuration from the process environment.
func LoadFromEnv() (*Config, error) { return Load(os.Getenv) }

// TLSEnabled reports whether the API should serve HTTPS directly — both a
// certificate and a key are configured. When false, TLS terminates at the ingress.
func (c *Config) TLSEnabled() bool { return c.TLSCertFile != "" && c.TLSKeyFile != "" }

// CookieSecure (SEC-009) decides the Secure attribute on every cookie: true
// when this process serves TLS itself OR the deployment edge does
// (PROBECTL_PUBLIC_TLS behind a TLS-terminating ingress). Browsers only see
// the edge, so the edge — not the app listener — is the right signal.
func (c *Config) CookieSecure() bool { return c.TLSEnabled() || c.PublicTLS }

// AgentTransportEnabled reports whether the agent gRPC transport should run — an
// address and the full mTLS material (cert, key, CA) are configured.
func (c *Config) AgentTransportEnabled() bool {
	return c.AgentGRPCAddr != "" && c.AgentTLSCertFile != "" && c.AgentTLSKeyFile != "" && c.AgentTLSCAFile != ""
}

// OTLPEnabled reports whether the OTLP receiver should run — an address, TLS
// cert+key, and at least one bearer token are configured. The receiver is
// TLS-only and authenticated (CLAUDE.md §7 guardrail 12).
func (c *Config) OTLPEnabled() bool {
	return (c.OTLPGRPCAddr != "" || c.OTLPHTTPAddr != "") &&
		c.OTLPTLSCertFile != "" && c.OTLPTLSKeyFile != "" && len(c.OTLPTokens) > 0
}

// OTLPExportEnabled reports whether the config-driven OTLP export pipeline
// should run (ARCH-007) — an external collector endpoint is configured.
func (c *Config) OTLPExportEnabled() bool { return c.OTLPExportEndpoint != "" }

// AIModelEnabled reports whether the AI assistant should call an external model
// endpoint. False means the default in-process built-in synthesizer — fully
// air-gapped, no network (CLAUDE.md §7 guardrail 2).
func (c *Config) AIModelEnabled() bool {
	return c.AIModelProvider != "" && c.AIModelProvider != "builtin"
}

// MCPEnabled reports whether the MCP HTTP transport should run — an address and
// TLS cert+key are configured. The transport is TLS-only and bearer-authenticated
// (CLAUDE.md §7 guardrail 12); the stdio transport is separate (local).
func (c *Config) MCPEnabled() bool {
	return c.MCPHTTPAddr != "" && c.MCPTLSCertFile != "" && c.MCPTLSKeyFile != ""
}

// LogValue implements slog.LogValuer so the config can be logged at startup
// without leaking the database password (CLAUDE.md §7 guardrail 6).
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http_addr", c.HTTPAddr),
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.Int("database_max_conns", int(c.DatabaseMaxConns)),
		slog.Bool("migrate_on_boot", c.MigrateOnBoot),
		slog.String("log_level", c.LogLevel),
		slog.String("log_format", c.LogFormat),
		slog.Bool("hsts_enabled", c.HSTSEnabled),
		slog.Bool("tls", c.TLSEnabled()),
		slog.Bool("agent_transport", c.AgentTransportEnabled()),
		slog.String("bus_mode", c.BusMode),
		slog.String("tsdb_mode", c.TSDBMode),
	)
}

// Redacted returns a safe-to-share snapshot of the configuration for the
// support bundle (S-EE4). It is an ALLOWLIST: only known-non-secret
// operational settings are included, DSNs are password-redacted, and NO
// secret field (envelope key, OIDC/CMDB/SIEM/AI secrets, bootstrap/OTLP/MCP
// tokens, webhook secrets) is ever reflected — a new secret field added later
// cannot leak because it is simply not on the list.
func (c *Config) Redacted() map[string]any {
	return map[string]any{
		"http_addr":                   c.HTTPAddr,
		"database_url":                redactURL(c.DatabaseURL),
		"database_read_url":           redactURL(c.DatabaseReadURL),
		"database_max_conns":          c.DatabaseMaxConns,
		"database_min_conns":          c.DatabaseMinConns,
		"migrate_on_boot":             c.MigrateOnBoot,
		"log_level":                   c.LogLevel,
		"log_format":                  c.LogFormat,
		"auth_mode":                   c.AuthMode,
		"hsts_enabled":                c.HSTSEnabled,
		"tls_enabled":                 c.TLSEnabled(),
		"agent_transport":             c.AgentTransportEnabled(),
		"bus_mode":                    c.BusMode,
		"tsdb_mode":                   c.TSDBMode,
		"otlp_enabled":                c.OTLPEnabled(),
		"ai_model_enabled":            c.AIModelEnabled(),
		"mcp_enabled":                 c.MCPEnabled(),
		"oidc_issuer":                 c.OIDCIssuer, // an issuer URL is not a secret
		"region":                      c.Region,
		"regions":                     c.Regions,
		"residency":                   c.Residency,
		"replication_mode":            c.ReplicationMode,
		"flow_retention_days":         c.FlowRetentionDays,
		"backup_retention_note":       c.BackupRetentionNote,
		"data_planes_configured":      c.DataPlanes != "",
		"envelope_key_configured":     c.EnvelopeKey != "", // a boolean, never the key
		"session_hmac_key_configured": len(c.SessionHMACKey) == crypto.KeySize,
	}
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}
	if u.User != nil {
		if _, hasPW := u.User.Password(); hasPW {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.String()
}

// loader reads keys and accumulates validation errors.
type loader struct {
	getenv func(string) string
	errs   []error
}

// isLoopbackURL reports whether u targets a loopback host (test instances may
// use plain http there; everything else must be https).
func isLoopbackURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// isLoopbackOTLPEndpoint reports whether an OTLP export endpoint targets a
// loopback host. The endpoint may carry an https://, http://, or grpc://
// scheme prefix, or none at all (gRPC dial targets are often host:port).
func isLoopbackOTLPEndpoint(ep string) bool {
	host := ep
	for _, p := range []string{"https://", "http://", "grpc://"} {
		host = strings.TrimPrefix(host, p)
	}
	if i := strings.IndexAny(host, "/"); i >= 0 {
		host = host[:i]
	}
	// Strip the port if present (handle bare IPv6 in brackets too).
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			host = host[1:i]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (l *loader) str(key, def string) string {
	if v := l.getenv(key); v != "" {
		return v
	}
	return def
}

func (l *loader) dur(key string, def time.Duration) time.Duration {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errf("%s: invalid duration %q: %v", key, v, err)
		return def
	}
	if d < 0 {
		l.errf("%s: must not be negative", key)
		return def
	}
	return d
}

func (l *loader) float(key string, def float64) float64 {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		l.errf("%s: invalid number %q: %v", key, v, err)
		return def
	}
	if f < 0 {
		l.errf("%s: must not be negative", key)
		return def
	}
	return f
}

func (l *loader) intRange(key string, def, lo, hi int) int {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errf("%s: invalid integer %q", key, v)
		return def
	}
	if n < lo || n > hi {
		l.errf("%s: %d out of range [%d,%d]", key, n, lo, hi)
		return def
	}
	return n
}

// list parses a comma-separated value into a trimmed, non-empty slice.
func (l *loader) list(key string) []string {
	v := l.getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tokenMap parses "token1=tenant1,token2=tenant2" into a bearer-token→tenant map.
func (l *loader) tokenMap(key string) map[string]string {
	v := l.getenv(key)
	if v == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(v, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		token, tenant := "", ""
		if eq > 0 {
			token = strings.TrimSpace(pair[:eq])
			tenant = strings.TrimSpace(pair[eq+1:])
		}
		if token == "" || tenant == "" {
			l.errf("%s: %q must be token=tenant", key, pair)
			continue
		}
		out[token] = tenant
	}
	return out
}

// knownChangeProviders is the allowlist a change-webhook credential's provider
// must name. Kept here (rather than importing internal/change) so config stays a
// low-level package; it is asserted against the change registry in tests.
var knownChangeProviders = map[string]bool{"generic": true, "github": true, "gitlab": true}

// changeWebhooks parses "id:tenant:provider:secret,..." into a webhook-id→credential
// map (S29). The secret is the last field (SplitN=4) so it may contain ':' but not
// ','; generate URL-safe (hex/base64) secrets. The id is a non-secret URL selector;
// the tenant is bound here, never taken from the payload.
func (l *loader) changeWebhooks(key string) map[string]ChangeWebhook {
	v := l.getenv(key)
	if v == "" {
		return nil
	}
	out := map[string]ChangeWebhook{}
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		f := strings.SplitN(entry, ":", 4)
		if len(f) != 4 {
			l.errf("%s: %q must be id:tenant:provider:secret", key, entry)
			continue
		}
		id, tenant, provider, secret := strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.ToLower(strings.TrimSpace(f[2])), f[3]
		if id == "" || tenant == "" || provider == "" || secret == "" {
			l.errf("%s: %q has an empty field (id:tenant:provider:secret)", key, entry)
			continue
		}
		if !knownChangeProviders[provider] {
			l.errf("%s: unknown provider %q (want generic|github|gitlab)", key, provider)
			continue
		}
		out[id] = ChangeWebhook{TenantID: tenant, Provider: provider, Secret: secret}
	}
	return out
}

// knownNotifyProviders is the supported on-call/ITSM connector set (S33).
var knownNotifyProviders = map[string]bool{
	"pagerduty": true, "opsgenie": true, "slack": true,
	"teams": true, "servicenow": true, "jira": true,
}

// notifyConnectors parses "tenant|provider|endpoint|secret,..." into outbound
// connectors (S33). Fields are pipe-delimited because the endpoint is a URL (it
// contains ':'); entries are comma-separated. The secret is the last field and may
// contain '|' but not ',' — use URL-safe tokens.
func (l *loader) notifyConnectors(key string) []NotifyConnector {
	v := l.getenv(key)
	if v == "" {
		return nil
	}
	var out []NotifyConnector
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		f := strings.SplitN(entry, "|", 4)
		if len(f) != 4 {
			l.errf("%s: %q must be tenant|provider|endpoint|secret", key, entry)
			continue
		}
		tenant, provider, endpoint, secret := strings.TrimSpace(f[0]), strings.ToLower(strings.TrimSpace(f[1])), strings.TrimSpace(f[2]), f[3]
		if tenant == "" || provider == "" || endpoint == "" {
			l.errf("%s: %q has an empty field (tenant|provider|endpoint|secret)", key, entry)
			continue
		}
		if !knownNotifyProviders[provider] {
			l.errf("%s: unknown provider %q", key, provider)
			continue
		}
		out = append(out, NotifyConnector{TenantID: tenant, Provider: provider, Endpoint: endpoint, Secret: secret})
	}
	return out
}

// notifyInbound parses "id:tenant:provider:secret,..." into inbound status-sync
// credentials (S33). No endpoint (the URL is probectl's own), so it mirrors the
// change-webhook colon form: the secret is last and may contain ':' but not ','.
func (l *loader) notifyInbound(key string) map[string]NotifyInbound {
	v := l.getenv(key)
	if v == "" {
		return nil
	}
	out := map[string]NotifyInbound{}
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		f := strings.SplitN(entry, ":", 4)
		if len(f) != 4 {
			l.errf("%s: %q must be id:tenant:provider:secret", key, entry)
			continue
		}
		id, tenant, provider, secret := strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.ToLower(strings.TrimSpace(f[2])), f[3]
		if id == "" || tenant == "" || provider == "" || secret == "" {
			l.errf("%s: %q has an empty field (id:tenant:provider:secret)", key, entry)
			continue
		}
		if !knownNotifyProviders[provider] {
			l.errf("%s: unknown provider %q", key, provider)
			continue
		}
		out[id] = NotifyInbound{TenantID: tenant, Provider: provider, Secret: secret}
	}
	return out
}

func (l *loader) boolean(key string, def bool) bool {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.errf("%s: invalid boolean %q", key, v)
		return def
	}
	return b
}

func (l *loader) enum(key, def string, allowed ...string) string {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	v = strings.ToLower(v)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	l.errf("%s: %q is not one of [%s]", key, v, strings.Join(allowed, ", "))
	return def
}

func (l *loader) errf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) err() error { return errors.Join(l.errs...) }

// hexBytes decodes a hex-encoded byte slice from an env var. Returns nil when
// the env var is unset; records a validation error when set but not valid hex or
// not exactly wantLen bytes long.
func (l *loader) hexBytes(key string, wantLen int) []byte {
	v := l.getenv(key)
	if v == "" {
		return nil
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		l.errf("%s: invalid hex encoding: %v", key, err)
		return nil
	}
	if wantLen > 0 && len(b) != wantLen {
		l.errf("%s: key must be exactly %d bytes (%d hex chars), got %d bytes", key, wantLen, wantLen*2, len(b))
		return nil
	}
	return b
}
