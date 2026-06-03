// Package config loads and validates the netctl control-plane configuration
// from NETCTL_-prefixed environment variables. Every key is documented in
// docs/configuration.md (CLAUDE.md §6). Load reports all validation problems at
// once so a misconfiguration is fixed in a single pass.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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
	DatabaseMaxConns    int32
	DatabaseMinConns    int32
	DatabaseConnTimeout time.Duration

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
	TSDBMode   string
	TSDBURL    string

	// Alerting (S16): how often the engine evaluates enabled rules over the TSDB.
	AlertEvalInterval time.Duration

	// Incidents (S17): the time window within which related signals correlate
	// into one incident.
	IncidentWindow time.Duration

	// SecurityContact (S19) is advertised at /.well-known/security.txt (RFC 9116)
	// as this deployment's vulnerability-disclosure contact (e.g.
	// "mailto:security@your-org.example"). Operator-configured.
	SecurityContact string

	// Identity & access (S18). AuthMode: "session" (real OIDC SSO + RBAC) or
	// "dev" (trusted-header dev principal with all permissions — never in prod).
	AuthMode         string
	SessionTTL       time.Duration
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	// Path store (S10/S11): where discovered network paths are persisted and
	// served. memory (default) or clickhouse (a ClickHouse HTTP URL).
	PathStoreMode string
	PathStoreURL  string

	// OTLP receiver (S22): TLS-only, authenticated, tenant-scoped ingest of
	// external OTLP. Enabled when an address + TLS cert/key + tokens are all set.
	OTLPGRPCAddr    string
	OTLPHTTPAddr    string
	OTLPTLSCertFile string
	OTLPTLSKeyFile  string
	OTLPTokens      map[string]string // bearer token -> tenant id

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

	// MCP server (S25): the Model Context Protocol HTTP transport (network-
	// exposed). Enabled when an address + TLS cert/key are all set; it is TLS-only
	// and bearer-authenticated (guardrail 12). The stdio transport is local
	// (netctl-control mcp-stdio) and reads its token from NETCTL_MCP_TOKEN.
	// MCPRatePerMin caps per-tenant tool-call volume.
	MCPHTTPAddr    string
	MCPTLSCertFile string
	MCPTLSKeyFile  string
	MCPRatePerMin  int

	// Security / threat (S27): TLS/cert posture over already-captured TLS (S13/S21).
	// CertctlURL deep-links cert findings to certctl for renewal; TLSExpiryWarning
	// is the expiring-soon window. CT correlation is OPT-IN (CTEnabled) — an
	// external fetch (AUP / sovereignty / no-phone-home), off by default.
	CertctlURL       string
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
	cfg := &Config{
		HTTPAddr:            l.str("NETCTL_HTTP_ADDR", ":8080"),
		ReadTimeout:         l.dur("NETCTL_HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:        l.dur("NETCTL_HTTP_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:         l.dur("NETCTL_HTTP_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout:     l.dur("NETCTL_SHUTDOWN_TIMEOUT", 15*time.Second),
		DatabaseURL:         l.str("NETCTL_DATABASE_URL", "postgres://netctl:netctl@localhost:5432/netctl?sslmode=disable"),
		DatabaseMaxConns:    int32(l.intRange("NETCTL_DATABASE_MAX_CONNS", 10, 1, 1000)),
		DatabaseMinConns:    int32(l.intRange("NETCTL_DATABASE_MIN_CONNS", 0, 0, 1000)),
		DatabaseConnTimeout: l.dur("NETCTL_DATABASE_CONNECT_TIMEOUT", 5*time.Second),
		MigrateOnBoot:       l.boolean("NETCTL_MIGRATE_ON_BOOT", false),
		LogLevel:            l.enum("NETCTL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:           l.enum("NETCTL_LOG_FORMAT", "json", "json", "text"),
		HSTSEnabled:         l.boolean("NETCTL_HSTS_ENABLED", true),
		HSTSMaxAge:          l.dur("NETCTL_HSTS_MAX_AGE", 365*24*time.Hour),
		TLSCertFile:         l.str("NETCTL_TLS_CERT_FILE", ""),
		TLSKeyFile:          l.str("NETCTL_TLS_KEY_FILE", ""),
		EnvelopeKey:         l.str("NETCTL_ENVELOPE_KEY", ""),
		EnvelopeKeyID:       l.str("NETCTL_ENVELOPE_KEY_ID", "dev"),
		AgentGRPCAddr:       l.str("NETCTL_AGENT_GRPC_ADDR", ""),
		AgentSkewWindow:     l.intRange("NETCTL_AGENT_SKEW_WINDOW", 1, 0, 100),
		AgentMinVersion:     l.str("NETCTL_AGENT_MIN_VERSION", ""),
		AgentTLSCertFile:    l.str("NETCTL_AGENT_TLS_CERT_FILE", ""),
		AgentTLSKeyFile:     l.str("NETCTL_AGENT_TLS_KEY_FILE", ""),
		AgentTLSCAFile:      l.str("NETCTL_AGENT_TLS_CA_FILE", ""),
		BusMode:             l.enum("NETCTL_BUS_MODE", "memory", "memory", "kafka"),
		BusBrokers:          l.list("NETCTL_BUS_BROKERS"),
		TSDBMode:            l.enum("NETCTL_TSDB_MODE", "memory", "memory", "prometheus"),
		TSDBURL:             l.str("NETCTL_TSDB_URL", ""),
		PathStoreMode:       l.enum("NETCTL_PATHSTORE_MODE", "memory", "memory", "clickhouse"),
		PathStoreURL:        l.str("NETCTL_PATHSTORE_URL", ""),
		AlertEvalInterval:   l.dur("NETCTL_ALERT_EVAL_INTERVAL", 30*time.Second),
		IncidentWindow:      l.dur("NETCTL_INCIDENT_WINDOW", 10*time.Minute),
		AuthMode:            l.enum("NETCTL_AUTH_MODE", "dev", "dev", "session"),
		SessionTTL:          l.dur("NETCTL_SESSION_TTL", 12*time.Hour),
		OIDCIssuer:          l.str("NETCTL_OIDC_ISSUER", ""),
		OIDCClientID:        l.str("NETCTL_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:    l.str("NETCTL_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:     l.str("NETCTL_OIDC_REDIRECT_URL", ""),
		SecurityContact:     l.str("NETCTL_SECURITY_CONTACT", ""),
		OTLPGRPCAddr:        l.str("NETCTL_OTLP_GRPC_ADDR", ""),
		OTLPHTTPAddr:        l.str("NETCTL_OTLP_HTTP_ADDR", ""),
		OTLPTLSCertFile:     l.str("NETCTL_OTLP_TLS_CERT_FILE", ""),
		OTLPTLSKeyFile:      l.str("NETCTL_OTLP_TLS_KEY_FILE", ""),
		OTLPTokens:          l.tokenMap("NETCTL_OTLP_TOKENS"),
		AIModelProvider:     l.enum("NETCTL_AI_MODEL_PROVIDER", "builtin", "builtin", "ollama", "openai", "anthropic"),
		AIModelEndpoint:     l.str("NETCTL_AI_MODEL_ENDPOINT", ""),
		AIModelName:         l.str("NETCTL_AI_MODEL_NAME", ""),
		AIModelToken:        l.str("NETCTL_AI_MODEL_TOKEN", ""),
		AIModelTimeout:      l.dur("NETCTL_AI_MODEL_TIMEOUT", 60*time.Second),
		AIMaxEvidence:       l.intRange("NETCTL_AI_MAX_EVIDENCE", 50, 1, 1000),
		MCPHTTPAddr:         l.str("NETCTL_MCP_HTTP_ADDR", ""),
		MCPTLSCertFile:      l.str("NETCTL_MCP_TLS_CERT_FILE", ""),
		MCPTLSKeyFile:       l.str("NETCTL_MCP_TLS_KEY_FILE", ""),
		MCPRatePerMin:       l.intRange("NETCTL_MCP_RATE_PER_MIN", 120, 0, 100000),
		CertctlURL:          l.str("NETCTL_CERTCTL_URL", ""),
		TLSExpiryWarning:    l.dur("NETCTL_TLS_EXPIRY_WARNING", 21*24*time.Hour),
		CTEnabled:           l.boolean("NETCTL_CT_ENABLED", false),
		CTEndpoint:          l.str("NETCTL_CT_ENDPOINT", "https://crt.sh"),
		ThreatIntelEnabled:  l.boolean("NETCTL_THREATINTEL_ENABLED", false),
		ThreatIntelRefresh:  l.dur("NETCTL_THREATINTEL_REFRESH", 6*time.Hour),
		ThreatIntelFeeds:    l.list("NETCTL_THREATINTEL_FEEDS"),

		SIEMEnabled:      l.boolean("NETCTL_SIEM_ENABLED", false),
		SIEMPreset:       l.enum("NETCTL_SIEM_PRESET", "generic", "generic", "splunk", "sentinel", "elastic", "chronicle"),
		SIEMFormat:       l.enum("NETCTL_SIEM_FORMAT", "", "", "syslog", "cef", "ecs", "otlp"),
		SIEMEndpoint:     l.str("NETCTL_SIEM_ENDPOINT", ""),
		SIEMToken:        l.str("NETCTL_SIEM_TOKEN", ""),
		SIEMPollInterval: l.dur("NETCTL_SIEM_POLL_INTERVAL", 30*time.Second),
		SIEMBufferSize:   l.intRange("NETCTL_SIEM_BUFFER", 1024, 1, 1_000_000),
		SIEMRedactKeys:   l.list("NETCTL_SIEM_REDACT_KEYS"),

		ChangeWebhooks:          l.changeWebhooks("NETCTL_CHANGE_WEBHOOKS"),
		ChangeCorrelationWindow: l.dur("NETCTL_CHANGE_CORRELATION_WINDOW", 24*time.Hour),

		NotifyConnectors: l.notifyConnectors("NETCTL_NOTIFY_CONNECTORS"),
		NotifyInbound:    l.notifyInbound("NETCTL_NOTIFY_INBOUND"),
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		l.errf("NETCTL_TLS_CERT_FILE and NETCTL_TLS_KEY_FILE must be set together")
	}
	if cfg.AgentGRPCAddr != "" && !cfg.AgentTransportEnabled() {
		l.errf("NETCTL_AGENT_GRPC_ADDR requires mTLS: also set NETCTL_AGENT_TLS_CERT_FILE, NETCTL_AGENT_TLS_KEY_FILE, and NETCTL_AGENT_TLS_CA_FILE")
	}
	if cfg.BusMode == "kafka" && len(cfg.BusBrokers) == 0 {
		l.errf("NETCTL_BUS_MODE=kafka requires NETCTL_BUS_BROKERS (a comma-separated host:port list)")
	}
	if cfg.TSDBMode == "prometheus" && cfg.TSDBURL == "" {
		l.errf("NETCTL_TSDB_MODE=prometheus requires NETCTL_TSDB_URL")
	}
	if cfg.PathStoreMode == "clickhouse" && cfg.PathStoreURL == "" {
		l.errf("NETCTL_PATHSTORE_MODE=clickhouse requires NETCTL_PATHSTORE_URL")
	}
	if (cfg.OTLPGRPCAddr != "" || cfg.OTLPHTTPAddr != "") && !cfg.OTLPEnabled() {
		l.errf("the OTLP receiver is TLS-only and authenticated: set NETCTL_OTLP_TLS_CERT_FILE, NETCTL_OTLP_TLS_KEY_FILE, and NETCTL_OTLP_TOKENS (token=tenant,...) alongside an address")
	}
	if cfg.AIModelEnabled() && cfg.AIModelEndpoint == "" {
		l.errf("NETCTL_AI_MODEL_PROVIDER=%s requires NETCTL_AI_MODEL_ENDPOINT (a remote endpoint must be https; loopback may be http for a local model)", cfg.AIModelProvider)
	}
	if cfg.MCPHTTPAddr != "" && !cfg.MCPEnabled() {
		l.errf("the MCP HTTP transport is TLS-only and authenticated: set NETCTL_MCP_TLS_CERT_FILE and NETCTL_MCP_TLS_KEY_FILE alongside NETCTL_MCP_HTTP_ADDR")
	}

	if cfg.DatabaseMinConns > cfg.DatabaseMaxConns {
		l.errf("NETCTL_DATABASE_MIN_CONNS (%d) must be <= NETCTL_DATABASE_MAX_CONNS (%d)",
			cfg.DatabaseMinConns, cfg.DatabaseMaxConns)
	}
	if _, err := url.Parse(cfg.DatabaseURL); err != nil {
		l.errf("NETCTL_DATABASE_URL: invalid URL: %v", err)
	}

	if err := l.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadFromEnv resolves configuration from the process environment.
func LoadFromEnv() (*Config, error) { return Load(os.Getenv) }

// TLSEnabled reports whether the API should serve HTTPS directly — both a
// certificate and a key are configured. When false, TLS terminates at the ingress.
func (c *Config) TLSEnabled() bool { return c.TLSCertFile != "" && c.TLSKeyFile != "" }

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
// credentials (S33). No endpoint (the URL is netctl's own), so it mirrors the
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
