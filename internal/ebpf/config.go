// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/configschema"
)

const ConfigAPIVersion = "probectl.io/ebpf-agent/v1"

// Config is the eBPF agent configuration: a YAML file with PROBECTL_EBPF_*
// environment overrides. Every key is documented in docs/configuration.md.
type Config struct {
	APIVersion    string `yaml:"apiVersion"`
	SchemaVersion int    `yaml:"schema_version,omitempty"`

	// TenantID binds every emitted flow to one tenant (F50). In production the
	// agent derives this from its SPIFFE client-cert identity (like the canary
	// agent); the explicit field supports the lightweight / single-tenant deploy.
	TenantID string `yaml:"tenant_id"`
	Host     string `yaml:"host"`

	// Bus is where flow + service-edge batches are published (probectl.ebpf.flows).
	Bus BusConfig `yaml:"bus"`

	// FixturePath, when set, replays recorded flows instead of loading eBPF —
	// the no-kernel path used by CI, macOS, and unprivileged containers.
	FixturePath string `yaml:"fixture_path"`

	// L7FixturePath, when set, replays recorded L7 events (the no-kernel path for
	// L7 visibility, S21). Live L7 capture otherwise requires -tags ebpf.
	L7FixturePath string `yaml:"l7_fixture_path"`

	// ProcRoot is the procfs root used for enrichment ("" => /proc).
	ProcRoot string `yaml:"proc_root"`

	// FlushInterval is how often accumulated flows + the service map are emitted.
	FlushInterval time.Duration `yaml:"flush_interval"`

	// Map bounds (EBPF-001/SCALE-003/FUZZ-001). On a busy or hostile host the
	// service map and the L7 per-connection maps would otherwise grow without
	// limit. MaxServiceEdges caps the live service-edge set (LRU evict);
	// MaxL7Conns caps live L7 trackers; L7ConnIdleTTL abandons a connection idle
	// for this long (also the service-map idle window). Zero leaves a bound
	// UNSET (unbounded — lightweight/test mode only); Default() sets sane caps.
	MaxServiceEdges int           `yaml:"max_service_edges"`
	MaxL7Conns      int           `yaml:"max_l7_conns"`
	L7ConnIdleTTL   time.Duration `yaml:"l7_conn_idle_ttl"`

	// HealthAddr binds the compatibility liveness/readiness HTTP probe server
	// (OPS-001), e.g. ":9090". Empty disables it. Kubernetes uses
	// HealthStateDir by default so no plaintext listener is opened.
	HealthAddr string `yaml:"health_addr"`

	// HealthStateDir writes exec-probe health state files, avoiding any
	// plaintext listener in Kubernetes. Empty disables file health.
	HealthStateDir string `yaml:"health_state_dir"`

	// RingBufferBytes sizes the kernel ring buffer (live source only); it is
	// rounded to a valid power-of-two page multiple at load (U-050) and must
	// not exceed maxRingBufferBytes (EBPF-005). 0 = the 16 MiB default.
	RingBufferBytes int `yaml:"ring_buffer_bytes"`

	// TLS-plaintext capture policy (U-003 + EBPF-001/002): live sslsniff
	// capture is OFF by default and requires THREE explicit statements — the
	// enable flag, a per-tenant consent naming this agent's tenant, and a
	// process-scope allowlist naming the opted-in workloads (host-wide
	// capture is not expressible). L7CaptureRedaction selects the boundary
	// policy ("headers" default — bodies zeroed before any retention;
	// "length" — no payload bytes at all; "full" only for consented
	// debugging).
	L7CaptureEnabled       bool   `yaml:"l7_capture_enabled"`
	L7CaptureConsentTenant string `yaml:"l7_capture_consent_tenant"`
	L7CaptureRedaction     string `yaml:"l7_capture_redaction"`

	// L7CaptureScope is the EXPLICIT workload opt-in (EBPF-001/RED-003):
	// entries pid:<n>, exe:/abs/path, cgroup:/abs/cgroup-dir. The kernel
	// program drops everything else before copying a byte. Container/pod
	// scoping is the cgroup form (a container IS a cgroup).
	L7CaptureScope []string `yaml:"l7_capture_scope"`

	// L7CaptureKernelWindow bounds plaintext bytes per chunk that may
	// transit the kernel ring under "headers" redaction (EBPF-002).
	// 0 = default (1024). Bounds: 128..4095. "length" forces 0; "full"
	// forces 4095.
	L7CaptureKernelWindow int `yaml:"l7_capture_kernel_window"`
}

// BusConfig selects the bus backend for emission.
type BusConfig struct {
	Mode    string   `yaml:"mode"`    // memory | kafka
	Brokers []string `yaml:"brokers"` // kafka mode
	// Namespace routes this tenant's batches onto its SILOED bus lane
	// (TENANT-107): topics become probectl.<namespace>.<...>. Empty = the
	// shared (pooled) lane. A malformed value refuses agent start (RED-006).
	Namespace string `yaml:"namespace"`
}

// Default returns the built-in defaults (memory bus, /proc, 10s flush, 16 MiB ring).
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{
		Host:               host,
		Bus:                BusConfig{Mode: "memory"},
		ProcRoot:           "/proc",
		FlushInterval:      10 * time.Second,
		RingBufferBytes:    1 << 24,
		L7CaptureRedaction: RedactHeaders, // U-003: capture off by default; bodies zeroed when on
		// EBPF-001/SCALE-003/FUZZ-001: bound the live maps by default so the
		// shipped production agent enforces the cap (not just tests).
		MaxServiceEdges: 50_000,
		MaxL7Conns:      8192,
		L7ConnIdleTTL:   5 * time.Minute,
	}
}

// Load reads the YAML config at path (if non-empty), applies PROBECTL_EBPF_*
// environment overrides, and validates the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ebpf config: %w", err)
		}
		if err := decodeConfigYAML(data, cfg); err != nil {
			return nil, fmt.Errorf("parse ebpf config: %w", err)
		}
	}
	cfg.applyEnv(os.Getenv)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decodeConfigYAML(raw []byte, cfg *Config) error {
	if err := configschema.DecodeStrictYAML(raw, cfg); err != nil {
		return err
	}
	apiVersion, err := configschema.ResolveAPIVersion("ebpf", cfg.APIVersion, cfg.SchemaVersion, ConfigAPIVersion)
	if err != nil {
		return err
	}
	cfg.APIVersion = apiVersion
	return nil
}

func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("PROBECTL_EBPF_TENANT_ID"); v != "" {
		c.TenantID = v
	}
	if v := getenv("PROBECTL_EBPF_HOST"); v != "" {
		c.Host = v
	}
	if v := getenv("PROBECTL_EBPF_BUS_MODE"); v != "" {
		c.Bus.Mode = v
	}
	if v := getenv("PROBECTL_EBPF_BUS_BROKERS"); v != "" {
		c.Bus.Brokers = splitComma(v)
	}
	if v := getenv("PROBECTL_EBPF_BUS_NAMESPACE"); v != "" {
		c.Bus.Namespace = v
	}
	if v := getenv("PROBECTL_EBPF_FIXTURE_PATH"); v != "" {
		c.FixturePath = v
	}
	if v := getenv("PROBECTL_EBPF_L7_FIXTURE_PATH"); v != "" {
		c.L7FixturePath = v
	}
	if v := getenv("PROBECTL_EBPF_PROC_ROOT"); v != "" {
		c.ProcRoot = v
	}
	if v := getenv("PROBECTL_EBPF_RING_BUFFER_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.RingBufferBytes = n
		}
	}
	if v := getenv("PROBECTL_EBPF_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.FlushInterval = d
		}
	}
	if v := getenv("PROBECTL_EBPF_MAX_SERVICE_EDGES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxServiceEdges = n
		}
	}
	if v := getenv("PROBECTL_EBPF_MAX_L7_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxL7Conns = n
		}
	}
	if v := getenv("PROBECTL_EBPF_L7_CONN_IDLE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.L7ConnIdleTTL = d
		}
	}
	if v := getenv("PROBECTL_EBPF_HEALTH_ADDR"); v != "" {
		c.HealthAddr = v
	}
	if v := getenv("PROBECTL_EBPF_HEALTH_STATE_DIR"); v != "" {
		c.HealthStateDir = v
	}
	if v := getenv("PROBECTL_EBPF_L7_CAPTURE"); v != "" {
		c.L7CaptureEnabled = v == "true"
	}
	if v := getenv("PROBECTL_EBPF_L7_CONSENT_TENANT"); v != "" {
		c.L7CaptureConsentTenant = v
	}
	if v := getenv("PROBECTL_EBPF_L7_REDACTION"); v != "" {
		c.L7CaptureRedaction = v
	}
	if v := getenv("PROBECTL_EBPF_L7_SCOPE"); v != "" {
		c.L7CaptureScope = splitComma(v)
	}
	if v := getenv("PROBECTL_EBPF_L7_KERNEL_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.L7CaptureKernelWindow = n
		}
	}
}

func (c *Config) validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("ebpf: tenant_id is required (PROBECTL_EBPF_TENANT_ID or config)")
	}
	switch c.Bus.Mode {
	case "memory", "kafka":
	default:
		return fmt.Errorf("ebpf: invalid bus mode %q (memory|kafka)", c.Bus.Mode)
	}
	if c.Bus.Mode == "kafka" && len(c.Bus.Brokers) == 0 {
		return fmt.Errorf("ebpf: kafka bus requires brokers")
	}
	if c.FlushInterval <= 0 {
		return fmt.Errorf("ebpf: flush_interval must be > 0")
	}
	if c.L7CaptureRedaction != "" && !validRedactionMode(c.L7CaptureRedaction) {
		return fmt.Errorf("ebpf: l7_capture_redaction %q (want %s|%s|%s)", c.L7CaptureRedaction, RedactHeaders, RedactLengthOnly, RedactFull)
	}
	if c.L7CaptureEnabled && c.L7CaptureConsentTenant == "" {
		return fmt.Errorf("ebpf: l7_capture_enabled requires l7_capture_consent_tenant (the EXPLICIT per-tenant consent, U-003)")
	}
	if c.L7CaptureEnabled && len(c.L7CaptureScope) == 0 {
		return fmt.Errorf("ebpf: l7_capture_enabled requires l7_capture_scope — name the opted-in workloads (pid:<n>|exe:/path|cgroup:/path); host-wide capture is not expressible (EBPF-001)")
	}
	if _, err := ParseScopeEntries(c.L7CaptureScope); err != nil {
		return err
	}
	if w := c.L7CaptureKernelWindow; w != 0 && (w < minKernelWindow || w > maxKernelWindow) {
		return fmt.Errorf("ebpf: l7_capture_kernel_window %d out of bounds (%d..%d, 0 = default %d)", w, minKernelWindow, maxKernelWindow, defaultKernelWindow)
	}
	// EBPF-005: cap the ring buffer. ringBufferBytes() rounds UP to the next
	// power of two, so an over-large request would silently pin hundreds of MiB
	// (or more) of unswappable kernel memory per agent. Refuse it at config
	// time with a clear bounds error rather than rounding it up at Load().
	if c.RingBufferBytes > maxRingBufferBytes {
		return fmt.Errorf("ebpf: ring_buffer_bytes %d exceeds the maximum %d (256 MiB); pick a smaller size (0 = default %d)", c.RingBufferBytes, maxRingBufferBytes, 1<<24)
	}
	return nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
