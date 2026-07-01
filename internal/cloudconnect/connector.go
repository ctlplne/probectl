// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package cloudconnect pulls read-only cloud telemetry metadata into probectl.
// It is deliberately SDK-free: deployments point each connector at an
// operator-approved HTTPS endpoint or proxy, credentials are read-only, results
// are tenant-stamped from config, and the last good snapshot is cached so a
// provider outage degrades instead of breaking correlation.
package cloudconnect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/flow"
)

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"

	maxSnapshotBytes = 4 << 20
)

var (
	ErrTenantRequired      = errors.New("cloudconnect: tenant_id is required")
	ErrUnknownProvider     = errors.New("cloudconnect: unknown provider")
	ErrReadOnlyCredentials = errors.New("cloudconnect: credentials must be read-only")
	ErrHTTPSEndpoint       = errors.New("cloudconnect: endpoint must be https")
)

// Provider identifies the cloud adapter.
type Provider string

// Credential describes one read-only cloud principal. Token is secret material
// resolved by the caller from the existing secret-reference layer.
type Credential struct {
	Principal string
	Token     string
	Scopes    []string
}

// Config configures one tenant-bound cloud connector.
type Config struct {
	TenantID   string
	Provider   Provider
	AccountID  string
	Region     string
	Endpoint   string
	Credential Credential
	Client     *http.Client
	Now        func() time.Time
}

// Metric is one normalized cloud metric sample.
type Metric struct {
	TenantID   string            `json:"tenant_id"`
	Provider   Provider          `json:"provider"`
	AccountID  string            `json:"account_id"`
	Region     string            `json:"region"`
	ResourceID string            `json:"resource_id"`
	Name       string            `json:"name"`
	Unit       string            `json:"unit"`
	Value      float64           `json:"value"`
	Timestamp  time.Time         `json:"timestamp"`
	Labels     map[string]string `json:"labels,omitempty"`
	Provenance map[string]string `json:"provenance,omitempty"`
}

// FlowObject is one provider object that contains flow-log records ready for the
// existing cloudflow importer after the operator's export pipeline makes it local.
type FlowObject struct {
	TenantID   string            `json:"tenant_id"`
	Provider   Provider          `json:"provider"`
	AccountID  string            `json:"account_id"`
	Region     string            `json:"region"`
	URI        string            `json:"uri"`
	Format     string            `json:"format"`
	UpdatedAt  time.Time         `json:"updated_at"`
	SizeBytes  int64             `json:"size_bytes"`
	Provenance map[string]string `json:"provenance,omitempty"`
}

// Snapshot is one pull result. Down-source degradation returns the last cached
// snapshot with Degraded=true instead of failing the caller.
type Snapshot struct {
	TenantID    string       `json:"tenant_id"`
	Provider    Provider     `json:"provider"`
	AccountID   string       `json:"account_id"`
	Region      string       `json:"region"`
	Metrics     []Metric     `json:"metrics"`
	FlowObjects []FlowObject `json:"flow_objects"`
	FetchedAt   time.Time    `json:"fetched_at"`
	Cached      bool         `json:"cached"`
	Degraded    bool         `json:"degraded"`
	Error       string       `json:"error,omitempty"`
}

// Connector pulls metrics and cloud-flow object manifests for one tenant.
type Connector struct {
	cfg Config

	mu    sync.Mutex
	cache Snapshot
}

// NewConnector validates cfg and returns a tenant-bound cloud connector.
func NewConnector(cfg Config) (*Connector, error) {
	if cfg.TenantID == "" {
		return nil, ErrTenantRequired
	}
	if !validProvider(cfg.Provider) {
		return nil, fmt.Errorf("%w %q", ErrUnknownProvider, cfg.Provider)
	}
	if err := validateEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}
	if err := validateReadOnlyCredential(cfg.Provider, cfg.Credential); err != nil {
		return nil, err
	}
	if cfg.Client == nil {
		cfg.Client = crypto.HardenedHTTPClient(10 * time.Second)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Connector{cfg: cfg}, nil
}

// RequiredReadScopes returns the exact read-only scopes a provider connector
// accepts. Keeping this list small makes accidental write-capable credentials
// obvious during review and tests.
func RequiredReadScopes(provider Provider) []string {
	scopes := requiredScopes(provider)
	sort.Strings(scopes)
	return scopes
}

// Pull fetches one snapshot. If the source is down and a previous good snapshot
// exists, Pull returns that snapshot with Degraded=true and Cached=true.
func (c *Connector) Pull(ctx context.Context) (Snapshot, error) {
	snap, err := c.fetch(ctx)
	if err != nil {
		return c.degradedSnapshot(err), nil
	}
	c.mu.Lock()
	c.cache = snap.clone()
	c.mu.Unlock()
	return snap, nil
}

func (c *Connector) fetch(ctx context.Context) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.snapshotURL(), nil)
	if err != nil {
		return Snapshot{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.Credential.Token)
	req.Header.Set("User-Agent", "probectl-cloudconnect/1.0")

	resp, err := c.cfg.Client.Do(req)
	if err != nil {
		return Snapshot{}, fmt.Errorf("cloudconnect: pull %s metrics: %w", c.cfg.Provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Snapshot{}, fmt.Errorf("cloudconnect: pull %s metrics: status %d", c.cfg.Provider, resp.StatusCode)
	}
	var payload snapshotPayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSnapshotBytes)).Decode(&payload); err != nil {
		return Snapshot{}, fmt.Errorf("cloudconnect: decode %s snapshot: %w", c.cfg.Provider, err)
	}
	return c.normalize(payload)
}

func (c *Connector) snapshotURL() string {
	u, _ := url.Parse(c.cfg.Endpoint)
	q := u.Query()
	if c.cfg.AccountID != "" {
		q.Set("account_id", c.cfg.AccountID)
	}
	if c.cfg.Region != "" {
		q.Set("region", c.cfg.Region)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Connector) normalize(payload snapshotPayload) (Snapshot, error) {
	now := c.cfg.Now().UTC()
	host := endpointHost(c.cfg.Endpoint)
	snap := Snapshot{
		TenantID:  c.cfg.TenantID,
		Provider:  c.cfg.Provider,
		AccountID: c.cfg.AccountID,
		Region:    c.cfg.Region,
		FetchedAt: now,
	}
	for _, raw := range payload.Metrics {
		ts := raw.Timestamp
		if ts.IsZero() {
			ts = now
		}
		m := Metric{
			TenantID:   c.cfg.TenantID,
			Provider:   c.cfg.Provider,
			AccountID:  c.cfg.AccountID,
			Region:     firstNonEmpty(raw.Region, c.cfg.Region),
			ResourceID: raw.ResourceID,
			Name:       normalizeMetricName(c.cfg.Provider, raw.Name),
			Unit:       raw.Unit,
			Value:      raw.Value,
			Timestamp:  ts.UTC(),
			Labels:     copyStringMap(raw.Labels),
			Provenance: map[string]string{
				"cloud.provider":      string(c.cfg.Provider),
				"cloud.account_id":    c.cfg.AccountID,
				"cloud.endpoint_host": host,
				"cloud.principal":     c.cfg.Credential.Principal,
			},
		}
		snap.Metrics = append(snap.Metrics, m)
	}
	for _, raw := range payload.FlowObjects {
		format := raw.Format
		if format == "" {
			format = flowFormat(c.cfg.Provider)
		}
		if format != flowFormat(c.cfg.Provider) {
			return Snapshot{}, fmt.Errorf("cloudconnect: unsupported %s flow format %q", c.cfg.Provider, format)
		}
		updated := raw.UpdatedAt
		if updated.IsZero() {
			updated = now
		}
		obj := FlowObject{
			TenantID:  c.cfg.TenantID,
			Provider:  c.cfg.Provider,
			AccountID: c.cfg.AccountID,
			Region:    firstNonEmpty(raw.Region, c.cfg.Region),
			URI:       raw.URI,
			Format:    format,
			UpdatedAt: updated.UTC(),
			SizeBytes: raw.SizeBytes,
			Provenance: map[string]string{
				"cloud.provider":      string(c.cfg.Provider),
				"cloud.account_id":    c.cfg.AccountID,
				"cloud.endpoint_host": host,
				"cloud.principal":     c.cfg.Credential.Principal,
			},
		}
		snap.FlowObjects = append(snap.FlowObjects, obj)
	}
	return snap, nil
}

func (c *Connector) degradedSnapshot(err error) Snapshot {
	c.mu.Lock()
	cached := c.cache.clone()
	c.mu.Unlock()
	if cached.TenantID != "" {
		cached.Cached = true
		cached.Degraded = true
		cached.Error = sanitizeError(err)
		return cached
	}
	return Snapshot{
		TenantID:  c.cfg.TenantID,
		Provider:  c.cfg.Provider,
		AccountID: c.cfg.AccountID,
		Region:    c.cfg.Region,
		FetchedAt: c.cfg.Now().UTC(),
		Degraded:  true,
		Error:     sanitizeError(err),
	}
}

type snapshotPayload struct {
	TenantID    string              `json:"tenant_id"`
	Metrics     []metricPayload     `json:"metrics"`
	FlowObjects []flowObjectPayload `json:"flow_objects"`
}

type metricPayload struct {
	TenantID   string            `json:"tenant_id"`
	Region     string            `json:"region"`
	ResourceID string            `json:"resource_id"`
	Name       string            `json:"name"`
	Unit       string            `json:"unit"`
	Value      float64           `json:"value"`
	Timestamp  time.Time         `json:"timestamp"`
	Labels     map[string]string `json:"labels"`
}

type flowObjectPayload struct {
	TenantID  string    `json:"tenant_id"`
	Region    string    `json:"region"`
	URI       string    `json:"uri"`
	Format    string    `json:"format"`
	UpdatedAt time.Time `json:"updated_at"`
	SizeBytes int64     `json:"size_bytes"`
}

func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: invalid endpoint", ErrHTTPSEndpoint)
	}
	if u.Scheme != "https" {
		return ErrHTTPSEndpoint
	}
	return nil
}

func validateReadOnlyCredential(provider Provider, cred Credential) error {
	if cred.Token == "" {
		return fmt.Errorf("%w: missing token", ErrReadOnlyCredentials)
	}
	required := requiredScopes(provider)
	allowed := map[string]struct{}{}
	for _, s := range required {
		allowed[s] = struct{}{}
	}
	have := map[string]struct{}{}
	for _, scope := range cred.Scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := allowed[scope]; !ok {
			return fmt.Errorf("%w: %s is not an approved read scope for %s", ErrReadOnlyCredentials, scope, provider)
		}
		have[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := have[scope]; !ok {
			return fmt.Errorf("%w: missing %s", ErrReadOnlyCredentials, scope)
		}
	}
	return nil
}

func requiredScopes(provider Provider) []string {
	switch provider {
	case ProviderAWS:
		return []string{"cloudwatch:GetMetricData", "ec2:DescribeFlowLogs", "s3:GetObject"}
	case ProviderAzure:
		return []string{"Microsoft.Insights/metrics/read", "Microsoft.Network/networkWatchers/flowLogs/read", "Storage Blob Data Reader"}
	case ProviderGCP:
		return []string{"logging.logEntries.list", "monitoring.timeSeries.list", "storage.objects.get"}
	default:
		return nil
	}
}

func validProvider(provider Provider) bool {
	switch provider {
	case ProviderAWS, ProviderAzure, ProviderGCP:
		return true
	default:
		return false
	}
}

func flowFormat(provider Provider) string {
	switch provider {
	case ProviderAWS:
		return flow.ProtoAWSVPCFlowLogs
	case ProviderAzure:
		return flow.ProtoAzureNSGFlowLogs
	case ProviderGCP:
		return flow.ProtoGCPVPCFlowLogs
	default:
		return ""
	}
}

func normalizeMetricName(provider Provider, name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "cloud.") {
		return name
	}
	if name == "" {
		return "cloud." + string(provider) + ".metric"
	}
	return "cloud." + string(provider) + "." + snake(name)
}

func snake(s string) string {
	var b strings.Builder
	var prevLower bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			if prevLower {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
			prevLower = false
		case r == '-' || r == ' ' || r == '/':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
			prevLower = false
		default:
			b.WriteRune(r)
			prevLower = r >= 'a' && r <= 'z'
		}
	}
	return strings.Trim(b.String(), "_")
}

func endpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Host
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s Snapshot) clone() Snapshot {
	out := s
	out.Metrics = append([]Metric(nil), s.Metrics...)
	for i := range out.Metrics {
		out.Metrics[i].Labels = copyStringMap(out.Metrics[i].Labels)
		out.Metrics[i].Provenance = copyStringMap(out.Metrics[i].Provenance)
	}
	out.FlowObjects = append([]FlowObject(nil), s.FlowObjects...)
	for i := range out.FlowObjects {
		out.FlowObjects[i].Provenance = copyStringMap(out.FlowObjects[i].Provenance)
	}
	return out
}
