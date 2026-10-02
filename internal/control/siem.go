// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/metrics"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// defaultRedactKeys are audit `data` keys never forwarded to the SIEM — secrets
// and obvious PII. Operators extend this via PROBECTL_SIEM_REDACT_KEYS (governance).
// Matching is case-insensitive on the key name; values become "[redacted]".
var defaultRedactKeys = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"authorization", "cookie", "private_key", "client_secret", "ssn",
}

// BuildSIEM constructs the SIEM forwarder from config. It returns (nil, false)
// unless SIEM export is explicitly enabled — OFF by default, since enabling it
// opens an outbound connection to the operator's SIEM (sovereignty / no-phone-home).
// The forwarder renders audit + threat events into the configured format and
// delivers them over hardened TLS with retry + backpressure (no drops, S32/F26).
func BuildSIEM(cfg *config.Config, log *slog.Logger) (*siem.Forwarder, bool) {
	if log == nil {
		log = slog.Default()
	}
	if cfg == nil || !cfg.SIEMEnabled {
		return nil, false
	}
	if cfg.SIEMEndpoint == "" {
		log.Warn("siem enabled but PROBECTL_SIEM_ENDPOINT is empty; export disabled")
		return nil, false
	}
	if _, ok, _ := siemEndpointPosture(cfg.SIEMEndpoint); !ok {
		log.Warn("siem enabled but PROBECTL_SIEM_ENDPOINT is not a valid HTTPS URL; export disabled")
		return nil, false
	}
	preset, ok := siem.ParsePreset(cfg.SIEMPreset)
	if !ok {
		preset = siem.PresetGeneric
	}
	format := cfg.SIEMFormat
	if format == "" {
		format = preset.DefaultFormat()
	}
	formatter, ok := siem.NewFormatter(format)
	if !ok {
		log.Warn("siem: unknown format; export disabled", "format", format)
		return nil, false
	}
	sender := siem.NewHTTPSender(preset, cfg.SIEMEndpoint, cfg.SIEMToken, cfg.SIEMAuthScheme, formatter.ContentType(), nil)
	fw := siem.NewForwarder(formatter, sender, siem.Config{BufferSize: cfg.SIEMBufferSize}, log)
	return fw, true
}

// redactionSet merges the built-in denylist with operator-configured keys.
func redactionSet(extra []string) map[string]struct{} {
	set := make(map[string]struct{}, len(defaultRedactKeys)+len(extra))
	for _, k := range defaultRedactKeys {
		set[k] = struct{}{}
	}
	for _, k := range extra {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			set[k] = struct{}{}
		}
	}
	return set
}

// auditToSIEM maps one audit event to a SIEM event, scrubbing redacted keys. The
// tenant comes from the audit stream key (the drained scope's tenant), never the
// event body.
// auditToSIEM renders one audit event for the SIEM. AUD-06: the SIEM is the
// OPERATOR'S own SOC, so by default (identityClear) the real actor/target
// identity is forwarded — only secret keys (redact) are scrubbed — so the SOC
// can attribute actions. In pseudonymize mode the PII-masking policy is applied
// so identities are partially masked in the SIEM copy (a deliberate, lossy
// choice that then gates retention pruning; see the retention runner).
func auditToSIEM(tenantID string, ev audit.Event, redact map[string]struct{}, identityClear bool) siem.Event {
	// clear (default): scrub secrets/PAN/SSN but keep identities, so the SOC can
	// attribute. pseudonymize: apply the full PII-masking policy too. Secrets are
	// NEVER exported in clear in either mode.
	mask := govern.RedactSecretsOnlyText
	maskAttr := func(_, v string) string { return govern.RedactSecretsOnlyText(v) }
	if !identityClear {
		pol := govern.DefaultPIIPolicy()
		mask = func(v string) string { return govern.RedactTelemetryText(pol, v) }
		maskAttr = func(k, v string) string { return govern.RedactTelemetryAttribute(pol, k, v) }
	}
	attrs := map[string]string{
		"audit.seq":  maskAttr("audit.seq", strconv.FormatInt(ev.Seq, 10)),
		"audit.hash": maskAttr("audit.hash", ev.Hash),
	}
	var outcome string
	for k, v := range ev.Data {
		if _, bad := redact[strings.ToLower(k)]; bad {
			attrs[k] = "[redacted]"
			continue
		}
		sv := stringifyAny(v)
		if strings.ToLower(k) == "outcome" {
			outcome = sv
		}
		attrs[k] = maskAttr(k, sv)
	}
	return siem.Event{
		Time:       ev.CreatedAt,
		TenantID:   tenantID,
		Category:   siem.CategoryAudit,
		Action:     mask(ev.Action),
		Severity:   auditSeverity(outcome),
		Actor:      mask(ev.Actor),
		Target:     mask(ev.Target),
		Outcome:    mask(outcome),
		Attributes: attrs,
	}
}

// auditSeverity bumps a failed/denied action to warning; audit is otherwise info.
func auditSeverity(outcome string) siem.Severity {
	switch strings.ToLower(outcome) {
	case "failure", "failed", "denied", "error":
		return siem.SeverityWarning
	default:
		return siem.SeverityInfo
	}
}

// signalToSIEM maps a threat-plane incident signal to a SIEM event. The threat
// consumers enqueue it (async, backpressured) alongside correlating it into an
// incident — the SOC gets the raw confidence-scored signal (never a block; §7).
func signalToSIEM(sig incident.Signal) siem.Event {
	attrs := make(map[string]string, len(sig.Attributes)+3)
	for k, v := range sig.Attributes {
		attrs[k] = v
	}
	if sig.Plane != "" {
		attrs["plane"] = sig.Plane
	}
	if sig.Prefix != "" {
		attrs["prefix"] = sig.Prefix
	}
	if sig.Summary != "" {
		attrs["summary"] = sig.Summary
	}
	return siem.Event{
		Time:       sig.OccurredAt,
		TenantID:   sig.TenantID,
		Category:   siemCategoryForPlane(sig.Plane),
		Action:     sig.Kind,
		Severity:   siemSeverity(sig.Severity),
		Target:     sig.Target,
		Message:    sig.Title,
		Attributes: attrs,
	}
}

func siemCategoryForPlane(plane string) siem.Category {
	if plane == "change" {
		return siem.CategoryChange
	}
	return siem.CategoryThreat
}

func siemSeverity(s incident.Severity) siem.Severity {
	switch s {
	case incident.SeverityCritical:
		return siem.SeverityCritical
	case incident.SeverityWarning:
		return siem.SeverityWarning
	default:
		return siem.SeverityInfo
	}
}

// stringifyAny renders an audit data value as a stable string for a SIEM label.
func stringifyAny(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// bufferSink maps a page of audit events into siem.Events IN MEMORY (scrubbing
// secrets), with no network I/O, so it implements the audit.Sink contract while
// the drain reads a page inside a short transaction. The poller then releases
// that transaction and POSTs the collected batch — a slow SIEM therefore never
// holds a database connection open (AUD-16). The tenant comes from the drained
// stream key, never the event body (docs/guardrails.md G7-N).
type bufferSink struct {
	redact        map[string]struct{}
	identityClear bool
	events        []siem.Event
}

func (b *bufferSink) Export(_ context.Context, streamKey string, ev audit.Event) error {
	b.events = append(b.events, auditToSIEM(streamKey, ev, b.redact, b.identityClear))
	return nil
}

// Drain-loop tunables (AUD-16).
const (
	// siemDrainWorkers bounds the per-tick concurrency: tenants drain in
	// parallel so one slow or large tenant cannot starve the others, but the
	// pool is bounded so export never fans out unboundedly.
	siemDrainWorkers = 8
	// siemClaimLease is how long an export claim is honored before another
	// replica may steal it — long enough to cover a batch POST + retries under
	// the singleton poller, short enough that a crashed poller does not stall a
	// tenant for long. (Normal operation has a single poller via the lease
	// singleton; the claim is the storage-layer backstop for failover overlap.)
	siemClaimLease = 2 * time.Minute
	// siemPostTimeout bounds one batch POST (including retries) so a wedged SIEM
	// pauses the drain instead of blocking a worker forever; the next tick
	// resumes from the unchanged cursor.
	siemPostTimeout = 30 * time.Second
)

// SIEMAuditPoller forwards every tenant's audit stream to the SIEM on an
// interval, resuming from a per-tenant persisted cursor (store.SIEMDelivery) so
// a restart neither drops events nor re-floods. Each tick it drains tenants
// CONCURRENTLY through a bounded worker pool; per tenant it reads a page inside
// a short transaction, POSTs the whole page in ONE request with no transaction
// open, then advances the cursor with a compare-and-set — so throughput no
// longer collapses under SIEM latency and a slow tenant cannot starve the rest
// (AUD-16). Delivery is at-least-once: the cursor only advances past a page
// whose POST succeeded, and a page re-sent after a mid-flight failure is a
// duplicate the SIEM dedups on audit.seq, never a drop (S32 done-when).
type SIEMAuditPoller struct {
	pool          *pgxpool.Pool
	tenants       *store.Tenants
	fw            *siem.Forwarder
	redact        map[string]struct{}
	identityClear bool
	interval      time.Duration
	pageSize      int
	workers       int
	owner         string
	lease         time.Duration
	postTimeout   time.Duration
	log           *slog.Logger

	mu      sync.Mutex
	backlog map[string]int64 // per-tenant pending events (headSeq-cursor), sampled each tick
}

// NewSIEMAuditPoller builds the poller over the forwarder. redact extends the
// built-in PII/secret denylist.
func NewSIEMAuditPoller(pool *pgxpool.Pool, fw *siem.Forwarder, redact []string, identityClear bool, interval time.Duration, log *slog.Logger) *SIEMAuditPoller {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	// A per-instance owner id so the export claim distinguishes this poller from
	// an overlapping replica during failover (not security-sensitive; crypto.UUIDv4
	// keeps randomness inside internal/crypto per the crypto guardrail).
	owner, err := crypto.UUIDv4()
	if err != nil || owner == "" {
		owner = fmt.Sprintf("siem-poller-%d", time.Now().UnixNano())
	}
	return &SIEMAuditPoller{
		pool:          pool,
		tenants:       store.NewTenants(pool),
		fw:            fw,
		redact:        redactionSet(redact),
		identityClear: identityClear,
		interval:      interval,
		pageSize:      audit.DefaultExportPageSize,
		workers:       siemDrainWorkers,
		owner:         owner,
		lease:         siemClaimLease,
		postTimeout:   siemPostTimeout,
		log:           log,
		backlog:       map[string]int64{},
	}
}

// RegisterMetrics publishes the SIEM export backlog on /metrics. Per OPS-005 and
// the /metrics tenant-id guard, the scrape carries NO per-tenant series; these
// AGGREGATES still make per-tenant backlog visible — the worst single tenant
// (max) and how many tenants are behind — so a slow or starved tenant is
// observable (AUD-16).
func (p *SIEMAuditPoller) RegisterMetrics(m *metrics.Registry) {
	if m == nil {
		return
	}
	m.Gauge("probectl_siem_export_backlog_events",
		"Audit events pending SIEM delivery, summed across all tenants (AUD-16).",
		func() float64 { s, _, _ := p.backlogStats(); return float64(s) })
	m.Gauge("probectl_siem_export_backlog_max_events",
		"Largest single-tenant SIEM export backlog, so one slow or large tenant is visible without a per-tenant series (AUD-16, OPS-005).",
		func() float64 { _, mx, _ := p.backlogStats(); return float64(mx) })
	m.Gauge("probectl_siem_export_backlog_tenants",
		"Number of tenants currently behind on SIEM export (AUD-16).",
		func() float64 { _, _, b := p.backlogStats(); return float64(b) })
}

// Run polls until ctx is canceled.
func (p *SIEMAuditPoller) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := p.tick(ctx); err != nil {
				p.log.Warn("siem audit poll failed", "error", err)
			}
		}
	}
}

func (p *SIEMAuditPoller) tick(ctx context.Context) error {
	tenants, err := p.tenants.List(ctx)
	if err != nil {
		return err
	}
	live := make(map[string]struct{}, len(tenants))
	for _, t := range tenants {
		live[t.ID] = struct{}{}
	}
	p.pruneBacklog(live)

	workers := p.workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(tenants) {
		workers = len(tenants)
	}
	if workers == 0 {
		return ctx.Err()
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				if ctx.Err() != nil {
					continue // drain the queue without new work once canceled
				}
				if err := p.drainTenant(ctx, id); err != nil {
					// One tenant's failure must not stop the others.
					p.log.Warn("siem drain tenant failed", "tenant", id, "error", err)
				}
			}
		}()
	}
queue:
	for _, t := range tenants {
		select {
		case <-ctx.Done():
			break queue
		case jobs <- t.ID:
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

// drainTenant forwards a tenant's pending audit events one page at a time until
// it catches up or a page pauses (claim lost, SIEM error). Each page is a short
// read transaction, then a POST with no transaction open, then a short
// compare-and-set cursor advance.
func (p *SIEMAuditPoller) drainTenant(ctx context.Context, tenantID string) error {
	for {
		more, err := p.drainPage(ctx, tenantID)
		if err != nil || !more || ctx.Err() != nil {
			return err
		}
	}
}

// drainPage reads and forwards a single page. It (1) claims the tenant and reads
// a page into an in-memory buffer inside a SHORT transaction, (2) POSTs the
// whole batch in ONE request with NO transaction open, then (3) advances the
// cursor with a compare-and-set in a second SHORT transaction — only after the
// POST succeeded. It returns more=true when a full page committed (another page
// may remain). The cursor never advances past an event whose POST did not
// succeed (at-least-once).
func (p *SIEMAuditPoller) drainPage(ctx context.Context, tenantID string) (more bool, err error) {
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))

	var (
		from    int64
		toSeq   int64
		headSeq int64
		held    bool
		batch   []siem.Event
	)
	// (1) Short read transaction: claim, read head, map a page. No network here.
	if err = tenancy.InTenant(tctx, p.pool, func(c context.Context, sc tenancy.Scope) error {
		cur, ok, e := (store.SIEMDelivery{}).ClaimPage(c, sc, p.owner, p.lease)
		if e != nil || !ok {
			held = ok
			return e
		}
		held = true
		from = cur
		if h, he := audit.TenantHeadSeq(c, sc); he == nil {
			headSeq = h
		}
		buf := &bufferSink{redact: p.redact, identityClear: p.identityClear}
		next, de := audit.Drain(c, sc, buf, cur, p.pageSize)
		if de != nil {
			return de
		}
		toSeq = next
		batch = buf.events
		return nil
	}); err != nil {
		return false, err
	}
	if !held {
		// Another replica holds the claim; it will forward this page.
		return false, nil
	}
	if len(batch) == 0 {
		// Caught up: nothing to POST. Release the claim; record zero backlog.
		p.recordBacklog(tenantID, headSeq-from)
		return false, p.releaseClaim(tctx)
	}

	// (2) POST the whole batch in ONE request with NO transaction open.
	postCtx, cancel := context.WithTimeout(ctx, p.postTimeout)
	defer cancel()
	if postErr := p.fw.DeliverBatch(postCtx, batch); postErr != nil {
		// Delivery paused (SIEM down/slow, or ctx canceled). Do NOT advance the
		// cursor; release the claim so the next tick resumes from `from`.
		p.log.Warn("siem batch paused; resumes next tick", "tenant", tenantID, "delivered_through", from, "error", postErr)
		p.recordBacklog(tenantID, headSeq-from)
		return false, p.releaseClaim(tctx)
	}

	// (3) Short commit transaction: CAS-advance only after a successful POST.
	committed := false
	if err = tenancy.InTenant(tctx, p.pool, func(c context.Context, sc tenancy.Scope) error {
		ok, e := (store.SIEMDelivery{}).CommitCursor(c, sc, p.owner, from, toSeq)
		committed = ok
		return e
	}); err != nil {
		return false, err
	}
	if !committed {
		// The cursor moved under us (a concurrent replica advanced it). We
		// already delivered this page (a duplicate the SIEM dedups on audit.seq);
		// resume from the new cursor next tick rather than rewind.
		p.log.Warn("siem cursor advanced concurrently; not rewinding", "tenant", tenantID, "from", from, "to", toSeq)
		return false, nil
	}
	p.recordBacklog(tenantID, headSeq-toSeq)
	// A full page may mean more remain; a short page means we caught up.
	return len(batch) == p.pageSize, nil
}

func (p *SIEMAuditPoller) releaseClaim(tctx context.Context) error {
	return tenancy.InTenant(tctx, p.pool, func(c context.Context, sc tenancy.Scope) error {
		return (store.SIEMDelivery{}).ReleaseClaim(c, sc, p.owner)
	})
}

func (p *SIEMAuditPoller) recordBacklog(tenantID string, pending int64) {
	if pending < 0 {
		pending = 0
	}
	p.mu.Lock()
	p.backlog[tenantID] = pending
	p.mu.Unlock()
}

func (p *SIEMAuditPoller) pruneBacklog(live map[string]struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.backlog {
		if _, ok := live[id]; !ok {
			delete(p.backlog, id)
		}
	}
}

// backlogStats is the AGGREGATE view RegisterMetrics publishes: total pending,
// the largest single-tenant backlog, and how many tenants are behind.
func (p *SIEMAuditPoller) backlogStats() (sum, peak, behind int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.backlog {
		sum += v
		if v > peak {
			peak = v
		}
		if v > 0 {
			behind++
		}
	}
	return sum, peak, behind
}
