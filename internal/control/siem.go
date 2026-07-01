// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/siem"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
	sender := siem.NewHTTPSender(preset, cfg.SIEMEndpoint, cfg.SIEMToken, formatter.ContentType(), nil)
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
func auditToSIEM(tenantID string, ev audit.Event, redact map[string]struct{}) siem.Event {
	pol := govern.DefaultPIIPolicy()
	attrs := map[string]string{
		"audit.seq":  redactSIEMAttribute(pol, "audit.seq", strconv.FormatInt(ev.Seq, 10)),
		"audit.hash": redactSIEMAttribute(pol, "audit.hash", ev.Hash),
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
		attrs[k] = redactSIEMAttribute(pol, k, sv)
	}
	return siem.Event{
		Time:       ev.CreatedAt,
		TenantID:   tenantID,
		Category:   siem.CategoryAudit,
		Action:     redactSIEMText(pol, ev.Action),
		Severity:   auditSeverity(outcome),
		Actor:      redactSIEMText(pol, ev.Actor),
		Target:     redactSIEMText(pol, ev.Target),
		Outcome:    redactSIEMText(pol, outcome),
		Attributes: attrs,
	}
}

func redactSIEMAttribute(pol govern.Policy, key, value string) string {
	return govern.RedactTelemetryAttribute(pol, key, value)
}

func redactSIEMText(pol govern.Policy, value string) string {
	return govern.RedactTelemetryText(pol, value)
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

// siemAuditSink adapts the forwarder to the audit.Sink contract: it maps each
// audit event (redacting secrets) and delivers it with a bounded per-event
// timeout so a SIEM outage pauses the drain (and thus the persisted cursor)
// instead of holding the database transaction open indefinitely. Because the
// cursor advances only past delivered events, a paused drain resumes without
// dropping — durable no-drop delivery (S32 done-when).
type siemAuditSink struct {
	fw      *siem.Forwarder
	redact  map[string]struct{}
	timeout time.Duration
}

func (s siemAuditSink) Export(ctx context.Context, streamKey string, ev audit.Event) error {
	dctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.fw.Deliver(dctx, auditToSIEM(streamKey, ev, s.redact))
}

// SIEMAuditPoller forwards every tenant's audit stream to the SIEM on an interval,
// resuming from a per-tenant persisted cursor (store.SIEMDelivery) so a restart
// neither drops events nor re-floods. It drains sequentially via audit.Drain,
// which stops at the first delivery error; the committed cursor still advances
// past whatever was delivered, so the next tick resumes exactly where it paused.
type SIEMAuditPoller struct {
	pool     *pgxpool.Pool
	tenants  *store.Tenants
	sink     siemAuditSink
	interval time.Duration
	pageSize int
	log      *slog.Logger
}

// NewSIEMAuditPoller builds the poller over the forwarder. redact extends the
// built-in PII/secret denylist.
func NewSIEMAuditPoller(pool *pgxpool.Pool, fw *siem.Forwarder, redact []string, interval time.Duration, log *slog.Logger) *SIEMAuditPoller {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &SIEMAuditPoller{
		pool:     pool,
		tenants:  store.NewTenants(pool),
		sink:     siemAuditSink{fw: fw, redact: redactionSet(redact), timeout: 10 * time.Second},
		interval: interval,
		pageSize: audit.DefaultExportPageSize,
		log:      log,
	}
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
	for _, t := range tenants {
		if err := p.drainTenant(ctx, t.ID); err != nil {
			// A single tenant's failure must not stop the others.
			p.log.Warn("siem drain tenant failed", "tenant", t.ID, "error", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// drainTenant forwards a tenant's pending audit events one page (one transaction)
// at a time until it catches up or a page pauses (SIEM error). One short tx per
// page keeps the database transaction off the network-delivery path.
func (p *SIEMAuditPoller) drainTenant(ctx context.Context, tenantID string) error {
	for {
		more, err := p.drainPage(ctx, tenantID)
		if err != nil || !more || ctx.Err() != nil {
			return err
		}
	}
}

// drainPage drains a single page inside one tenant-scoped transaction, persisting
// the advanced cursor on commit. It returns more=true when a full page committed
// (another page may remain). On a delivery error it commits the partial progress
// and returns more=false so the next tick resumes.
func (p *SIEMAuditPoller) drainPage(ctx context.Context, tenantID string) (more bool, err error) {
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			cursor, e := (store.SIEMDelivery{}).Cursor(c, sc)
			if e != nil {
				return e
			}
			next, derr := audit.Drain(c, sc, p.sink, cursor, p.pageSize)
			if next > cursor {
				if e := (store.SIEMDelivery{}).Advance(c, sc, next); e != nil {
					return e
				}
				more = derr == nil // delivered a full/partial page cleanly → maybe more
			}
			if derr != nil {
				p.log.Warn("siem drain paused; resumes next tick", "tenant", tenantID, "error", derr)
				more = false
			}
			return nil
		})
	return more, err
}
