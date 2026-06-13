// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// tsdbQuerier is the read side of the in-memory TSDB the evaluator needs.
type tsdbQuerier interface {
	Query(metric string, match map[string]string) []tsdb.Series
}

// metricSource adapts the TSDB to alert.MetricSource for one tenant: every query
// is constrained to the tenant's series (tenant_id label), so the evaluator can
// never read another tenant's metrics (F50). It returns the latest value per
// distinct label set.
type metricSource struct {
	q      tsdbQuerier
	tenant string
}

func (m metricSource) Current(_ context.Context, metric string, match map[string]string) ([]alert.Sample, error) {
	scoped := map[string]string{"tenant_id": m.tenant}
	for k, v := range match {
		scoped[k] = v
	}
	rows := m.q.Query(metric, scoped)

	latest := make(map[string]alert.Sample, len(rows))
	order := make([]string, 0, len(rows))
	for _, s := range rows {
		fp := labelFingerprint(s.Labels)
		if _, seen := latest[fp]; !seen {
			order = append(order, fp)
		}
		latest[fp] = alert.Sample{Labels: s.Labels, Value: s.Value}
	}
	out := make([]alert.Sample, 0, len(order))
	for _, fp := range order {
		out = append(out, latest[fp])
	}
	return out, nil
}

// promInstantQuerier is the read side of a remote-write TSDB (Prometheus /
// VictoriaMetrics) the evaluator needs when there is no in-process store.
type promInstantQuerier interface {
	InstantVector(ctx context.Context, promql string) ([]tsdb.LabeledSample, error)
}

// promMetricSource adapts a Prometheus/VictoriaMetrics instant query to
// alert.MetricSource for one tenant (ARCH-002/CORRECT-006). It pins every query
// to the tenant's tenant_id label so the evaluator can never read another
// tenant's series, exactly like the in-memory metricSource.
type promMetricSource struct {
	q      promInstantQuerier
	tenant string
}

func (m promMetricSource) Current(ctx context.Context, metric string, match map[string]string) ([]alert.Sample, error) {
	var b strings.Builder
	b.WriteString(metric)
	b.WriteByte('{')
	b.WriteString(`tenant_id=`)
	b.WriteString(promQuote(m.tenant))
	for k, v := range match {
		b.WriteByte(',')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(promQuote(v))
	}
	b.WriteByte('}')
	rows, err := m.q.InstantVector(ctx, b.String())
	if err != nil {
		return nil, err
	}
	out := make([]alert.Sample, 0, len(rows))
	for _, r := range rows {
		out = append(out, alert.Sample{Labels: r.Labels, Value: r.Value})
	}
	return out, nil
}

// promQuote renders a PromQL label-matcher value (double-quoted, escaped).
func promQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func labelFingerprint(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(';')
	}
	return b.String()
}

// tenantRuleProvider loads a tenant's enabled rules through the RLS choke point.
type tenantRuleProvider struct {
	pool   *pgxpool.Pool
	tenant tenancy.ID
}

func (p tenantRuleProvider) Rules(ctx context.Context) ([]alert.Rule, error) {
	var rules []alert.Rule
	err := tenancy.InTenant(tenancy.WithTenant(ctx, p.tenant), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			rs, e := store.AlertRules{}.ListEnabled(c, sc)
			rules = rs
			return e
		})
	return rules, err
}

// BuildAlertEvaluator wires the alerting evaluator over the shared TSDB and the
// rule store for one tenant. It returns (nil, false) when the TSDB cannot be
// queried in-process (e.g. Prometheus remote-write mode) — alerting then needs a
// query backend (a follow-up), and the caller skips the loop rather than failing.
//
// Single-tenant wiring: a multi-tenant deployment runs one evaluator per tenant
// (a fan-out refinement); here the default tenant is evaluated.
// A non-nil sink forwards every fired/resolved alert (e.g. into the incident
// correlator, S17).
func BuildAlertEvaluator(pool *pgxpool.Pool, writer any, deps alert.ChannelDeps,
	interval time.Duration, tenant tenancy.ID, sink func(context.Context, alert.Alert),
	log *slog.Logger) (*alert.Evaluator, bool) {
	if pool == nil {
		return nil, false
	}
	// ARCH-002/CORRECT-006: pick a metric source for the deployment profile.
	// In-process TSDB (lightweight mode) → query it directly. Remote-write mode
	// (the production Kafka+CH+Prom profile) → query the upstream over its
	// instant API, so rules ACTUALLY evaluate instead of silently never firing.
	var source alert.MetricSource
	switch w := writer.(type) {
	case tsdbQuerier:
		source = metricSource{q: w, tenant: tenant.String()}
	case promInstantQuerier:
		source = promMetricSource{q: w, tenant: tenant.String()}
		log.Info("alerting: evaluating against the remote-write upstream (instant queries)", "tenant", tenant.String())
	default:
		return nil, false
	}
	var opts []alert.EngineOption
	if sink != nil {
		opts = append(opts, alert.WithAlertSink(sink))
	}
	engine := alert.NewEngine(source, alert.NewNotifier(deps, log), log, opts...)
	// ARCH-005 (scoped per the volatile-stores ADR): silences/acks are the
	// ADR's documented exception — reload them so a restart does not drop
	// operator state, and delete the row when the episode resolves.
	restoreCtx, cancelRestore := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelRestore()
	err := tenancy.InTenant(tenancy.WithTenant(restoreCtx, tenant), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			ops, lerr := (store.AlertOps{}).List(ctx, sc)
			if lerr != nil {
				return lerr
			}
			if len(ops) == 0 {
				return nil
			}
			restored := make(map[string]alert.RestoredOp, len(ops))
			for _, op := range ops {
				r := alert.RestoredOp{AckedBy: op.AckedBy}
				if op.SilencedUntil != nil {
					r.SilencedUntil = *op.SilencedUntil
				}
				if op.AckedAt != nil {
					r.AckedAt = *op.AckedAt
				}
				restored[op.Fingerprint] = r
			}
			engine.RestoreOps(restored)
			log.Info("alert silences/acks restored", "tenant", tenant.String(), "ops", len(ops))
			return nil
		})
	if err != nil {
		// Degrade loudly, never block alerting on the ops table.
		log.Warn("alert ops reload failed (silences/acks from before the restart are lost)",
			"tenant", tenant.String(), "error", err.Error())
	}
	engine.SetResolveHook(func(fingerprint string) {
		hctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tenancy.InTenant(tenancy.WithTenant(hctx, tenant), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				return (store.AlertOps{}).Delete(ctx, sc, fingerprint)
			}); err != nil {
			// CODE-002: a failed resolve-cleanup leaves a stale ops row; log it
			// (the alert still resolves) rather than discard silently.
			log.Warn("alert resolve-hook cleanup failed", "tenant", tenant.String(), "fingerprint", fingerprint, "error", err.Error())
		}
	})
	provider := tenantRuleProvider{pool: pool, tenant: tenant}
	return alert.NewEvaluator(engine, provider, interval, log), true
}
