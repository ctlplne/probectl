package control

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/config"
	resultv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/result/v1"
	"github.com/imfeelingtheagi/netctl/internal/incident"
	"github.com/imfeelingtheagi/netctl/internal/opendata"
	"github.com/imfeelingtheagi/netctl/internal/siem"
)

// BuildThreatIntel builds the S28 IOC store + refresher from config. It returns
// (nil, nil, false) unless threat-intel is explicitly enabled — enabling it makes
// outbound fetches to public feeds (sovereignty / no-phone-home: OFF by default).
// The store is shared (ingested once); matches land on tenant-scoped records.
func BuildThreatIntel(cfg *config.Config, log *slog.Logger) (*opendata.IOCStore, *opendata.IntelRefresher, bool) {
	if cfg == nil || !cfg.ThreatIntelEnabled {
		return nil, nil, false
	}
	names := cfg.ThreatIntelFeeds
	if len(names) == 0 {
		names = opendata.IntelFeedNames() // empty → all built-in feeds
	}
	feeds := opendata.NewIntelFeeds(names, nil) // nil → hardened-TLS default client
	if len(feeds) == 0 {
		log.Warn("threat-intel enabled but no known feeds configured", "feeds", names)
		return nil, nil, false
	}
	store := opendata.NewIOCStore()
	refresher := opendata.NewIntelRefresher(store, feeds, cfg.ThreatIntelRefresh, log)
	return store, refresher, true
}

// IOCConsumer subscribes to network results and scores each result's peer address
// (IP or hostname) against the shared IOC store (S28), correlating any match into
// a tenant-scoped threat-plane incident. A match is a confidence-scored SIGNAL
// with source attribution — netctl never blocks traffic (guardrail 9).
type IOCConsumer struct {
	bus        bus.Bus
	correlator *incident.Correlator
	store      *opendata.IOCStore
	siem       *siem.Forwarder
	log        *slog.Logger
}

// NewIOCConsumer builds the consumer. store must be non-nil (gate on
// BuildThreatIntel's ok return before constructing).
func NewIOCConsumer(b bus.Bus, c *incident.Correlator, store *opendata.IOCStore, log *slog.Logger) *IOCConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &IOCConsumer{bus: b, correlator: c, store: store, log: log}
}

// WithSIEM forwards each IOC-match signal to the SIEM (S32) in addition to
// correlating it into an incident. nil disables it (the default).
func (cs *IOCConsumer) WithSIEM(fw *siem.Forwarder) *IOCConsumer {
	cs.siem = fw
	return cs
}

// Run subscribes to the network-results topic until ctx is canceled.
func (cs *IOCConsumer) Run(ctx context.Context) error {
	return cs.bus.Subscribe(ctx, bus.NetworkResultsTopic, "threat-intel-ip",
		func(ctx context.Context, msg bus.Message) error {
			var r resultv1.Result
			if err := proto.Unmarshal(msg.Value, &r); err != nil {
				cs.log.Warn("skipping malformed result", "error", err)
				return nil
			}
			for _, sig := range cs.signals(&r) {
				if _, err := cs.correlator.Ingest(ctx, sig); err != nil {
					cs.log.Warn("correlate ioc match into incident failed", "error", err)
				}
				if cs.siem != nil {
					if err := cs.siem.Enqueue(ctx, signalToSIEM(sig)); err != nil {
						cs.log.Warn("forward ioc match to siem failed", "error", err)
					}
				}
			}
			return nil
		})
}

// signals scores a result's peer address against the store and maps each match to
// a threat-plane signal. Returns nothing when there is no address or no match.
func (cs *IOCConsumer) signals(r *resultv1.Result) []incident.Signal {
	host := peerHost(r.GetServerAddress())
	if host == "" {
		return nil
	}
	var matches []opendata.IOCMatch
	if addr, err := netip.ParseAddr(host); err == nil {
		matches = cs.store.ScoreIP(addr.String())
	} else {
		matches = cs.store.ScoreDomain(host)
	}
	if len(matches) == 0 {
		return nil
	}
	occurred := time.Unix(0, r.GetStartTimeUnixNano())
	out := make([]incident.Signal, 0, len(matches))
	for _, m := range matches {
		out = append(out, iocSignal(r, host, m, occurred))
	}
	return out
}

func iocSignal(r *resultv1.Result, host string, m opendata.IOCMatch, occurred time.Time) incident.Signal {
	attrs := map[string]string{
		"intel.source":     m.Source,
		"intel.category":   m.Category,
		"intel.type":       string(m.Type),
		"intel.indicator":  m.Indicator,
		"intel.confidence": strconv.Itoa(m.Confidence),
	}
	if m.License != "" {
		attrs["intel.license"] = m.License
	}
	if ct := r.GetCanaryType(); ct != "" {
		attrs["observed.canary_type"] = ct
	}
	cat := m.Category
	if cat == "" {
		cat = "blocklist"
	}
	return incident.Signal{
		TenantID:   r.GetTenantId(),
		Plane:      "threat",
		Kind:       "ioc." + cat,
		Severity:   severityForConfidence(m.Confidence),
		Title:      fmt.Sprintf("%s matches threat-intel indicator (%s, source %s)", host, cat, m.Source),
		Summary:    fmt.Sprintf("%s matched threat-intel indicator %s from %s (confidence %d)", host, m.Indicator, m.Source, m.Confidence),
		Target:     host,
		Attributes: attrs,
		OccurredAt: occurred,
	}
}

// severityForConfidence maps a feed's confidence to an incident severity. A match
// is always tunable/suppressible downstream (signal, not block).
func severityForConfidence(confidence int) incident.Severity {
	switch {
	case confidence >= 80:
		return incident.Severity("critical")
	case confidence >= 60:
		return incident.Severity("warning")
	default:
		return incident.Severity("info")
	}
}

// peerHost extracts the host portion of a result's server address (stripping a
// :port when present), so an IP or hostname can be scored.
func peerHost(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
