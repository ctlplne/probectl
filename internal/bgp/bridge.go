// Package bgp bridges the Python BGP analyzer into the control plane (S14).
//
// The analyzer (analyzer/) ingests public collector data and emits
// probectl.bgp.events as JSON Lines. The Bridge reads that stream, validates each
// event's tenant (the outermost scope — F50), and republishes it onto the bus as
// the canonical probectl.bgp.v1.BGPEvent protobuf, keyed by tenant so a tenant's
// routing events stay co-located (pooled tenant-tagging). Detections are signals,
// not actions (CLAUDE.md §7 guardrail 9): the bridge transports them, it does not
// act on routing.
package bgp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// maxEventLine bounds a single JSONL record (defensive: collector-derived input
// is untrusted — CLAUDE.md §7 guardrail 10).
const maxEventLine = 1 << 20

// Publisher is the subset of the bus the bridge needs.
type Publisher interface {
	Publish(ctx context.Context, topic string, key, value []byte) error
}

// Bridge republishes analyzer events onto the bus.
type Bridge struct {
	bus Publisher
	log *slog.Logger
}

// Stats summarizes an ingest run.
type Stats struct {
	Published int // events published to the bus
	Skipped   int // events rejected (malformed or missing tenant) — never published
}

// NewBridge constructs a Bridge over the given bus.
func NewBridge(b Publisher, log *slog.Logger) *Bridge {
	if log == nil {
		log = slog.Default()
	}
	return &Bridge{bus: b, log: log}
}

// Ingest reads JSON-Lines events from r until EOF, publishing each valid event
// to probectl.bgp.events keyed by its tenant. A malformed or tenant-less line is
// logged and skipped (fail closed), so one bad record never blocks the stream or
// leaks across tenants. It returns the stats and the first transport error
// (a publish failure is fatal to the run; a parse/validation failure is not).
func (br *Bridge) Ingest(ctx context.Context, r io.Reader) (Stats, error) {
	var stats Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxEventLine)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			stats.Skipped++
			br.log.Warn("skipping malformed bgp event", "error", err)
			continue
		}
		if err := ev.validate(); err != nil {
			stats.Skipped++
			br.log.Warn("skipping invalid bgp event", "error", err)
			continue
		}
		value, err := proto.Marshal(ev.toProto())
		if err != nil {
			stats.Skipped++
			br.log.Warn("skipping unmarshalable bgp event", "error", err, "prefix", ev.Prefix)
			continue
		}
		if err := br.bus.Publish(ctx, bus.BGPEventsTopic, []byte(ev.TenantID), value); err != nil {
			return stats, fmt.Errorf("bgp: publish event: %w", err)
		}
		stats.Published++
		br.log.Info("bgp event bridged",
			"tenant_id", ev.TenantID,
			"event_type", ev.EventType,
			"prefix", ev.Prefix,
			"severity", ev.Severity,
		)
	}
	if err := sc.Err(); err != nil {
		return stats, fmt.Errorf("bgp: read event stream: %w", err)
	}
	return stats, nil
}
