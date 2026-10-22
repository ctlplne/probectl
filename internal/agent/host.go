// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/otel"
)

type scheduled struct {
	canary   canary.Canary
	interval time.Duration
	testID   string
}

const resultEnvelopeSchemaVersion uint32 = 1

// resultEnvelope stamps tenant + agent identity onto a canary result so it is
// tenant-attributable end to end (F50). It is the buffered and streamed payload.
// SchemaVersion 0 is the legacy pre-version frame and remains decodable.
type resultEnvelope struct {
	SchemaVersion uint32 `json:"schema_version,omitempty"`
	TenantID      string `json:"tenant_id"`
	AgentID       string `json:"agent_id"`
	// ResultID is a per-result UUID minted ONCE at probe time and persisted in
	// the buffer (CORRECT-002). Because it is stamped before the result is
	// buffered, a retried/redelivered frame carries the SAME id — the dedup key
	// the row stores collapse on. Minted here, not at send time, precisely so a
	// resend does not get a fresh id.
	ResultID string        `json:"result_id"`
	Result   canary.Result `json:"result"`
}

// newResultID mints the per-result dedup UUID (CORRECT-002); on the vanishingly
// rare RNG failure it returns "" and the control plane stamps a deterministic
// fallback id instead, so dedup still holds.
func newResultID() string {
	id, err := crypto.UUIDv4()
	if err != nil {
		return ""
	}
	return id
}

// Host schedules canaries and writes their results into the buffer. It runs
// independently of control-plane connectivity, so results accumulate while the
// control plane is unreachable.
//
// It runs two sets side by side: the static canaries from the local YAML, and
// the central test set the agent pulled and verified (G9, testsync.go), which
// applyCentral replaces at runtime by diff — a test whose definition did not
// change keeps its goroutine and cadence.
type Host struct {
	scheduled []scheduled
	buffer    *Buffer
	tenantID  string
	agentID   string
	log       *slog.Logger
	metrics   *agentmetrics.Runtime

	mu      sync.Mutex
	runCtx  context.Context // set while Run is active; nil before and after
	group   *errgroup.Group
	central map[string]*centralTest // test id -> running (or pending) central test
}

// centralTest is one central test the host runs. hash identifies its verified
// definition; cancel stops its goroutine (nil while Run has not started).
type centralTest struct {
	sched  scheduled
	hash   string
	cancel context.CancelFunc
}

// centralDef is one admitted central test, ready to schedule.
type centralDef struct {
	id    string
	hash  string
	sched scheduled
}

// Run runs each canary on its interval until ctx is canceled.
//
// Fan-out uses errgroup, the one sanctioned agent-side idiom (docs/architecture
// .md, "Concurrency idioms"): every goroutine is joined before Run returns, and
// there is a single place a future error return can be threaded through. The
// raw WaitGroup this replaced did the same job with a second vocabulary.
// firstProbeJitter bounds the random delay before a canary's FIRST probe.
// Probing immediately is what makes first data arrive in seconds instead of one
// full interval (DPR-139) — an agent with a five-minute check used to show an
// empty screen for five minutes — but firing every canary at t=0 would burst a
// host with many of them, and every agent in a fleet restarted together would
// burst the control plane. A short random offset gives both.
const firstProbeJitter = 3 * time.Second

func (h *Host) Run(ctx context.Context) {
	var g errgroup.Group
	h.mu.Lock()
	h.runCtx, h.group = ctx, &g
	for _, ct := range h.central {
		h.startCentralLocked(ct)
	}
	h.mu.Unlock()
	// Hold the group open for the whole run, so a central test started later
	// by applyCentral always joins a live group (never Go on a group whose
	// Wait may already be returning): the holder detaches the group under the
	// lock before it exits, and startCentralLocked starts nothing once it has.
	g.Go(func() error {
		<-ctx.Done()
		h.mu.Lock()
		h.runCtx, h.group = nil, nil
		for _, ct := range h.central {
			ct.cancel = nil
		}
		h.mu.Unlock()
		return nil
	})
	for _, s := range h.scheduled {
		g.Go(func() error { h.loop(ctx, s); return nil })
	}
	_ = g.Wait() // no schedule goroutine returns an error; ctx is the only exit
}

// loop runs one canary on its interval until ctx is canceled.
func (h *Host) loop(ctx context.Context, s scheduled) {
	// The first probe is immediate, modulo jitter that never exceeds the
	// interval itself — a 5ms canary must not wait 3s for its first run.
	jitter := firstProbeJitter
	if s.interval < jitter {
		jitter = s.interval
	}
	first := time.NewTimer(time.Duration(rand.Int64N(int64(jitter) + 1)))
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
		h.probe(ctx, s)
	}

	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.probe(ctx, s)
		}
	}
}

// applyCentral replaces the central test set with defs by diff: a test whose
// id and definition hash are unchanged keeps running untouched; a removed or
// changed test is stopped; a new or changed test is started. Before Run (the
// persisted set re-applied at start) the set is only recorded and Run starts
// it. It returns how many tests were started and stopped.
func (h *Host) applyCentral(defs []centralDef) (started, stopped int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.central == nil {
		h.central = map[string]*centralTest{}
	}
	want := make(map[string]centralDef, len(defs))
	for _, d := range defs {
		want[d.id] = d
	}
	for id, ct := range h.central {
		if d, keep := want[id]; keep && d.hash == ct.hash {
			continue
		}
		if ct.cancel != nil {
			ct.cancel()
		}
		delete(h.central, id)
		stopped++
	}
	for _, d := range defs {
		if _, running := h.central[d.id]; running {
			continue
		}
		ct := &centralTest{sched: d.sched, hash: d.hash}
		h.central[d.id] = ct
		h.startCentralLocked(ct)
		started++
	}
	return started, stopped
}

// startCentralLocked starts one central test's loop when Run is active.
// The caller holds h.mu.
func (h *Host) startCentralLocked(ct *centralTest) {
	if h.runCtx == nil {
		return
	}
	ctx, cancel := context.WithCancel(h.runCtx)
	ct.cancel = cancel
	s := ct.sched
	h.group.Go(func() error { h.loop(ctx, s); return nil })
}

// centralIDs returns the ids of the central tests the host currently holds.
func (h *Host) centralIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.central))
	for id := range h.central {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (h *Host) probe(ctx context.Context, s scheduled) {
	c := s.canary
	if h.metrics != nil {
		h.metrics.Collection(1)
	}
	res, err := c.Run(ctx)
	if err != nil {
		// A plugin/internal fault — distinct from a probe failure, which is a
		// Result with Success=false.
		h.log.Error("canary fault", "type", c.Describe().Type, "error", err.Error())
		if h.metrics != nil {
			h.metrics.Error()
		}
		return
	}
	if s.testID != "" {
		if res.Attributes == nil {
			res.Attributes = make(map[string]string, 2)
		}
		// These are runtime authority, not plugin input. Stamp them after Run so
		// a plugin cannot forge the local schedule identity used by cadence
		// receipts.
		res.Attributes[otel.AttrTestID] = s.testID
		res.Attributes[otel.AttrTestInterval] = strconv.FormatFloat(s.interval.Seconds(), 'f', -1, 64)
	}
	payload, err := json.Marshal(resultEnvelope{
		SchemaVersion: resultEnvelopeSchemaVersion,
		TenantID:      h.tenantID,
		AgentID:       h.agentID,
		ResultID:      newResultID(),
		Result:        res,
	})
	if err != nil {
		h.log.Error("marshal result", "error", err.Error())
		if h.metrics != nil {
			h.metrics.Error()
		}
		return
	}
	if err := h.buffer.Enqueue(payload); err != nil {
		h.log.Warn("dropping result (buffer full)", "type", res.Type, "error", err.Error())
		if h.metrics != nil {
			h.metrics.Error()
			h.metrics.SetBufferDepth(h.buffer.Len())
		}
		return
	}
	if h.metrics != nil {
		h.metrics.SetBufferDepth(h.buffer.Len())
	}
	// RESIL-009: warn early when the store-and-forward buffer is approaching
	// either bound (records or on-disk bytes) — a control-plane outage is filling
	// it and shedding is imminent. Observable before data loss starts.
	if h.buffer.NearFull(0.9) {
		h.log.Warn("store-and-forward buffer nearing capacity (impending low-disk drop)",
			"records", h.buffer.Len(), "bytes", h.buffer.Bytes(), "dropped", h.buffer.Dropped())
	}
}
