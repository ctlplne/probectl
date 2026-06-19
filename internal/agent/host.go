// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

type scheduled struct {
	canary   canary.Canary
	interval time.Duration
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
type Host struct {
	scheduled []scheduled
	buffer    *Buffer
	tenantID  string
	agentID   string
	log       *slog.Logger
}

// Run runs each canary on its interval until ctx is canceled.
func (h *Host) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range h.scheduled {
		wg.Add(1)
		go func(s scheduled) {
			defer wg.Done()
			t := time.NewTicker(s.interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					h.probe(ctx, s.canary)
				}
			}
		}(s)
	}
	wg.Wait()
}

func (h *Host) probe(ctx context.Context, c canary.Canary) {
	res, err := c.Run(ctx)
	if err != nil {
		// A plugin/internal fault — distinct from a probe failure, which is a
		// Result with Success=false.
		h.log.Error("canary fault", "type", c.Describe().Type, "error", err.Error())
		return
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
		return
	}
	if err := h.buffer.Enqueue(payload); err != nil {
		h.log.Warn("dropping result (buffer full)", "type", res.Type, "error", err.Error())
		return
	}
	// RESIL-009: warn early when the store-and-forward buffer is approaching
	// either bound (records or on-disk bytes) — a control-plane outage is filling
	// it and shedding is imminent. Observable before data loss starts.
	if h.buffer.NearFull(0.9) {
		h.log.Warn("store-and-forward buffer nearing capacity (impending low-disk drop)",
			"records", h.buffer.Len(), "bytes", h.buffer.Bytes(), "dropped", h.buffer.Dropped())
	}
}
