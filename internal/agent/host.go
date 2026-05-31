package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/canary"
)

type scheduled struct {
	canary   canary.Canary
	interval time.Duration
}

// resultEnvelope stamps tenant + agent identity onto a canary result so it is
// tenant-attributable end to end (F50). It is the buffered and streamed payload.
type resultEnvelope struct {
	TenantID string        `json:"tenant_id"`
	AgentID  string        `json:"agent_id"`
	Result   canary.Result `json:"result"`
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
	payload, err := json.Marshal(resultEnvelope{TenantID: h.tenantID, AgentID: h.agentID, Result: res})
	if err != nil {
		h.log.Error("marshal result", "error", err.Error())
		return
	}
	if err := h.buffer.Enqueue(payload); err != nil {
		h.log.Warn("dropping result (buffer full)", "type", res.Type, "error", err.Error())
	}
}
