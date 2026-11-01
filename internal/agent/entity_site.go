// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

const (
	siteEvidenceRefresh = 12 * time.Hour
	siteEvidenceRetry   = time.Minute
)

// SiteEvidenceEmitter is the optional D-179 evidence-only mTLS client. Its
// request has no tenant, context or canonical site ID. The live operator
// assignment selects the site under FORCE RLS on the receiver.
type SiteEvidenceEmitter interface {
	Submit(context.Context, []entity.Observation) (accepted, unresolved int, err error)
}

// WithSiteEvidence is called before Run once the evidence SVID has been
// checked against this agent's ordinary mTLS tenant and registered ID.
func (a *Agent) WithSiteEvidence(emitter SiteEvidenceEmitter) {
	a.siteEvidence = emitter
	if emitter != nil {
		a.siteEvidenceReset = make(chan struct{}, 1)
	}
}

// RefreshSiteEvidenceAfterRotation wakes the optional worker so it attests
// the current site under the renewed SVID rather than waiting 12 hours.
func (a *Agent) RefreshSiteEvidenceAfterRotation() {
	if a == nil || a.siteEvidenceReset == nil {
		return
	}
	select {
	case a.siteEvidenceReset <- struct{}{}:
	default:
	}
}

func (a *Agent) siteObservation(at time.Time) (entity.Observation, error) {
	id, err := crypto.UUIDv4()
	if err != nil {
		return entity.Observation{}, err
	}
	return entity.Observation{
		ID: id,
		Source: entity.SourceKey{AgentID: a.agentID, Kind: entity.AgentSite,
			SourceRef: a.agentID},
		Alias: entity.AliasKey{Kind: entity.AgentSiteAlias,
			Value: a.cfg.Agent.Labels["site"]},
		SourceRef: "agent:label:site", ObservedAt: at,
	}, nil
}

// This optional, one-claim worker never delays probe execution, heartbeat or
// result forwarding. A failed/unresolved claim remains raw and retries; only
// an accepted claim waits for the next pre-expiry refresh.
func (a *Agent) runSiteEvidence(ctx context.Context) {
	delay := time.Duration(0)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		case <-a.siteEvidenceReset:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		claim, err := a.siteObservation(time.Now().UTC())
		if err != nil {
			a.log.Error("agent site evidence ID unavailable", "tenant_id", a.tenantID,
				"agent_id", a.agentID, "error", err.Error())
			delay = siteEvidenceRetry
			continue
		}
		accepted, unresolved, err := a.siteEvidence.Submit(ctx, []entity.Observation{claim})
		if a.metrics != nil {
			a.metrics.EntityEvidence(accepted, unresolved, err)
		}
		if err != nil {
			a.log.Warn("agent site canonical evidence unavailable; raw agent results retained",
				"tenant_id", a.tenantID, "agent_id", a.agentID, "error", err.Error())
			delay = siteEvidenceRetry
			continue
		}
		if accepted == 1 && unresolved == 0 {
			delay = siteEvidenceRefresh
		} else {
			delay = siteEvidenceRetry
		}
	}
}
