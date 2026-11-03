// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

type agentAddressCollector func() ([]netip.Addr, error)

func collectAgentAddresses() ([]netip.Addr, error) {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return localAgentAddresses(interfaces)
}

// Retain the actual host IP, not an interface network or a guessed hostname.
// Interface zones are local enumeration context, never a target on the wire.
func localAgentAddresses(interfaces []net.Addr) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(interfaces))
	for _, value := range interfaces {
		var ip net.IP
		switch item := value.(type) {
		case *net.IPNet:
			if item == nil {
				return nil, entity.ErrInvalidClaim
			}
			ip = item.IP
		case *net.IPAddr:
			if item == nil {
				return nil, entity.ErrInvalidClaim
			}
			ip = item.IP
		default:
			return nil, entity.ErrInvalidClaim
		}
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, entity.ErrInvalidClaim
		}
		address = address.Unmap()
		if address.IsUnspecified() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			continue
		}
		addresses = append(addresses, address)
	}
	return entity.NormalizeAgentAddresses(addresses)
}

func sameAgentAddressSnapshot(a, b []netip.Addr) bool {
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}

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
// result forwarding. Poll locally for changes, but submit only a change,
// rotation or the existing pre-expiry refresh. A failed collection submits a
// nil-address fence instead of inventing a complete empty set.
func (a *Agent) runSiteEvidence(ctx context.Context) {
	delay := time.Duration(0)
	poll := siteEvidenceRetry
	if a.sitePollInterval > 0 {
		poll = a.sitePollInterval
	}
	collector := a.siteAddresses
	if collector == nil {
		collector = collectAgentAddresses
	}
	var previous []netip.Addr
	havePrevious, force := false, true
	var refreshAt time.Time
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
			force = true
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		now := time.Now().UTC()
		addresses, collectionErr := collector()
		if collectionErr == nil {
			addresses, collectionErr = entity.NormalizeAgentAddresses(addresses)
		}
		if collectionErr != nil {
			addresses = nil
			if force || !havePrevious || previous != nil {
				a.log.Warn("agent address collection unavailable; address facts withheld", "tenant_id", a.tenantID, "agent_id", a.agentID)
			}
		}
		if !force && havePrevious && sameAgentAddressSnapshot(previous, addresses) && now.Before(refreshAt) {
			delay = poll
			continue
		}
		claim, err := a.siteObservation(now)
		if err != nil {
			a.log.Error("agent site evidence ID unavailable", "tenant_id", a.tenantID,
				"agent_id", a.agentID, "error", err.Error())
			delay = poll
			continue
		}
		claim.AgentAddresses = addresses
		accepted, unresolved, err := a.siteEvidence.Submit(ctx, []entity.Observation{claim})
		if a.metrics != nil {
			a.metrics.EntityEvidence(accepted, unresolved, err)
		}
		if err != nil {
			a.log.Warn("agent site canonical evidence unavailable; raw agent results retained",
				"tenant_id", a.tenantID, "agent_id", a.agentID, "error", err.Error())
			force = true
			delay = poll
			continue
		}
		if accepted == 1 && unresolved == 0 {
			previous = addresses
			havePrevious, force = true, false
			refreshAt = now.Add(siteEvidenceRefresh)
		} else {
			force = true
		}
		delay = poll
	}
}
