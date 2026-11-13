// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

// The writer retains every historical observation. A stable poll therefore
// refreshes its 24-hour authority twice daily instead of creating a new row
// for every one-minute SNMP poll. A changed identifier sends immediately.
// Prefix content and availability participate in the same fingerprint. A
// changed/withdrawn table sends immediately; unchanged verified observations
// retain the refresh cadence and the receiver's explicit 24-hour expiry.
const (
	entityEvidenceRefresh         = 12 * time.Hour
	entityEvidenceUnresolvedRetry = time.Hour
	deviceFaultRefresh            = 5 * time.Minute
	deviceFaultPendingMaxAge      = 6 * 24 * time.Hour
)

type entityEvidenceSnapshot struct {
	fingerprint string
	sentAt      time.Time // all claims accepted
	retryAt     time.Time // some claims unresolved; bound duplicate accepted rows
}

func identityFingerprint(target string, inv Inventory, neighbors []NeighborEvidence) string {
	type interfaceIdentity struct {
		Index                   uint32
		Name                    string
		Description             string
		OperStatus, AdminStatus uint32
		Addresses               []string
	}
	type neighborIdentity struct{ ID, ManagementAddress string }
	snapshot := struct {
		Target, SysName, SysDescr, PeerAddress string
		Interfaces                             []interfaceIdentity
		Neighbors                              []neighborIdentity
		PrefixAttempted                        bool
		Prefixes                               []snmpInterfacePrefix
	}{Target: target, SysName: inv.SysName, SysDescr: inv.SysDescr, PeerAddress: inv.peerAddress.String(),
		PrefixAttempted: inv.prefixAttempted, Prefixes: inv.interfacePrefixes}
	indexes := make([]uint32, 0, len(inv.Interfaces))
	for index := range inv.Interfaces {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	for _, index := range indexes {
		iface := inv.Interfaces[index]
		entry := interfaceIdentity{Index: index, Name: iface.Name, Description: iface.Descr, OperStatus: iface.OperStatus, AdminStatus: iface.AdminStatus}
		for _, address := range iface.Addrs {
			entry.Addresses = append(entry.Addresses, address.String())
		}
		sort.Strings(entry.Addresses)
		snapshot.Interfaces = append(snapshot.Interfaces, entry)
	}
	for _, neighbor := range neighbors {
		snapshot.Neighbors = append(snapshot.Neighbors, neighborIdentity{
			ID: neighbor.EvidenceID(), ManagementAddress: neighbor.RemoteManagementAddress})
	}
	sort.Slice(snapshot.Neighbors, func(i, j int) bool {
		if snapshot.Neighbors[i].ID != snapshot.Neighbors[j].ID {
			return snapshot.Neighbors[i].ID < snapshot.Neighbors[j].ID
		}
		return snapshot.Neighbors[i].ManagementAddress < snapshot.Neighbors[j].ManagementAddress
	})
	encoded, _ := json.Marshal(snapshot) // only fixed Go fields and bounded poll strings
	return hex.EncodeToString(crypto.Hash(encoded))
}

// EvidenceEmitter is the restricted D-179 mTLS writer. It never receives a
// tenant or canonical entity ID from a device packet; the live operator source
// assignment selects those on the server. Raw metrics continue over the bus.
type EvidenceEmitter interface {
	Submit(context.Context, []entity.Observation) (accepted, unresolved int, err error)
}

// FaultEmitter is optional for collectors that can report a bounded failure
// on the same sender-bound mTLS evidence channel as identity observations.
type FaultEmitter interface {
	SubmitFault(context.Context, entity.FaultObservation) error
}

// WithEntityEvidence attaches an already verified, sender-bound client before
// Run. A nil client leaves all canonical joins unresolved while raw metrics
// retain their existing path.
func (r *Runtime) WithEntityEvidence(emitter EvidenceEmitter) { r.evidence = emitter }

// RefreshEvidenceAfterRotation makes the next poll restate current identity
// under the new evidence certificate before the old serial expires.
func (r *Runtime) RefreshEvidenceAfterRotation() {
	r.evidenceMu.Lock()
	r.evidenceEpoch++
	r.evidenceLast = make(map[string]entityEvidenceSnapshot)
	r.faultPending = make(map[string]entity.FaultObservation)
	r.evidenceMu.Unlock()
}

func (r *Runtime) clearSNMPFault(address string) {
	r.evidenceMu.Lock()
	if !r.faultLast[address].IsZero() || r.faultPending[address].ID != "" {
		// A successful base poll must restate current evidence after a fault,
		// even when the complete fingerprint is unchanged. A failed evidence
		// RPC leaves the cache absent so the next successful poll retries.
		delete(r.evidenceLast, address)
	}
	delete(r.faultLast, address)
	delete(r.faultPending, address)
	r.evidenceMu.Unlock()
}

func (r *Runtime) emitSNMPFault(ctx context.Context, dev Target, at time.Time) {
	emitter, ok := r.evidence.(FaultEmitter)
	if !ok {
		return
	}
	// DNS names and malformed configured targets cannot name a canonical
	// address. The existing bus outcome still records the collection failure.
	addr, err := netip.ParseAddr(dev.Address)
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return
	}
	r.evidenceMu.Lock()
	if last := r.faultLast[dev.Address]; !last.IsZero() &&
		time.Since(last) < deviceFaultRefresh {
		r.evidenceMu.Unlock()
		return
	}
	fault, pending := r.faultPending[dev.Address]
	if pending && at.Sub(fault.ObservedAt) > deviceFaultPendingMaxAge {
		pending = false
	}
	if !pending {
		id, err := crypto.UUIDv4()
		if err != nil {
			r.evidenceMu.Unlock()
			r.stats.EvidenceErrors.Add(1)
			r.log.Warn("device fault evidence ID unavailable; collection outcome retained",
				"tenant_id", r.cfg.TenantID, "agent_id", r.cfg.AgentID,
				"error", err.Error())
			return
		}
		fault = entity.FaultObservation{ID: id,
			Source: entity.SourceKey{AgentID: r.cfg.AgentID,
				Kind: entity.DeviceTarget, SourceRef: dev.Address},
			Target: dev.Address, Kind: entity.FaultDevicePollFailed,
			ObservedAt: at}
		if r.faultPending == nil {
			r.faultPending = make(map[string]entity.FaultObservation)
		}
		r.faultPending[dev.Address] = fault
	}
	r.evidenceMu.Unlock()
	if err := emitter.SubmitFault(ctx, fault); err != nil {
		r.stats.EvidenceErrors.Add(1)
		r.log.Warn("device fault evidence unavailable; collection outcome retained",
			"tenant_id", r.cfg.TenantID, "agent_id", r.cfg.AgentID,
			"error", err.Error())
		return
	}
	r.evidenceMu.Lock()
	if current := r.faultPending[dev.Address]; current.ID == fault.ID {
		delete(r.faultPending, dev.Address)
		if r.faultLast == nil {
			r.faultLast = make(map[string]time.Time)
		}
		r.faultLast[dev.Address] = time.Now()
	}
	r.evidenceMu.Unlock()
}

func (r *Runtime) emitSNMPEntityEvidence(ctx context.Context, dev Target, inv Inventory,
	neighbors []NeighborEvidence, at time.Time) {
	if r.evidence == nil {
		return
	}
	fingerprint := identityFingerprint(dev.Address, inv, neighbors)
	r.evidenceMu.Lock()
	last := r.evidenceLast[dev.Address]
	epoch := r.evidenceEpoch
	skip := last.fingerprint == fingerprint &&
		((!last.sentAt.IsZero() && time.Since(last.sentAt) < entityEvidenceRefresh) ||
			(!last.retryAt.IsZero() && time.Since(last.retryAt) < entityEvidenceUnresolvedRetry))
	r.evidenceMu.Unlock()
	// The fingerprint includes complete prefix contents and availability.
	// Changes bypass the ordinary identity refresh without a per-poll append
	// stream. Fault recovery also invalidates the previous cached receipt.
	if skip {
		return
	}
	source := entity.SourceKey{AgentID: r.cfg.AgentID, Kind: entity.DeviceTarget,
		SourceRef: dev.Address}
	// The configured target and SNMP result are observations, never routing
	// authority. Only the current operator anchor can make either canonical.
	items := make([]entity.Observation, 0, 64)
	allResolved, submittedAny, acceptedAny := true, false, false
	flush := func() bool {
		if len(items) == 0 {
			return true
		}
		accepted, unresolved, err := r.evidence.Submit(ctx, items)
		if err != nil {
			r.stats.EvidenceErrors.Add(1)
			r.log.Warn("device canonical evidence unavailable; raw metrics retained",
				"tenant_id", r.cfg.TenantID, "agent_id", r.cfg.AgentID,
				"count", len(items), "error", err.Error())
			return false
		}
		r.stats.EvidenceAccepted.Add(uint64(accepted))
		r.stats.EvidenceUnresolved.Add(uint64(unresolved))
		submittedAny = true
		acceptedAny = acceptedAny || accepted > 0
		if unresolved != 0 || accepted != len(items) {
			allResolved = false
		}
		items = items[:0]
		return true
	}
	add := func(alias entity.AliasKey, originalRef, ifName, ifDescr string) bool {
		id, err := crypto.UUIDv4()
		if err != nil {
			r.stats.EvidenceErrors.Add(1)
			r.log.Error("device canonical evidence ID unavailable", "tenant_id", r.cfg.TenantID)
			return false
		}
		observation := entity.Observation{ID: id, Source: source,
			Alias: alias, SourceRef: originalRef, ObservedAt: at,
			InterfaceName: ifName, InterfaceDescription: ifDescr}
		if alias.Kind == entity.SNMPInterfaceAlias {
			index, err := strconv.ParseUint(alias.Value, 10, 32)
			if err != nil {
				return true
			}
			observation.SNMPInterfaceState = snmpOriginalInterfaceState(inv.Interfaces[uint32(index)])
		}
		claim, err := observation.Normalize(at)
		if err != nil {
			return true // untrusted SNMP data cannot reject the other claims
		}
		if originalRef == "snmp:configured-target" {
			claim = r.withSNMPSystemMetadata(claim, inv, at)
			claim = r.withSNMPPrefixMetadata(claim, inv, at)
		}
		items = append(items, claim)
		if originalRef == "snmp:configured-target" && inv.prefixAttempted {
			// Give the complete table its own wire envelope, rather than
			// combining it with an arbitrary number of interface aliases.
			return flush()
		}
		if len(items) == 64 {
			return flush()
		}
		return true
	}
	address, _ := netip.ParseAddr(dev.Address)
	if !address.IsValid() {
		address = inv.peerAddress
	}
	if address.IsValid() && address.Zone() == "" {
		if !add(entity.AliasKey{Kind: entity.AddressAlias, Value: address.Unmap().String()},
			"snmp:configured-target", "", "") {
			return
		}
	}
	if inv.SysName != "" && entity.ValidateSNMPSystemName(inv.SysName) == nil && !add(entity.AliasKey{Kind: entity.SNMPDeviceAlias,
		Value: inv.SysName}, "snmp:sysName", "", "") {
		return
	}
	indexes := make([]uint32, 0, len(inv.Interfaces))
	for index := range inv.Interfaces {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	for _, index := range indexes {
		iface := inv.Interfaces[index]
		if !add(entity.AliasKey{Kind: entity.SNMPInterfaceAlias,
			Value: strconv.FormatUint(uint64(index), 10)},
			fmt.Sprintf("snmp:ifIndex:%d", index), iface.Name, iface.Descr) {
			return
		}
		for _, address := range iface.Addrs {
			if !add(entity.AliasKey{Kind: entity.AddressAlias, Value: address.String()},
				fmt.Sprintf("snmp:ifIndex:%d", index), "", "") {
				return
			}
		}
	}
	for _, neighbor := range neighbors {
		if neighbor.LocalIfIndex == 0 || neighbor.RemotePortID == "" ||
			(neighbor.RemoteManagementAddress == "" && neighbor.RemoteDeviceName == "") {
			continue // no unique local/remote candidate; raw snapshot remains
		}
		id, err := crypto.UUIDv4()
		if err != nil {
			r.stats.EvidenceErrors.Add(1)
			return
		}
		original := neighbor.EvidenceID()
		claim := entity.Observation{ID: id, Source: source,
			Alias:     entity.AliasKey{Kind: entity.PhysicalNeighborAlias, Value: original},
			SourceRef: original, ObservedAt: at,
			NeighborProtocol: neighbor.Protocol, NeighborLocalIfIndex: neighbor.LocalIfIndex,
			NeighborLocalPortID:  neighbor.LocalPortID,
			NeighborRemotePortID: neighbor.RemotePortID,
			NeighborChassisID:    neighbor.RemoteChassisID,
			NeighborDeviceName:   neighbor.RemoteDeviceName,
			NeighborAddress:      neighbor.RemoteManagementAddress}
		if _, err := claim.Normalize(at); err != nil {
			continue // untrusted SNMP string cannot become canonical evidence
		}
		items = append(items, claim)
		if len(items) == 64 && !flush() {
			return
		}
	}
	if !flush() {
		return
	}
	if submittedAny {
		r.evidenceMu.Lock()
		if r.evidenceEpoch != epoch {
			// A rotation completed while this RPC was in flight. Do not let
			// its old-SVID response suppress the next fresh observation.
			r.evidenceMu.Unlock()
			return
		}
		if r.evidenceLast == nil {
			r.evidenceLast = make(map[string]entityEvidenceSnapshot)
		}
		if len(r.evidenceLast) > 65536 {
			r.evidenceLast = make(map[string]entityEvidenceSnapshot)
		}
		snapshot := entityEvidenceSnapshot{fingerprint: fingerprint}
		switch {
		case allResolved:
			snapshot.sentAt = time.Now()
		case acceptedAny:
			// The RPC reports aggregate outcomes, so we cannot isolate the
			// unresolved claim yet. Retry a stable inventory hourly instead of
			// writing every accepted alias once per one-minute poll.
			snapshot.retryAt = time.Now()
		}
		r.evidenceLast[dev.Address] = snapshot
		r.evidenceMu.Unlock()
	}
}

// Validate optional fields independently. A malformed name cannot discard a
// valid description/address, nor can a malformed description discard the name.
func (r *Runtime) withSNMPSystemMetadata(claim entity.Observation, inv Inventory, at time.Time) entity.Observation {
	withName := claim
	withName.SystemName = &inv.SysName
	if normalized, err := withName.Normalize(at); err == nil {
		claim = normalized
	} else {
		r.stats.EvidenceErrors.Add(1)
	}
	withDescription := claim
	withDescription.SystemDescription = inv.SysDescr
	if normalized, err := withDescription.Normalize(at); err == nil {
		claim = normalized
	} else {
		r.stats.EvidenceErrors.Add(1)
	}
	return claim
}

// snmpOriginalInterfaceState keeps column presence independent. In particular,
// a legacy binary flag cannot invent either original IF-MIB enumeration.
func snmpOriginalInterfaceState(iface Interface) *entity.SNMPInterfaceState {
	if iface.OperStatus == 0 && iface.AdminStatus == 0 {
		return nil
	}
	state := &entity.SNMPInterfaceState{Version: 1}
	if iface.OperStatus != 0 {
		state.OperStatus = &iface.OperStatus
	}
	if iface.AdminStatus != 0 {
		state.AdminStatus = &iface.AdminStatus
	}
	return state
}
