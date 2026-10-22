// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

// The control plane's trap read model (D-60, DPR-296). The device agent
// authenticates each SNMP trap and publishes it on the tenant's trap-events
// lane; the control plane persists it into the forced-RLS device_traps table,
// and GET /v1/device/traps reads it back. These bounds are the untrusted-ingest
// contract: a trap is a datagram a device (or anyone who reached the agent)
// chose the contents of, so every field is capped before it reaches storage.
const (
	// MaxTrapVarBinds caps the varbinds stored per trap. A trap carrying more
	// keeps its first MaxTrapVarBinds (in wire order) and is marked truncated.
	MaxTrapVarBinds = 64
	// MaxTrapVarBindValueBytes caps one stored varbind value.
	MaxTrapVarBindValueBytes = 512
	// MaxTrapOIDLength caps a trap OID / varbind OID (dotted decimal).
	MaxTrapOIDLength = 255
	// MaxTrapsPerTenant bounds a tenant's stored traps; older rows are pruned
	// on write, newest kept.
	MaxTrapsPerTenant = 10_000
	// TrapRetention is the age after which a stored trap is pruned on write.
	TrapRetention = 30 * 24 * time.Hour
	// MaxTrapRead is the hard cap on one GET /v1/device/traps page.
	MaxTrapRead = 500
	// DefaultTrapRead is the page size when the caller names none.
	DefaultTrapRead = 100
	// MaxTrapEventsPerBatch bounds one trap-events bus record. The agent
	// publishes one trap per batch; anything larger is refused as malformed.
	MaxTrapEventsPerBatch = 64

	maxTrapIdentityLength = 255
	maxTrapKindLength     = 64
	maxTrapTypeLength     = 32
	maxTrapFingerprint    = 64
	maxTrapAgentID        = 128
)

// ErrInvalidTrapRecord marks a trap the store must never persist.
var ErrInvalidTrapRecord = errors.New("device trap record: invalid")

// TrapRecord is one stored, authenticated SNMP trap as the control plane holds
// it. It never carries credential material: auth_principal is the configured
// source name (SNMPv2c) or the USM user name (SNMPv3), never a community or
// passphrase.
type TrapRecord struct {
	ID                string        `json:"id"`
	TenantID          string        `json:"-"`
	AgentID           string        `json:"agent_id"`
	DeviceAddress     string        `json:"device_address"`
	SourceAddress     string        `json:"source_address,omitempty"`
	AuthPrincipal     string        `json:"auth_principal,omitempty"`
	Version           string        `json:"version"`
	Kind              string        `json:"kind"`
	Severity          string        `json:"severity"`
	TrapOID           string        `json:"trap_oid"`
	TrapName          string        `json:"trap_name"`
	RequestID         int64         `json:"request_id"`
	UptimeTicks       uint32        `json:"uptime_ticks,omitempty"`
	IfIndex           uint32        `json:"if_index,omitempty"`
	VarBinds          []TrapVarBind `json:"varbinds"`
	VarBindsTruncated bool          `json:"varbinds_truncated,omitempty"`
	Fingerprint       string        `json:"fingerprint"`
	ObservedAt        time.Time     `json:"observed_at"`
	ReceivedAt        time.Time     `json:"received_at"`
}

// TrapFilter bounds one tenant-scoped trap read.
type TrapFilter struct {
	Device string
	Since  time.Time
	Until  time.Time
	Limit  int
}

// TrapEventStore is the durable, tenant-scoped trap read model.
// RecordTrapEvent is idempotent on (tenant, agent, fingerprint): a redelivered
// bus record reports inserted=false and changes nothing.
type TrapEventStore interface {
	RecordTrapEvent(ctx context.Context, tenant string, rec TrapRecord) (inserted bool, err error)
	ListTrapEvents(ctx context.Context, tenant string, filter TrapFilter) ([]TrapRecord, bool, error)
}

// TrapMatchQuery asks for each device's newest trap that matches a trap alert
// rule (D-61): its trap OID or its clear-trap OID, optionally one device and
// one exact varbind value, received at or after Since.
type TrapMatchQuery struct {
	TrapOID      string
	ClearTrapOID string
	Device       string
	VarBindOID   string
	VarBindValue string
	Since        time.Time
	Limit        int
}

// TrapMatch is one device's newest matching trap.
type TrapMatch struct {
	DeviceAddress string
	TrapOID       string
	ReceivedAt    time.Time
}

// MaxTrapMatchDevices bounds the devices one trap rule evaluates per pass.
const MaxTrapMatchDevices = 500

// TrapMatchReader is the tenant-scoped read a trap alert rule evaluates.
type TrapMatchReader interface {
	LatestTrapMatches(ctx context.Context, tenant string, q TrapMatchQuery) ([]TrapMatch, error)
}

// TrapRecordFromProto maps one bus trap event onto a record. The tenant on the
// wire is copied as-is; the consumer overwrites it with the verified lane
// tenant before validation (the payload is never authoritative).
func TrapRecordFromProto(e *devicev1.DeviceTrapEvent) TrapRecord {
	rec := TrapRecord{
		TenantID:      e.GetTenantId(),
		AgentID:       e.GetAgentId(),
		DeviceAddress: e.GetDeviceAddress(),
		SourceAddress: e.GetSourceAddress(),
		AuthPrincipal: e.GetAuthPrincipal(),
		Version:       e.GetVersion(),
		Kind:          e.GetKind(),
		Severity:      e.GetSeverity(),
		TrapOID:       e.GetTrapOid(),
		RequestID:     e.GetRequestId(),
		UptimeTicks:   e.GetUptimeTicks(),
		IfIndex:       e.GetIfIndex(),
		Fingerprint:   e.GetFingerprint(),
	}
	for _, vb := range e.GetVarbinds() {
		rec.VarBinds = append(rec.VarBinds, TrapVarBind{OID: vb.GetOid(), Type: vb.GetType(), Value: vb.GetValue()})
	}
	return rec
}

// ValidateTrapRecord normalizes and bounds an untrusted trap record. Identity
// and shape violations are refused (ErrInvalidTrapRecord); oversized payloads
// are truncated (varbind list) or sanitized (non-UTF-8 values become hex) so a
// device cannot poison the store or the redelivery loop.
func ValidateTrapRecord(rec TrapRecord) (TrapRecord, error) {
	rec.TenantID = strings.TrimSpace(rec.TenantID)
	rec.AgentID = strings.TrimSpace(rec.AgentID)
	if rec.TenantID == "" {
		return TrapRecord{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidTrapRecord)
	}
	if rec.AgentID == "" || len(rec.AgentID) > maxTrapAgentID || !printableTrapText(rec.AgentID) {
		return TrapRecord{}, fmt.Errorf("%w: agent_id must be 1-%d printable characters", ErrInvalidTrapRecord, maxTrapAgentID)
	}
	if err := validateTrapIdentity(&rec); err != nil {
		return TrapRecord{}, err
	}
	if err := normalizeTrapClass(&rec); err != nil {
		return TrapRecord{}, err
	}
	rec.VarBinds, rec.VarBindsTruncated = boundTrapVarBinds(rec.VarBinds, rec.VarBindsTruncated)
	if rec.ObservedAt.IsZero() {
		rec.ObservedAt = rec.ReceivedAt
	}
	rec.ObservedAt, rec.ReceivedAt = rec.ObservedAt.UTC(), rec.ReceivedAt.UTC()
	rec.TrapName = TrapName(rec.TrapOID)
	return rec, nil
}

func validateTrapIdentity(rec *TrapRecord) error {
	rec.DeviceAddress = strings.TrimSpace(rec.DeviceAddress)
	if rec.DeviceAddress == "" || len(rec.DeviceAddress) > maxTrapIdentityLength || !printableTrapText(rec.DeviceAddress) {
		return fmt.Errorf("%w: device_address must be 1-%d printable characters", ErrInvalidTrapRecord, maxTrapIdentityLength)
	}
	for name, v := range map[string]string{"source_address": rec.SourceAddress, "auth_principal": rec.AuthPrincipal} {
		if len(v) > maxTrapIdentityLength || !printableTrapText(v) {
			return fmt.Errorf("%w: %s must be at most %d printable characters", ErrInvalidTrapRecord, name, maxTrapIdentityLength)
		}
	}
	rec.Fingerprint = strings.TrimSpace(rec.Fingerprint)
	if rec.Fingerprint == "" || len(rec.Fingerprint) > maxTrapFingerprint || !printableTrapText(rec.Fingerprint) {
		return fmt.Errorf("%w: fingerprint must be 1-%d printable characters", ErrInvalidTrapRecord, maxTrapFingerprint)
	}
	if rec.TrapOID != "" && !validTrapOID(rec.TrapOID) {
		return fmt.Errorf("%w: trap_oid must be a dotted-decimal OID of at most %d characters", ErrInvalidTrapRecord, MaxTrapOIDLength)
	}
	rec.TrapOID = NormalizeTrapOID(rec.TrapOID)
	return nil
}

func normalizeTrapClass(rec *TrapRecord) error {
	switch rec.Version {
	case "snmpv1", "snmpv2c", "snmpv3":
	default:
		return fmt.Errorf("%w: version must be snmpv1, snmpv2c or snmpv3", ErrInvalidTrapRecord)
	}
	if rec.Kind == "" {
		rec.Kind = "snmp.trap"
	}
	if len(rec.Kind) > maxTrapKindLength || !strings.HasPrefix(rec.Kind, "snmp.trap") || !printableTrapText(rec.Kind) {
		return fmt.Errorf("%w: kind must be an snmp.trap kind of at most %d characters", ErrInvalidTrapRecord, maxTrapKindLength)
	}
	switch rec.Severity {
	case "info", "warning", "critical":
	default:
		rec.Severity = "info"
	}
	return nil
}

// boundTrapVarBinds keeps at most MaxTrapVarBinds varbinds, drops any whose OID
// is not a dotted-decimal OID, and sanitizes every value to valid, NUL-free
// UTF-8 of at most MaxTrapVarBindValueBytes.
func boundTrapVarBinds(in []TrapVarBind, truncated bool) ([]TrapVarBind, bool) {
	out := make([]TrapVarBind, 0, min(len(in), MaxTrapVarBinds))
	for _, vb := range in {
		if len(out) == MaxTrapVarBinds {
			truncated = true
			break
		}
		if !validTrapOID(vb.OID) {
			truncated = true
			continue
		}
		typ := vb.Type
		if len(typ) > maxTrapTypeLength || !printableTrapText(typ) {
			typ = "Unknown"
		}
		value, cut := sanitizeTrapValue(vb.Value)
		truncated = truncated || cut
		out = append(out, TrapVarBind{OID: vb.OID, Type: typ, Value: value})
	}
	return out, truncated
}

// sanitizeTrapValue makes an untrusted varbind value storable: binary or
// NUL-bearing octet strings (MAC addresses, engine ids) become "0x<hex>", and
// the result is capped at MaxTrapVarBindValueBytes on a rune boundary.
func sanitizeTrapValue(v string) (string, bool) {
	if !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
		v = "0x" + hex.EncodeToString([]byte(v))
	}
	if len(v) <= MaxTrapVarBindValueBytes {
		return v, false
	}
	cut := MaxTrapVarBindValueBytes
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut], true
}

func validTrapOID(oid string) bool {
	if oid == "" || len(oid) > MaxTrapOIDLength {
		return false
	}
	s := strings.TrimPrefix(oid, ".")
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func printableTrapText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// TrapName is the human name of a well-known SNMP trap OID (RFC 3418
// snmpTraps), or "" when the OID is enterprise-specific.
func TrapName(oid string) string {
	switch "." + strings.TrimPrefix(oid, ".") {
	case oidSNMPColdStart:
		return "coldStart"
	case oidSNMPWarmStart:
		return "warmStart"
	case oidSNMPLinkDown:
		return "linkDown"
	case oidSNMPLinkUp:
		return "linkUp"
	case oidSNMPAuthFailure:
		return "authenticationFailure"
	default:
		return ""
	}
}

// NormalizeTrapOID returns oid in the agent's canonical leading-dot form, so a
// rule written as "1.3.6.1.6.3.1.1.5.3" matches a stored ".1.3.6.1.6.3.1.1.5.3".
func NormalizeTrapOID(oid string) string {
	oid = strings.TrimSpace(oid)
	if oid == "" {
		return ""
	}
	return "." + strings.TrimPrefix(oid, ".")
}
