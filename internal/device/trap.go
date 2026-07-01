// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	SourceSNMPTrap = "snmp_trap"

	oidSNMPTrapOID0          = ".1.3.6.1.6.3.1.1.4.1.0"
	oidSNMPColdStart         = ".1.3.6.1.6.3.1.1.5.1"
	oidSNMPWarmStart         = ".1.3.6.1.6.3.1.1.5.2"
	oidSNMPLinkDown          = ".1.3.6.1.6.3.1.1.5.3"
	oidSNMPLinkUp            = ".1.3.6.1.6.3.1.1.5.4"
	oidSNMPAuthFailure       = ".1.3.6.1.6.3.1.1.5.5"
	oidIfIndex               = ".1.3.6.1.2.1.2.2.1.1"
	defaultMaxTrapRowsTenant = 1000
)

// TrapSource is one authenticated sender allowed to emit traps for the runtime's
// tenant. The Credential field is resolved from the existing CredentialSource
// seam before construction; events store Name/username, never secret material.
type TrapSource struct {
	Name       string
	Address    string
	Transport  string // snmpv2c | snmpv3
	Credential Credential
}

// TrapReceiverConfig configures one tenant-bound SNMP trap receiver.
type TrapReceiverConfig struct {
	TenantID string
	AgentID  string
	Sources  []TrapSource
	Now      func() time.Time
}

// TrapVarBind is one normalized SNMP varbind.
type TrapVarBind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// TrapEvent is the normalized event row produced by an accepted trap.
type TrapEvent struct {
	ID            string        `json:"id"`
	TenantID      string        `json:"tenant_id"`
	AgentID       string        `json:"agent_id"`
	SourceAddress string        `json:"source_address"`
	DeviceAddress string        `json:"device_address"`
	Source        string        `json:"source"`
	AuthPrincipal string        `json:"auth_principal"`
	Version       string        `json:"version"`
	Kind          string        `json:"kind"`
	Severity      string        `json:"severity"`
	TrapOID       string        `json:"trap_oid"`
	RequestID     int           `json:"request_id"`
	UptimeTicks   uint32        `json:"uptime_ticks,omitempty"`
	IfIndex       uint32        `json:"if_index,omitempty"`
	VarBinds      []TrapVarBind `json:"varbinds,omitempty"`
	Fingerprint   string        `json:"fingerprint"`
	ObservedAt    time.Time     `json:"observed_at"`
}

// TrapAlert is the operator-triage row paired with each accepted trap event.
type TrapAlert struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	TenantID    string    `json:"tenant_id"`
	Device      string    `json:"device"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	Fingerprint string    `json:"fingerprint"`
	ObservedAt  time.Time `json:"observed_at"`
}

// TrapStore persists normalized trap events and their alert rows.
type TrapStore interface {
	RecordTrap(ctx context.Context, event TrapEvent, alert TrapAlert) (TrapEvent, TrapAlert, bool, error)
}

// TrapReceiver authenticates, deduplicates, and normalizes SNMP traps for one
// tenant. A single receiver never accepts or emits cross-tenant rows.
type TrapReceiver struct {
	cfg     TrapReceiverConfig
	store   TrapStore
	sources []TrapSource
	params  *gosnmp.GoSNMP
}

// NewTrapReceiver validates cfg and builds a tenant-bound trap receiver.
func NewTrapReceiver(cfg TrapReceiverConfig, store TrapStore) (*TrapReceiver, error) {
	if cfg.TenantID == "" {
		return nil, errors.New("device trap: tenant_id is required")
	}
	if store == nil {
		return nil, errors.New("device trap: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	sources := append([]TrapSource(nil), cfg.Sources...)
	if len(sources) == 0 {
		return nil, errors.New("device trap: at least one authenticated source is required")
	}
	params, err := trapSNMPParams(sources)
	if err != nil {
		return nil, err
	}
	return &TrapReceiver{cfg: cfg, store: store, sources: sources, params: params}, nil
}

// Listen runs a gosnmp-backed UDP trap listener until ctx is canceled.
func (r *TrapReceiver) Listen(ctx context.Context, addr string) error {
	if addr == "" {
		return errors.New("device trap: listen address is required")
	}
	tl := gosnmp.NewTrapListener()
	tl.Params = r.params
	tl.OnNewTrap = func(pkt *gosnmp.SnmpPacket, remote *net.UDPAddr) {
		_, _, _, _ = r.RecordPacket(ctx, pkt, remote)
	}
	go func() {
		<-ctx.Done()
		tl.Close()
	}()
	return tl.Listen(addr)
}

// DecodeAndRecord decodes a raw SNMP trap datagram, authenticates it against the
// configured sources, and records exactly one event+alert row unless it is a
// duplicate replay.
func (r *TrapReceiver) DecodeAndRecord(ctx context.Context, data []byte, remote *net.UDPAddr) (TrapEvent, TrapAlert, bool, error) {
	if len(data) == 0 {
		return TrapEvent{}, TrapAlert{}, false, errors.New("device trap: empty datagram")
	}
	cp := append([]byte(nil), data...)
	pkt, err := r.params.UnmarshalTrap(cp, true)
	if err != nil {
		return TrapEvent{}, TrapAlert{}, false, fmt.Errorf("device trap: decode/authenticate: %w", err)
	}
	return r.RecordPacket(ctx, pkt, remote)
}

// RecordPacket records a packet already decoded by gosnmp's listener.
func (r *TrapReceiver) RecordPacket(ctx context.Context, pkt *gosnmp.SnmpPacket, remote *net.UDPAddr) (TrapEvent, TrapAlert, bool, error) {
	if pkt == nil {
		return TrapEvent{}, TrapAlert{}, false, errors.New("device trap: nil packet")
	}
	source, principal, err := r.authenticate(pkt, remote)
	if err != nil {
		return TrapEvent{}, TrapAlert{}, false, err
	}
	event := normalizeTrap(r.cfg, pkt, remote, source, principal)
	alert := alertFromTrap(event)
	return r.store.RecordTrap(ctx, event, alert)
}

func (r *TrapReceiver) authenticate(pkt *gosnmp.SnmpPacket, remote *net.UDPAddr) (TrapSource, string, error) {
	switch pkt.Version {
	case gosnmp.Version2c:
		for _, src := range r.sources {
			if src.Transport != TransportSNMPv2c {
				continue
			}
			if !sourceAddressMatches(src.Address, remote) {
				continue
			}
			if src.Credential.Community != "" && pkt.Community == src.Credential.Community {
				return src, src.Name, nil
			}
		}
		return TrapSource{}, "", errors.New("device trap: unauthenticated snmpv2c community/source")
	case gosnmp.Version3:
		user := trapUsername(pkt)
		var fallback *TrapSource
		fallbacks := 0
		for _, src := range r.sources {
			if src.Transport != TransportSNMPv3 {
				continue
			}
			if !sourceAddressMatches(src.Address, remote) {
				continue
			}
			cp := src
			fallback = &cp
			fallbacks++
			if src.Credential.Username == user {
				return src, user, nil
			}
		}
		if user == "" && fallback != nil && fallbacks == 1 {
			return *fallback, fallback.Credential.Username, nil
		}
		return TrapSource{}, "", errors.New("device trap: unauthenticated snmpv3 user/source")
	default:
		return TrapSource{}, "", fmt.Errorf("device trap: unsupported SNMP version %v", pkt.Version)
	}
}

func trapSNMPParams(sources []TrapSource) (*gosnmp.GoSNMP, error) {
	logger := gosnmp.NewLogger(log.New(io.Discard, "", 0))
	table := gosnmp.NewSnmpV3SecurityParametersTable(logger)
	var v3Params []*gosnmp.UsmSecurityParameters
	for i := range sources {
		src := &sources[i]
		if src.Name == "" {
			return nil, errors.New("device trap: source name is required")
		}
		switch src.Transport {
		case TransportSNMPv2c:
			if src.Credential.Community == "" {
				return nil, fmt.Errorf("device trap: source %q missing snmpv2c community credential", src.Name)
			}
		case TransportSNMPv3:
			sp, err := trapUSM(src.Credential)
			if err != nil {
				return nil, fmt.Errorf("device trap: source %q: %w", src.Name, err)
			}
			if err := table.Add(sp.UserName, sp); err != nil {
				return nil, fmt.Errorf("register snmpv3 trap source: %w", err)
			}
			v3Params = append(v3Params, sp)
		default:
			return nil, fmt.Errorf("device trap: source %q transport %q is not snmpv2c|snmpv3", src.Name, src.Transport)
		}
	}
	params := &gosnmp.GoSNMP{Logger: logger}
	if len(v3Params) == 1 {
		params.Version = gosnmp.Version3
		params.SecurityModel = gosnmp.UserSecurityModel
		params.SecurityParameters = v3Params[0]
	} else if len(v3Params) > 1 {
		params.Version = gosnmp.Version3
		params.SecurityModel = gosnmp.UserSecurityModel
		params.TrapSecurityParametersTable = table
	}
	return params, nil
}

func trapUSM(cred Credential) (*gosnmp.UsmSecurityParameters, error) {
	if cred.Username == "" || cred.AuthPass == "" {
		return nil, errors.New("snmpv3 trap source requires username and auth_pass")
	}
	usm := &gosnmp.UsmSecurityParameters{
		UserName:                 cred.Username,
		AuthenticationPassphrase: cred.AuthPass,
	}
	switch strings.ToLower(cred.AuthProto) {
	case "", "sha":
		usm.AuthenticationProtocol = gosnmp.SHA
	case "sha256":
		usm.AuthenticationProtocol = gosnmp.SHA256
	case "sha512":
		usm.AuthenticationProtocol = gosnmp.SHA512
	case "md5":
		usm.AuthenticationProtocol = gosnmp.MD5
	default:
		return nil, fmt.Errorf("unknown auth proto %q", cred.AuthProto)
	}
	if cred.PrivPass != "" {
		usm.PrivacyPassphrase = cred.PrivPass
		switch strings.ToLower(cred.PrivProto) {
		case "", "aes":
			usm.PrivacyProtocol = gosnmp.AES
		case "aes256":
			usm.PrivacyProtocol = gosnmp.AES256
		case "des":
			usm.PrivacyProtocol = gosnmp.DES
		default:
			return nil, fmt.Errorf("unknown priv proto %q", cred.PrivProto)
		}
	}
	return usm, nil
}

func normalizeTrap(cfg TrapReceiverConfig, pkt *gosnmp.SnmpPacket, remote *net.UDPAddr, source TrapSource, principal string) TrapEvent {
	remoteIP := ""
	if remote != nil && remote.IP != nil {
		remoteIP = remote.IP.String()
	}
	trapOID := ""
	var uptime uint32
	var ifIndex uint32
	var binds []TrapVarBind
	for _, p := range pkt.Variables {
		val := pduValueString(p.Value)
		binds = append(binds, TrapVarBind{OID: p.Name, Type: p.Type.String(), Value: val})
		switch p.Name {
		case oidSNMPTrapOID0:
			trapOID = val
		case oidSysUpTime:
			uptime = uint32(pduFloat(p))
		}
		if p.Name == oidIfIndex || strings.HasPrefix(p.Name, oidIfIndex+".") {
			if n := uint32(pduFloat(p)); n > 0 {
				ifIndex = n
			}
		}
	}
	if trapOID == "" && pkt.Enterprise != "" {
		trapOID = pkt.Enterprise
	}
	kind, severity := classifyTrap(trapOID)
	e := TrapEvent{
		TenantID:      cfg.TenantID,
		AgentID:       cfg.AgentID,
		SourceAddress: remoteIP,
		DeviceAddress: deviceAddressForTrap(pkt, remoteIP),
		Source:        SourceSNMPTrap,
		AuthPrincipal: principal,
		Version:       trapVersion(pkt.Version),
		Kind:          kind,
		Severity:      severity,
		TrapOID:       trapOID,
		RequestID:     int(pkt.RequestID),
		UptimeTicks:   uptime,
		IfIndex:       ifIndex,
		VarBinds:      binds,
		ObservedAt:    cfg.Now(),
	}
	if source.Address != "" {
		e.DeviceAddress = source.Address
	}
	e.Fingerprint = trapFingerprint(e)
	return e
}

func alertFromTrap(e TrapEvent) TrapAlert {
	title := trapTitle(e.Kind)
	summary := fmt.Sprintf("%s trap %s from %s", e.Version, e.TrapOID, e.DeviceAddress)
	if e.IfIndex > 0 {
		summary += fmt.Sprintf(" ifIndex=%d", e.IfIndex)
	}
	return TrapAlert{
		EventID:     e.ID,
		TenantID:    e.TenantID,
		Device:      e.DeviceAddress,
		Severity:    e.Severity,
		Title:       title,
		Summary:     summary,
		Fingerprint: e.Fingerprint,
		ObservedAt:  e.ObservedAt,
	}
}

func classifyTrap(trapOID string) (kind, severity string) {
	switch trapOID {
	case oidSNMPLinkDown:
		return "snmp.trap.link_down", "warning"
	case oidSNMPLinkUp:
		return "snmp.trap.link_up", "info"
	case oidSNMPColdStart:
		return "snmp.trap.cold_start", "warning"
	case oidSNMPWarmStart:
		return "snmp.trap.warm_start", "info"
	case oidSNMPAuthFailure:
		return "snmp.trap.authentication_failure", "warning"
	default:
		return "snmp.trap", "info"
	}
}

func trapTitle(kind string) string {
	switch kind {
	case "snmp.trap.link_down":
		return "SNMP link down"
	case "snmp.trap.link_up":
		return "SNMP link up"
	case "snmp.trap.cold_start":
		return "SNMP cold start"
	case "snmp.trap.warm_start":
		return "SNMP warm start"
	case "snmp.trap.authentication_failure":
		return "SNMP authentication failure"
	default:
		return "SNMP trap"
	}
}

func trapFingerprint(e TrapEvent) string {
	h := fnv.New64a()
	writeHash := func(s string) { _, _ = h.Write([]byte(s)); _, _ = h.Write([]byte{0}) }
	writeHash(e.TenantID)
	writeHash(e.DeviceAddress)
	writeHash(e.Version)
	writeHash(e.TrapOID)
	writeHash(strconv.Itoa(e.RequestID))
	writeHash(strconv.FormatUint(uint64(e.UptimeTicks), 10))
	for _, vb := range e.VarBinds {
		writeHash(vb.OID)
		writeHash(vb.Value)
	}
	return fmt.Sprintf("%016x", h.Sum64())
}

func deviceAddressForTrap(pkt *gosnmp.SnmpPacket, remoteIP string) string {
	if pkt.AgentAddress != "" {
		return pkt.AgentAddress
	}
	return remoteIP
}

func trapVersion(v gosnmp.SnmpVersion) string {
	switch v {
	case gosnmp.Version1:
		return "snmpv1"
	case gosnmp.Version2c:
		return "snmpv2c"
	case gosnmp.Version3:
		return "snmpv3"
	default:
		return fmt.Sprintf("snmpv%d", int(v))
	}
}

func trapUsername(pkt *gosnmp.SnmpPacket) string {
	if pkt.SecurityParameters == nil {
		return ""
	}
	if usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		return usm.UserName
	}
	return ""
}

func sourceAddressMatches(want string, remote *net.UDPAddr) bool {
	if want == "" {
		return true
	}
	if remote == nil || remote.IP == nil {
		return false
	}
	return remote.IP.String() == want
}

func pduValueString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// MemoryTrapStore keeps accepted trap event/alert rows partitioned by tenant and
// deduplicated by event fingerprint.
type MemoryTrapStore struct {
	mu      sync.Mutex
	max     int
	seq     uint64
	events  map[string][]TrapEvent
	alerts  map[string][]TrapAlert
	seen    map[string]map[string]TrapEvent
	alertBy map[string]TrapAlert
}

// NewMemoryTrapStore returns a bounded tenant-partitioned trap store.
func NewMemoryTrapStore(maxPerTenant int) *MemoryTrapStore {
	if maxPerTenant <= 0 {
		maxPerTenant = defaultMaxTrapRowsTenant
	}
	return &MemoryTrapStore{
		max:     maxPerTenant,
		events:  map[string][]TrapEvent{},
		alerts:  map[string][]TrapAlert{},
		seen:    map[string]map[string]TrapEvent{},
		alertBy: map[string]TrapAlert{},
	}
}

// RecordTrap stores an event and alert unless the fingerprint already exists
// inside the same tenant partition.
func (s *MemoryTrapStore) RecordTrap(_ context.Context, event TrapEvent, alert TrapAlert) (TrapEvent, TrapAlert, bool, error) {
	if event.TenantID == "" {
		return TrapEvent{}, TrapAlert{}, false, errors.New("device trap: tenant_id is required")
	}
	if event.Fingerprint == "" {
		return TrapEvent{}, TrapAlert{}, false, errors.New("device trap: fingerprint is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[event.TenantID] == nil {
		s.seen[event.TenantID] = map[string]TrapEvent{}
	}
	if existing, ok := s.seen[event.TenantID][event.Fingerprint]; ok {
		return existing, s.alertBy[existing.ID], false, nil
	}
	s.seq++
	event.ID = fmt.Sprintf("trap-%d", s.seq)
	alert.ID = fmt.Sprintf("trap-alert-%d", s.seq)
	alert.EventID = event.ID
	alert.TenantID = event.TenantID
	s.seen[event.TenantID][event.Fingerprint] = event
	s.alertBy[event.ID] = alert
	s.events[event.TenantID] = append([]TrapEvent{event}, s.events[event.TenantID]...)
	s.alerts[event.TenantID] = append([]TrapAlert{alert}, s.alerts[event.TenantID]...)
	if len(s.events[event.TenantID]) > s.max {
		s.events[event.TenantID] = s.events[event.TenantID][:s.max]
	}
	if len(s.alerts[event.TenantID]) > s.max {
		s.alerts[event.TenantID] = s.alerts[event.TenantID][:s.max]
	}
	return event, alert, true, nil
}

// ListTrapEvents returns a copy of one tenant's trap event partition.
func (s *MemoryTrapStore) ListTrapEvents(tenantID string) []TrapEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]TrapEvent(nil), s.events[tenantID]...)
	for i := range out {
		out[i].VarBinds = append([]TrapVarBind(nil), out[i].VarBinds...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt.After(out[j].ObservedAt) })
	return out
}

// ListTrapAlerts returns a copy of one tenant's trap alert partition.
func (s *MemoryTrapStore) ListTrapAlerts(tenantID string) []TrapAlert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]TrapAlert(nil), s.alerts[tenantID]...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt.After(out[j].ObservedAt) })
	return out
}
