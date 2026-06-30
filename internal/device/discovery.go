// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultDiscoveryMaxHosts = 1024

	DiscoveryStatusReviewRequired = "review_required"
	ActivationPendingReview       = "pending_review"

	AuditDiscoveryJobStarted     = "discovery.job_started"
	AuditDiscoveryDeviceFound    = "discovery.device_discovered"
	AuditDiscoveryReviewRequired = "discovery.review_required"
	AuditDiscoveryDeviceApproved = "discovery.device_approved"
)

var (
	ErrDiscoveryTenantRequired = errors.New("device discovery: tenant_id is required")
	ErrUnsafeDiscoveryRange    = errors.New("device discovery: unsafe range")
)

// DiscoveryJob is a tenant-scoped, review-only device discovery request. It
// carries credential references, never secret material.
type DiscoveryJob struct {
	ID              string                `json:"id"`
	TenantID        string                `json:"tenant_id"`
	CreatedBy       string                `json:"created_by,omitempty"`
	Ranges          []string              `json:"ranges"`
	Credentials     []DiscoveryCredential `json:"credentials"`
	ClassifierRules []ClassifierRule      `json:"classifier_rules,omitempty"`
	MaxHosts        int                   `json:"max_hosts,omitempty"`
}

// DiscoveryCredential points at a tenant-owned credential name. Discovery only
// uses SNMP transports today because gNMI is a configured streaming session, not
// a safe range probe.
type DiscoveryCredential struct {
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Port      uint16 `json:"port,omitempty"`
}

// ClassifierRule maps inventory evidence to a device role.
type ClassifierRule struct {
	Role             string   `json:"role"`
	SysNameContains  []string `json:"sys_name_contains,omitempty"`
	SysDescrContains []string `json:"sys_descr_contains,omitempty"`
	IfNameContains   []string `json:"if_name_contains,omitempty"`
	MinInterfaces    int      `json:"min_interfaces,omitempty"`
	Confidence       float64  `json:"confidence,omitempty"`
}

// DiscoveredInterface is the JSON-safe inventory shape shown to the reviewer.
type DiscoveredInterface struct {
	Index     uint32   `json:"index"`
	Name      string   `json:"name,omitempty"`
	Descr     string   `json:"descr,omitempty"`
	SpeedMbps uint64   `json:"speed_mbps,omitempty"`
	OperUp    bool     `json:"oper_up"`
	Addrs     []string `json:"addrs,omitempty"`
}

// DiscoveredDevice is a candidate device. It is deliberately not active until
// a reviewer accepts it.
type DiscoveredDevice struct {
	ID              string                `json:"id"`
	TenantID        string                `json:"tenant_id"`
	Address         string                `json:"address"`
	SysName         string                `json:"sys_name,omitempty"`
	SysDescr        string                `json:"sys_descr,omitempty"`
	Role            string                `json:"role"`
	Confidence      float64               `json:"confidence"`
	Credential      string                `json:"credential"`
	Transport       string                `json:"transport"`
	Port            uint16                `json:"port,omitempty"`
	ActivationState string                `json:"activation_state"`
	Interfaces      []DiscoveredInterface `json:"interfaces,omitempty"`
}

// DiscoveryAuditEvent is the tamper-evident audit payload callers can persist
// into the audit stream. It contains names and metadata, never credential
// material.
type DiscoveryAuditEvent struct {
	TenantID string            `json:"tenant_id"`
	JobID    string            `json:"job_id"`
	Action   string            `json:"action"`
	Subject  string            `json:"subject,omitempty"`
	Actor    string            `json:"actor,omitempty"`
	At       time.Time         `json:"at"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// DiscoveryResult is the reviewer handoff. Status stays review_required; this
// path never activates devices by itself.
type DiscoveryResult struct {
	JobID       string                `json:"job_id"`
	TenantID    string                `json:"tenant_id"`
	Status      string                `json:"status"`
	StartedAt   time.Time             `json:"started_at"`
	FinishedAt  time.Time             `json:"finished_at"`
	Devices     []DiscoveredDevice    `json:"devices"`
	AuditEvents []DiscoveryAuditEvent `json:"audit_events"`
}

// DiscoveryReview explicitly approves candidate IDs for import into the normal
// device-agent target list.
type DiscoveryReview struct {
	TenantID        string   `json:"tenant_id"`
	JobID           string   `json:"job_id"`
	ReviewedBy      string   `json:"reviewed_by"`
	AcceptDeviceIDs []string `json:"accept_device_ids"`
}

// DiscoveryProber probes one target with one resolved credential.
type DiscoveryProber interface {
	Probe(ctx context.Context, target Target, cred Credential) (Inventory, error)
}

// SNMPDiscoveryProber is the production prober: it uses the same SNMP dial and
// inventory collection path as steady-state polling.
type SNMPDiscoveryProber struct {
	Dial func(Target, Credential) (snmpConn, error)
	Now  func() time.Time
}

// Probe implements DiscoveryProber.
func (p SNMPDiscoveryProber) Probe(ctx context.Context, target Target, cred Credential) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	dial := p.Dial
	if dial == nil {
		dial = dialSNMP
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	conn, err := dial(target, cred)
	if err != nil {
		return Inventory{}, err
	}
	defer conn.Close()
	_, inv, err := pollSNMP(conn, target, "", "", now())
	return inv, err
}

// FixtureDiscoveryProber lets tests and air-gapped demos run the full
// discovery workflow without scanning a network.
type FixtureDiscoveryProber map[string]Inventory

// Probe implements DiscoveryProber.
func (p FixtureDiscoveryProber) Probe(ctx context.Context, target Target, cred Credential) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	if cred == (Credential{}) {
		return Inventory{}, fmt.Errorf("device discovery: credential %q resolved empty", target.Credential)
	}
	inv, ok := p[target.Address]
	if !ok {
		return Inventory{}, fmt.Errorf("device discovery: %s did not answer", target.Address)
	}
	out := cloneInventory(inv)
	if out.Device == "" {
		out.Device = target.Address
	}
	return out, nil
}

// Validate checks the job before any packet can leave the process.
func (j DiscoveryJob) Validate() error {
	if strings.TrimSpace(j.TenantID) == "" {
		return ErrDiscoveryTenantRequired
	}
	if strings.TrimSpace(j.ID) == "" {
		return errors.New("device discovery: id is required")
	}
	if len(j.Ranges) == 0 {
		return errors.New("device discovery: at least one range is required")
	}
	if len(j.Credentials) == 0 {
		return errors.New("device discovery: at least one credential reference is required")
	}
	for i, c := range j.Credentials {
		if c.TenantID != j.TenantID {
			return fmt.Errorf("device discovery: credentials[%d] tenant %q does not match job tenant %q", i, c.TenantID, j.TenantID)
		}
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("device discovery: credentials[%d] name is required", i)
		}
		switch c.Transport {
		case TransportSNMPv2c, TransportSNMPv3:
		default:
			return fmt.Errorf("device discovery: credentials[%d] transport %q is not supported for safe discovery", i, c.Transport)
		}
	}
	if _, err := safeDiscoveryTargets(j); err != nil {
		return err
	}
	return nil
}

// RunDiscovery probes the safe ranges, classifies answering devices, and
// returns review-only candidates plus audit events.
func RunDiscovery(ctx context.Context, job DiscoveryJob, creds CredentialSource, prober DiscoveryProber, now func() time.Time) (DiscoveryResult, error) {
	if err := job.Validate(); err != nil {
		return DiscoveryResult{}, err
	}
	if creds == nil {
		return DiscoveryResult{}, errors.New("device discovery: credential source is required")
	}
	if prober == nil {
		prober = SNMPDiscoveryProber{}
	}
	if now == nil {
		now = time.Now
	}
	targets, err := safeDiscoveryTargets(job)
	if err != nil {
		return DiscoveryResult{}, err
	}
	resolved := map[string]Credential{}
	for _, ref := range job.Credentials {
		if _, ok := resolved[ref.Name]; ok {
			continue
		}
		cred, err := creds.Resolve(ref.Name)
		if err != nil {
			return DiscoveryResult{}, err
		}
		resolved[ref.Name] = cred
	}

	started := now()
	result := DiscoveryResult{
		JobID:     job.ID,
		TenantID:  job.TenantID,
		Status:    DiscoveryStatusReviewRequired,
		StartedAt: started,
		AuditEvents: []DiscoveryAuditEvent{{
			TenantID: job.TenantID,
			JobID:    job.ID,
			Action:   AuditDiscoveryJobStarted,
			Actor:    job.CreatedBy,
			At:       started,
			Metadata: map[string]string{"ranges": fmt.Sprintf("%d", len(job.Ranges)), "targets": fmt.Sprintf("%d", len(targets))},
		}},
	}

	for _, addr := range targets {
		if err := ctx.Err(); err != nil {
			return DiscoveryResult{}, err
		}
		for _, ref := range job.Credentials {
			target := Target{
				Address:    addr.String(),
				Transport:  ref.Transport,
				Port:       ref.Port,
				Credential: ref.Name,
			}
			if target.Port == 0 {
				target.Port = 161
			}
			inv, err := prober.Probe(ctx, target, resolved[ref.Name])
			if err != nil {
				continue
			}
			if inv.Device == "" {
				inv.Device = target.Address
			}
			role, confidence := ClassifyInventory(inv, job.ClassifierRules)
			dev := discoveredDevice(job, inv, ref, role, confidence)
			result.Devices = append(result.Devices, dev)
			result.AuditEvents = append(result.AuditEvents, DiscoveryAuditEvent{
				TenantID: job.TenantID,
				JobID:    job.ID,
				Action:   AuditDiscoveryDeviceFound,
				Subject:  dev.ID,
				Actor:    job.CreatedBy,
				At:       now(),
				Metadata: map[string]string{
					"address":    dev.Address,
					"role":       dev.Role,
					"credential": dev.Credential,
					"transport":  dev.Transport,
				},
			})
			break
		}
	}
	sort.Slice(result.Devices, func(i, j int) bool { return result.Devices[i].Address < result.Devices[j].Address })
	result.FinishedAt = now()
	result.AuditEvents = append(result.AuditEvents, DiscoveryAuditEvent{
		TenantID: job.TenantID,
		JobID:    job.ID,
		Action:   AuditDiscoveryReviewRequired,
		Actor:    job.CreatedBy,
		At:       result.FinishedAt,
		Metadata: map[string]string{"devices": fmt.Sprintf("%d", len(result.Devices))},
	})
	return result, nil
}

// ClassifyInventory classifies a device from sysName/sysDescr/interface
// evidence. Operator rules win, then conservative built-ins provide a useful
// default.
func ClassifyInventory(inv Inventory, rules []ClassifierRule) (string, float64) {
	for _, rule := range rules {
		if rule.matches(inv) {
			conf := rule.Confidence
			if conf <= 0 {
				conf = 0.85
			}
			if conf > 1 {
				conf = 1
			}
			return rule.Role, conf
		}
	}
	blob := inventoryText(inv)
	switch {
	case containsAny(blob, []string{"firewall", "fw-", " fortigate", "palo alto", "asa "}):
		return "firewall", 0.80
	case containsAny(blob, []string{"router", " edge", "core", "wan", "uplink", "bgp"}):
		return "router", 0.74
	case containsAny(blob, []string{"switch", " sw", "access", "gigabitethernet"}) || len(inv.Interfaces) >= 8:
		return "switch", 0.72
	default:
		return "network-device", 0.50
	}
}

// BuildDiscoveryImport turns explicit reviewer choices into regular device
// targets. Non-selected candidates remain inactive.
func BuildDiscoveryImport(result DiscoveryResult, review DiscoveryReview, now func() time.Time) ([]Target, []DiscoveryAuditEvent, error) {
	if now == nil {
		now = time.Now
	}
	if review.TenantID == "" || review.TenantID != result.TenantID {
		return nil, nil, fmt.Errorf("device discovery: review tenant %q does not match result tenant %q", review.TenantID, result.TenantID)
	}
	if review.JobID == "" || review.JobID != result.JobID {
		return nil, nil, fmt.Errorf("device discovery: review job %q does not match result job %q", review.JobID, result.JobID)
	}
	if len(review.AcceptDeviceIDs) == 0 {
		return nil, nil, errors.New("device discovery: review must accept at least one device")
	}
	byID := map[string]DiscoveredDevice{}
	for _, d := range result.Devices {
		if d.TenantID == result.TenantID {
			byID[d.ID] = d
		}
	}
	targets := make([]Target, 0, len(review.AcceptDeviceIDs))
	events := make([]DiscoveryAuditEvent, 0, len(review.AcceptDeviceIDs))
	for _, id := range review.AcceptDeviceIDs {
		d, ok := byID[id]
		if !ok {
			return nil, nil, fmt.Errorf("device discovery: accepted device %q is not in tenant %q result", id, review.TenantID)
		}
		targets = append(targets, Target{
			Address:    d.Address,
			Port:       d.Port,
			Transport:  d.Transport,
			Credential: d.Credential,
		})
		events = append(events, DiscoveryAuditEvent{
			TenantID: review.TenantID,
			JobID:    review.JobID,
			Action:   AuditDiscoveryDeviceApproved,
			Subject:  id,
			Actor:    review.ReviewedBy,
			At:       now(),
			Metadata: map[string]string{"address": d.Address, "role": d.Role},
		})
	}
	return targets, events, nil
}

// MemoryDiscoveryStore is a small tenant-filtered result store for tests and
// lightweight installs that need review handoff without a database.
type MemoryDiscoveryStore struct {
	mu       sync.RWMutex
	byTenant map[string]map[string]DiscoveryResult
}

// NewMemoryDiscoveryStore builds an empty tenant-filtered store.
func NewMemoryDiscoveryStore() *MemoryDiscoveryStore {
	return &MemoryDiscoveryStore{byTenant: map[string]map[string]DiscoveryResult{}}
}

// SaveDiscoveryResult stores one result under its tenant and job IDs.
func (s *MemoryDiscoveryStore) SaveDiscoveryResult(result DiscoveryResult) error {
	if result.TenantID == "" {
		return ErrDiscoveryTenantRequired
	}
	if result.JobID == "" {
		return errors.New("device discovery: job_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[result.TenantID] == nil {
		s.byTenant[result.TenantID] = map[string]DiscoveryResult{}
	}
	s.byTenant[result.TenantID][result.JobID] = cloneDiscoveryResult(result)
	return nil
}

// ListDiscoveryResults returns only the caller tenant's results.
func (s *MemoryDiscoveryStore) ListDiscoveryResults(tenantID string) []DiscoveryResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := s.byTenant[tenantID]
	out := make([]DiscoveryResult, 0, len(rows))
	for _, r := range rows {
		out = append(out, cloneDiscoveryResult(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JobID < out[j].JobID })
	return out
}

// GetDiscoveryResult returns one result within the caller tenant.
func (s *MemoryDiscoveryStore) GetDiscoveryResult(tenantID, jobID string) (DiscoveryResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byTenant[tenantID][jobID]
	if !ok {
		return DiscoveryResult{}, false
	}
	return cloneDiscoveryResult(r), true
}

// LoadDiscoveryFixture decodes a JSON fixture for offline discovery runs.
func LoadDiscoveryFixture(r io.Reader) (FixtureDiscoveryProber, error) {
	var file discoveryFixtureFile
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	out := FixtureDiscoveryProber{}
	for i, d := range file.Devices {
		if d.Address == "" {
			return nil, fmt.Errorf("device discovery fixture: devices[%d] address is required", i)
		}
		inv := Inventory{Device: d.Address, SysName: d.SysName, SysDescr: d.SysDescr, Interfaces: map[uint32]Interface{}}
		for _, iface := range d.Interfaces {
			addrs := make([]netip.Addr, 0, len(iface.Addrs))
			for _, raw := range iface.Addrs {
				addr, err := netip.ParseAddr(raw)
				if err != nil {
					return nil, fmt.Errorf("device discovery fixture: %s interface %d bad address %q: %w", d.Address, iface.Index, raw, err)
				}
				addrs = append(addrs, addr)
			}
			inv.Interfaces[iface.Index] = Interface{
				Index:     iface.Index,
				Name:      iface.Name,
				Descr:     iface.Descr,
				SpeedMbps: iface.SpeedMbps,
				OperUp:    iface.OperUp,
				Addrs:     addrs,
			}
		}
		out[d.Address] = inv
	}
	return out, nil
}

type discoveryFixtureFile struct {
	Devices []discoveryFixtureDevice `json:"devices"`
}

type discoveryFixtureDevice struct {
	Address    string                      `json:"address"`
	SysName    string                      `json:"sys_name,omitempty"`
	SysDescr   string                      `json:"sys_descr,omitempty"`
	Interfaces []discoveryFixtureInterface `json:"interfaces,omitempty"`
}

type discoveryFixtureInterface struct {
	Index     uint32   `json:"index"`
	Name      string   `json:"name,omitempty"`
	Descr     string   `json:"descr,omitempty"`
	SpeedMbps uint64   `json:"speed_mbps,omitempty"`
	OperUp    bool     `json:"oper_up"`
	Addrs     []string `json:"addrs,omitempty"`
}

func (r ClassifierRule) matches(inv Inventory) bool {
	if r.Role == "" {
		return false
	}
	criteria := 0
	if len(r.SysNameContains) > 0 {
		criteria++
		if !containsAny(strings.ToLower(inv.SysName), lowerAll(r.SysNameContains)) {
			return false
		}
	}
	if len(r.SysDescrContains) > 0 {
		criteria++
		if !containsAny(strings.ToLower(inv.SysDescr), lowerAll(r.SysDescrContains)) {
			return false
		}
	}
	if len(r.IfNameContains) > 0 {
		criteria++
		if !containsAny(interfaceText(inv), lowerAll(r.IfNameContains)) {
			return false
		}
	}
	if r.MinInterfaces > 0 {
		criteria++
		if len(inv.Interfaces) < r.MinInterfaces {
			return false
		}
	}
	return criteria > 0
}

func discoveredDevice(job DiscoveryJob, inv Inventory, ref DiscoveryCredential, role string, confidence float64) DiscoveredDevice {
	interfaces := make([]DiscoveredInterface, 0, len(inv.Interfaces))
	for _, iface := range inv.Interfaces {
		addrs := make([]string, 0, len(iface.Addrs))
		for _, addr := range iface.Addrs {
			addrs = append(addrs, addr.String())
		}
		sort.Strings(addrs)
		interfaces = append(interfaces, DiscoveredInterface{
			Index:     iface.Index,
			Name:      iface.Name,
			Descr:     iface.Descr,
			SpeedMbps: iface.SpeedMbps,
			OperUp:    iface.OperUp,
			Addrs:     addrs,
		})
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	return DiscoveredDevice{
		ID:              discoveryDeviceID(job.ID, inv.Device),
		TenantID:        job.TenantID,
		Address:         inv.Device,
		SysName:         inv.SysName,
		SysDescr:        inv.SysDescr,
		Role:            role,
		Confidence:      confidence,
		Credential:      ref.Name,
		Transport:       ref.Transport,
		Port:            ref.Port,
		ActivationState: ActivationPendingReview,
		Interfaces:      interfaces,
	}
}

func discoveryDeviceID(jobID, addr string) string {
	return jobID + ":" + strings.NewReplacer(".", "-", ":", "-").Replace(addr)
}

func safeDiscoveryTargets(job DiscoveryJob) ([]netip.Addr, error) {
	maxHosts := job.MaxHosts
	if maxHosts <= 0 {
		maxHosts = DefaultDiscoveryMaxHosts
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, raw := range job.Ranges {
		prefix, err := parseDiscoveryRange(raw)
		if err != nil {
			return nil, err
		}
		count := discoveryHostCount(prefix)
		if count == 0 || count > uint64(maxHosts) {
			return nil, fmt.Errorf("%w %q expands to %d hosts (max %d)", ErrUnsafeDiscoveryRange, raw, count, maxHosts)
		}
		if uint64(len(out))+count > uint64(maxHosts) {
			return nil, fmt.Errorf("%w: total discovery targets exceed max_hosts %d", ErrUnsafeDiscoveryRange, maxHosts)
		}
		addrs := expandDiscoveryPrefix(prefix)
		for _, addr := range addrs {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

func parseDiscoveryRange(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, errors.New("device discovery: empty range")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return safeDiscoveryPrefix(netip.PrefixFrom(addr, addr.BitLen()), raw)
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("device discovery: parse range %q: %w", raw, err)
	}
	return safeDiscoveryPrefix(prefix.Masked(), raw)
}

func safeDiscoveryPrefix(prefix netip.Prefix, raw string) (netip.Prefix, error) {
	addr := prefix.Addr()
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("%w %q: only IPv4 discovery is supported", ErrUnsafeDiscoveryRange, raw)
	}
	if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
		return netip.Prefix{}, fmt.Errorf("%w %q: range must be private, loopback, or link-local", ErrUnsafeDiscoveryRange, raw)
	}
	return prefix, nil
}

func discoveryHostCount(prefix netip.Prefix) uint64 {
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return 0
	}
	total := uint64(1) << uint(32-bits)
	if bits <= 30 && total > 2 {
		return total - 2
	}
	return total
}

func expandDiscoveryPrefix(prefix netip.Prefix) []netip.Addr {
	total := uint64(1) << uint(32-prefix.Bits())
	start := addrToUint32(prefix.Addr())
	out := make([]netip.Addr, 0, discoveryHostCount(prefix))
	for i := uint64(0); i < total; i++ {
		if prefix.Bits() <= 30 && (i == 0 || i == total-1) {
			continue
		}
		out = append(out, uint32ToAddr(start+uint32(i)))
	}
	return out
}

func addrToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func inventoryText(inv Inventory) string {
	return strings.Join([]string{strings.ToLower(inv.SysName), strings.ToLower(inv.SysDescr), interfaceText(inv)}, " ")
}

func interfaceText(inv Inventory) string {
	parts := make([]string, 0, len(inv.Interfaces)*2)
	for _, iface := range inv.Interfaces {
		parts = append(parts, strings.ToLower(iface.Name), strings.ToLower(iface.Descr))
	}
	return strings.Join(parts, " ")
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func containsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func cloneInventory(inv Inventory) Inventory {
	out := Inventory{Device: inv.Device, SysName: inv.SysName, SysDescr: inv.SysDescr, Interfaces: map[uint32]Interface{}}
	for idx, iface := range inv.Interfaces {
		iface.Addrs = append([]netip.Addr(nil), iface.Addrs...)
		out.Interfaces[idx] = iface
	}
	return out
}

func cloneDiscoveryResult(in DiscoveryResult) DiscoveryResult {
	out := in
	out.Devices = append([]DiscoveredDevice(nil), in.Devices...)
	for i := range out.Devices {
		out.Devices[i].Interfaces = append([]DiscoveredInterface(nil), in.Devices[i].Interfaces...)
		for j := range out.Devices[i].Interfaces {
			out.Devices[i].Interfaces[j].Addrs = append([]string(nil), in.Devices[i].Interfaces[j].Addrs...)
		}
	}
	out.AuditEvents = append([]DiscoveryAuditEvent(nil), in.AuditEvents...)
	for i := range out.AuditEvents {
		if in.AuditEvents[i].Metadata != nil {
			out.AuditEvents[i].Metadata = map[string]string{}
			for k, v := range in.AuditEvents[i].Metadata {
				out.AuditEvents[i].Metadata[k] = v
			}
		}
	}
	return out
}
