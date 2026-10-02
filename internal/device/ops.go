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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const defaultOpsLimit = 100

// SyslogEvent is one authenticated, tenant-scoped device syslog line.
type SyslogEvent struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	Device        string            `json:"device"`
	SourceAddress string            `json:"source_address,omitempty"`
	Facility      int               `json:"facility,omitempty"`
	Severity      int               `json:"severity"`
	SeverityText  string            `json:"severity_text"`
	Hostname      string            `json:"hostname,omitempty"`
	AppName       string            `json:"app_name,omitempty"`
	Message       string            `json:"message"`
	Raw           string            `json:"raw,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	ObservedAt    time.Time         `json:"observed_at"`
}

// ConfigVersion is a redacted, tenant-scoped network-device config snapshot.
type ConfigVersion struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Device       string    `json:"device"`
	Source       string    `json:"source,omitempty"`
	Version      int       `json:"version"`
	Content      string    `json:"content,omitempty"`
	ContentHash  string    `json:"content_hash"`
	PreviousHash string    `json:"previous_hash,omitempty"`
	Drifted      bool      `json:"drifted"`
	ObservedAt   time.Time `json:"observed_at"`
	ArchivedAt   time.Time `json:"archived_at"`
}

// OpsStore stores device-management table-stakes rows behind a tenant-first API.
type OpsStore interface {
	RecordSyslog(context.Context, SyslogEvent) (SyslogEvent, error)
	ListSyslog(context.Context, string, OpsFilter) ([]SyslogEvent, error)
	ArchiveConfig(context.Context, ConfigVersion) (ConfigVersion, error)
	ListConfigs(context.Context, string, OpsFilter) ([]ConfigVersion, error)
}

// OpsFilter bounds tenant-scoped reads.
type OpsFilter struct {
	Device string
	Limit  int
}

// MemoryOpsStore is a tenant-keyed store for lightweight deployments and tests.
type MemoryOpsStore struct {
	mu      sync.RWMutex
	syslog  map[string][]SyslogEvent
	configs map[string][]ConfigVersion
	next    uint64
	now     func() time.Time
}

func NewMemoryOpsStore() *MemoryOpsStore {
	return &MemoryOpsStore{
		syslog:  map[string][]SyslogEvent{},
		configs: map[string][]ConfigVersion{},
		now:     time.Now,
	}
}

func (m *MemoryOpsStore) RecordSyslog(_ context.Context, ev SyslogEvent) (SyslogEvent, error) {
	if ev.TenantID == "" {
		return SyslogEvent{}, errors.New("device ops: tenant_id is required")
	}
	if strings.TrimSpace(ev.Device) == "" {
		return SyslogEvent{}, errors.New("device ops: device is required")
	}
	if strings.TrimSpace(ev.Message) == "" {
		return SyslogEvent{}, errors.New("device ops: message is required")
	}
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = m.now()
	}
	ev.ObservedAt = ev.ObservedAt.UTC()
	if ev.SeverityText == "" {
		ev.SeverityText = SyslogSeverityText(ev.Severity)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	ev.ID = fmt.Sprintf("syslog-%d", m.next)
	m.syslog[ev.TenantID] = append(m.syslog[ev.TenantID], ev)
	return ev, nil
}

func (m *MemoryOpsStore) ListSyslog(_ context.Context, tenant string, f OpsFilter) ([]SyslogEvent, error) {
	if tenant == "" {
		return nil, errors.New("device ops: tenant_id is required")
	}
	limit := normalizeOpsLimit(f.Limit)
	m.mu.RLock()
	rows := append([]SyslogEvent(nil), m.syslog[tenant]...)
	m.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ObservedAt.After(rows[j].ObservedAt) })
	out := make([]SyslogEvent, 0, min(limit, len(rows)))
	for _, row := range rows {
		if f.Device != "" && row.Device != f.Device {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryOpsStore) ArchiveConfig(_ context.Context, cfg ConfigVersion) (ConfigVersion, error) {
	if cfg.TenantID == "" {
		return ConfigVersion{}, errors.New("device ops: tenant_id is required")
	}
	if strings.TrimSpace(cfg.Device) == "" {
		return ConfigVersion{}, errors.New("device ops: device is required")
	}
	cfg.Device = strings.TrimSpace(cfg.Device)
	cfg.Content = RedactConfig(cfg.Content)
	cfg.ContentHash = hashConfig(cfg.Content)
	if cfg.ObservedAt.IsZero() {
		cfg.ObservedAt = m.now()
	}
	cfg.ObservedAt = cfg.ObservedAt.UTC()
	cfg.ArchivedAt = m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	var previous *ConfigVersion
	for i := len(m.configs[cfg.TenantID]) - 1; i >= 0; i-- {
		row := m.configs[cfg.TenantID][i]
		if row.Device == cfg.Device {
			previous = &row
			break
		}
	}
	if previous != nil {
		cfg.PreviousHash = previous.ContentHash
		cfg.Version = previous.Version + 1
		cfg.Drifted = previous.ContentHash != cfg.ContentHash
	} else {
		cfg.Version = 1
	}
	m.next++
	cfg.ID = fmt.Sprintf("config-%d", m.next)
	m.configs[cfg.TenantID] = append(m.configs[cfg.TenantID], cfg)
	return cfg, nil
}

func (m *MemoryOpsStore) ListConfigs(_ context.Context, tenant string, f OpsFilter) ([]ConfigVersion, error) {
	if tenant == "" {
		return nil, errors.New("device ops: tenant_id is required")
	}
	limit := normalizeOpsLimit(f.Limit)
	m.mu.RLock()
	rows := append([]ConfigVersion(nil), m.configs[tenant]...)
	m.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ArchivedAt.After(rows[j].ArchivedAt) })
	out := make([]ConfigVersion, 0, min(limit, len(rows)))
	for _, row := range rows {
		if f.Device != "" && row.Device != f.Device {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// ParseSyslogLine normalizes common RFC3164/RFC5424-ish syslog lines. It is
// intentionally conservative: authentication and tenant binding happen outside
// the parser, and unparsable prefixes still preserve the message body.
func ParseSyslogLine(raw, fallbackDevice string, observedAt time.Time) SyslogEvent {
	msg := strings.TrimSpace(raw)
	ev := SyslogEvent{Raw: msg, Message: msg, Device: strings.TrimSpace(fallbackDevice), ObservedAt: observedAt.UTC()}
	if pri, rest, ok := parsePriority(msg); ok {
		ev.Facility = pri / 8
		ev.Severity = pri % 8
		ev.SeverityText = SyslogSeverityText(ev.Severity)
		msg = strings.TrimSpace(rest)
		ev.Message = msg
	}
	fields := strings.Fields(msg)
	if len(fields) >= 4 && looksRFC3164Timestamp(fields[:3]) {
		ev.Hostname = fields[3]
		ev.Message = strings.TrimSpace(strings.TrimPrefix(msg, strings.Join(fields[:4], " ")))
	} else if len(fields) >= 3 && strings.Contains(fields[0], "T") {
		ev.Hostname = fields[1]
		ev.AppName = strings.TrimSuffix(fields[2], ":")
		ev.Message = strings.TrimSpace(strings.TrimPrefix(msg, strings.Join(fields[:3], " ")))
	}
	if ev.Device == "" {
		ev.Device = ev.Hostname
	}
	if ev.Device == "" {
		ev.Device = "unknown"
	}
	if ev.SeverityText == "" {
		ev.SeverityText = SyslogSeverityText(ev.Severity)
	}
	return ev
}

func parsePriority(s string) (int, string, bool) {
	if !strings.HasPrefix(s, "<") {
		return 0, s, false
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 5 {
		return 0, s, false
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return 0, s, false
	}
	return pri, s[end+1:], true
}

func looksRFC3164Timestamp(fields []string) bool {
	if len(fields) != 3 {
		return false
	}
	if len(fields[0]) != 3 || !strings.Contains(fields[2], ":") {
		return false
	}
	_, err := strconv.Atoi(fields[1])
	return err == nil
}

func SyslogSeverityText(sev int) string {
	switch sev {
	case 0:
		return "emergency"
	case 1:
		return "alert"
	case 2:
		return "critical"
	case 3:
		return "error"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "info"
	default:
		return "debug"
	}
}

// cfgMod is the set of non-secret modifier tokens that can sit between a secret
// directive and the actual value: key/type numbers, hash/cipher algorithms,
// key sizes, encoding and scope keywords. A directive rule consumes a run of
// these first, so the greedy value capture lands on the SECRET, not on an
// intervening keyword like md5 / local / ascii (WEB-03 reopen).
const cfgMod = `(?:\d+|md5|sha(?:\d+)?|hmac(?:-[a-z0-9-]+)?|aes|des|3des|rc4|128|192|256|ascii|ascii-text|cleartext|clear|encrypted|hexadecimal|hex|local|remote)`

// cfgVal captures a secret value: a quoted string or a bare token.
const cfgVal = `(?:"[^"\n]*"|\S+)`

// configRedactRules redact the VALUE (not the whole line) after each vendor
// secret directive, keeping the directive and any non-secret suffix visible
// (WEB-03). A single keyword regex missed TACACS/RADIUS keys, key-chain
// key-strings, routing-protocol auth keys (incl. NTP), IPsec/ISAKMP/IKEv2
// pre-shared keys, Wi-Fi PSKs, SNMPv3 auth/priv passwords, and SNMP trap-host
// communities. Each directive first consumes a run of cfgMod modifier tokens,
// then redacts the value — so an algorithm/scope keyword is never mistaken for
// the secret. Rules cover Cisco IOS/NX-OS, Junos, and Arista EOS; redaction is
// security-first, so a non-secret value occasionally over-masked is acceptable.
// `\S`/cfgVal never cross a newline, so each rule stays within its line.
var configRedactRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// TACACS/RADIUS shared key, including the host form with intervening
	// auth-port/acct-port/timeout/single-connection options before `key`.
	{regexp.MustCompile(`(?i)\b((?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?(?:(?:auth-port|acct-port|timeout|single-connection|retransmit|key-wrap)\s+\S+\s+|\d+\s+)*key\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	// Standalone type-encoded key subcommand — the modern `radius server NAME` /
	// `tacacs server NAME` block (and `key 7 <hash>` generally). `[ \t]` (not \s)
	// keeps it on one line so a key-chain `key 7` key-IDENTIFIER (alone on its
	// line, value on the next `key-string` line) is NOT mistaken for a secret.
	{regexp.MustCompile(`(?i)(\bkey[ \t]+(?:0|5|6|7)[ \t]+)\S+`), `${1}[redacted]`},
	// A hex key after a hash algorithm (OSPFv3/IPsec `authentication ipsec spi N
	// md5|sha1 <hex>`, and similar). 16+ hex digits keeps it off incidental small
	// values; the algorithm name is preserved.
	{regexp.MustCompile(`(?i)\b((?:md5|sha1|sha256|sha384|sha512)[ \t]+)[0-9a-fA-F]{16,}\b`), `${1}[redacted]`},
	// Key-chain key-string.
	{regexp.MustCompile(`(?i)\b(key-string\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	// Routing-protocol auth: (ip ospf / ntp) authentication-key, message-digest-key.
	{regexp.MustCompile(`(?i)\b(authentication-key\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	{regexp.MustCompile(`(?i)\b(message-digest-key\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	// First-hop redundancy (HSRP/VRRP/GLBP) authentication: `standby N
	// authentication [text] [7] <key>` and bare `authentication <key>` (Cisco
	// IOS/IOS-XE, cleartext or reversible type-7 in running-config). The md5
	// key-chain variant names a chain (not a secret; its key-string is redacted
	// by the key-string rule), so at worst the `md5` keyword is over-masked.
	{regexp.MustCompile(`(?i)\b((?:standby|vrrp|glbp)\s+\d+\s+authentication\s+(?:text\s+)?(?:\d+\s+)?)` + cfgVal), `${1}[redacted]`},
	// Cisco DMVPN NHRP authentication: `ip nhrp authentication <key>` — a cleartext
	// tunnel-authentication string carried in the running-config (weak by design,
	// but still a credential). `ip ospf authentication <mode>` is NOT matched here:
	// only `nhrp authentication` triggers, and that form always carries a key.
	{regexp.MustCompile(`(?i)\b(nhrp\s+authentication\s+)` + cfgVal), `${1}[redacted]`},
	// IPsec/ISAKMP: crypto isakmp key VALUE (address|hostname …) — key token only,
	// so the trailing address/hostname structure is preserved.
	{regexp.MustCompile(`(?i)\b(crypto\s+isakmp\s+key\s+)` + cfgVal), `${1}[redacted]`},
	// IKEv1 crypto-keyring form: `pre-shared-key {address <peer> [mask]|hostname
	// <fqdn>} key <PSK>` — the secret is after a SECOND `key` keyword (Cisco IOS/
	// IOS-XE, stored cleartext by default). Redact the value after that key; the
	// `.*?` stays on the line (no (?s)).
	{regexp.MustCompile(`(?i)(\bpre-shared-key\b.*?\bkey\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	// Pre-shared key direct form (incl. IKEv2 local/remote scope, ascii-text/hex).
	{regexp.MustCompile(`(?i)\b(pre-shared-key\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	// SNMPv3 user auth/priv passwords.
	{regexp.MustCompile(`(?i)\b(auth\s+(?:md5|sha(?:-?\d+)?)\s+)` + cfgVal), `${1}[redacted]`},
	{regexp.MustCompile(`(?i)\b(priv\s+(?:aes(?:-(?:128|192|256))?|3des|des)(?:\s+(?:128|192|256))?\s+)` + cfgVal), `${1}[redacted]`},
	// SNMP trap-host community (distinct from `snmp-server community`): the
	// community is the token after the host and any traps/informs/version/vrf
	// modifiers.
	{regexp.MustCompile(`(?i)\b(snmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+|(?:version|vrf|udp-port)\s+\S+\s+)*)` + cfgVal), `${1}[redacted]`},
	// Generic credential directives (incl. wpa-psk / psk, with encoding/type mods).
	{regexp.MustCompile(`(?i)\b((?:wpa-psk|psk|password|passwd|secret|passphrase|community|private-key|api[_-]?key|token)\s+(?:` + cfgMod + `\s+)*)` + cfgVal), `${1}[redacted]`},
	// Junos quoted secret.
	{regexp.MustCompile(`(?i)\b(secret\s+)"[^"\n]*"`), `${1}"[redacted]"`},
	// Cisco `$1$`/`$5$`/`$6$` and Junos `$9$` encoded secrets anywhere on a line.
	{regexp.MustCompile(`\$(?:1|5|6|9\$)[^\s"]+`), `[redacted]`},
}

// RedactConfig masks secret values in a device running-config before it is
// stored or shown (WEB-03). It is applied at archive time, so the at-rest copy
// and every read are redacted.
func RedactConfig(content string) string {
	for _, rule := range configRedactRules {
		content = rule.re.ReplaceAllString(content, rule.repl)
	}
	return content
}

func hashConfig(content string) string {
	return hex.EncodeToString(crypto.Hash([]byte(content)))
}

func normalizeOpsLimit(limit int) int {
	if limit <= 0 {
		return defaultOpsLimit
	}
	if limit > defaultMaxTrapRowsTenant {
		return defaultMaxTrapRowsTenant
	}
	return limit
}
