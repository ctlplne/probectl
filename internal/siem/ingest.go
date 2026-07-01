// SPDX-License-Identifier: LicenseRef-probectl-TBD

package siem

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const (
	SourceSyslog                   = "syslog"
	DefaultMaxSyslogLineBytes      = 64 * 1024
	defaultMaxSyslogRowsTenant     = 1000
	defaultSyslogRateLimitWindow   = time.Minute
	defaultSyslogReadBufferInitial = 4096
)

var (
	ErrSyslogUnauthenticated = errors.New("siem syslog ingest: unauthenticated source")
	ErrSyslogRateLimited     = errors.New("siem syslog ingest: rate limited")
	ErrSyslogParse           = errors.New("siem syslog ingest: parse")
)

// SyslogSource is one authenticated sender allowed to emit syslog records for a
// receiver's tenant. Tenant identity is stamped from this config, never from the
// syslog payload.
type SyslogSource struct {
	Name             string
	Address          string
	HMACSecret       string
	TLSClientSubject string
	RateLimit        int
	RateLimitWindow  time.Duration
}

// SyslogReceiverConfig configures one tenant-bound inbound syslog receiver.
type SyslogReceiverConfig struct {
	TenantID     string
	Sources      []SyslogSource
	MaxLineBytes int
	Now          func() time.Time
}

// SyslogEnvelope is one untrusted syslog delivery. Tests and non-network
// adapters use it directly; the TLS listener builds it from each received line.
type SyslogEnvelope struct {
	Line             []byte
	SourceAddress    string
	Signature        string
	TLSClientSubject string
	ReceivedAt       time.Time
}

// SyslogEvent is the tenant-owned normalized row produced by accepted syslog.
type SyslogEvent struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Source          string            `json:"source"`
	SourceName      string            `json:"source_name"`
	SourceAddress   string            `json:"source_address"`
	AuthPrincipal   string            `json:"auth_principal"`
	AuthMethod      string            `json:"auth_method"`
	Format          string            `json:"format"`
	Facility        int               `json:"facility"`
	Severity        int               `json:"severity"`
	Timestamp       time.Time         `json:"timestamp"`
	ReceivedAt      time.Time         `json:"received_at"`
	Hostname        string            `json:"hostname"`
	AppName         string            `json:"app_name"`
	ProcID          string            `json:"proc_id"`
	MsgID           string            `json:"msg_id"`
	StructuredData  string            `json:"structured_data,omitempty"`
	Message         string            `json:"message"`
	Fingerprint     string            `json:"fingerprint"`
	Provenance      map[string]string `json:"provenance,omitempty"`
	OriginalLength  int               `json:"original_length"`
	ParserHardening []string          `json:"parser_hardening,omitempty"`
}

// SyslogStore persists normalized syslog events.
type SyslogStore interface {
	RecordSyslog(ctx context.Context, event SyslogEvent) (SyslogEvent, error)
}

// SyslogReceiver authenticates, rate-limits, parses, and records inbound syslog
// for one tenant. A receiver never trusts tenant data in the syslog body.
type SyslogReceiver struct {
	cfg     SyslogReceiverConfig
	store   SyslogStore
	sources []SyslogSource

	mu   sync.Mutex
	hits map[string][]time.Time
}

// NewSyslogReceiver validates cfg and builds a tenant-bound receiver.
func NewSyslogReceiver(cfg SyslogReceiverConfig, store SyslogStore) (*SyslogReceiver, error) {
	if cfg.TenantID == "" {
		return nil, errors.New("siem syslog ingest: tenant_id is required")
	}
	if store == nil {
		return nil, errors.New("siem syslog ingest: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = DefaultMaxSyslogLineBytes
	}
	sources := append([]SyslogSource(nil), cfg.Sources...)
	if len(sources) == 0 {
		return nil, errors.New("siem syslog ingest: at least one authenticated source is required")
	}
	for i := range sources {
		if sources[i].Name == "" {
			return nil, errors.New("siem syslog ingest: source name is required")
		}
		if sources[i].HMACSecret == "" && sources[i].TLSClientSubject == "" {
			return nil, fmt.Errorf("siem syslog ingest: source %q requires hmac_secret or tls_client_subject", sources[i].Name)
		}
	}
	return &SyslogReceiver{cfg: cfg, store: store, sources: sources, hits: map[string][]time.Time{}}, nil
}

// SyslogSignature returns the canonical HMAC-SHA256 signature header value for
// a syslog body. It routes through internal/crypto so FIPS swaps stay contained.
func SyslogSignature(secret string, line []byte) string {
	return "sha256=" + hex.EncodeToString(crypto.Sign([]byte(secret), line))
}

// Record authenticates and records one syslog envelope.
func (r *SyslogReceiver) Record(ctx context.Context, env SyslogEnvelope) (SyslogEvent, error) {
	if len(env.Line) == 0 {
		return SyslogEvent{}, fmt.Errorf("%w: empty line", ErrSyslogParse)
	}
	if len(env.Line) > r.cfg.MaxLineBytes {
		return SyslogEvent{}, fmt.Errorf("%w: line exceeds %d bytes", ErrSyslogParse, r.cfg.MaxLineBytes)
	}
	receivedAt := env.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = r.cfg.Now().UTC()
	} else {
		receivedAt = receivedAt.UTC()
	}
	source, authMethod, err := r.authenticate(env)
	if err != nil {
		return SyslogEvent{}, err
	}
	if err := r.allow(source, receivedAt); err != nil {
		return SyslogEvent{}, err
	}
	parsed, err := parseSyslog(env.Line, receivedAt)
	if err != nil {
		return SyslogEvent{}, err
	}
	event := SyslogEvent{
		TenantID:        r.cfg.TenantID,
		Source:          SourceSyslog,
		SourceName:      source.Name,
		SourceAddress:   hostOnly(env.SourceAddress),
		AuthPrincipal:   source.Name,
		AuthMethod:      authMethod,
		Format:          parsed.format,
		Facility:        parsed.facility,
		Severity:        parsed.severity,
		Timestamp:       parsed.timestamp.UTC(),
		ReceivedAt:      receivedAt,
		Hostname:        parsed.hostname,
		AppName:         parsed.appName,
		ProcID:          parsed.procID,
		MsgID:           parsed.msgID,
		StructuredData:  parsed.structuredData,
		Message:         parsed.message,
		OriginalLength:  len(env.Line),
		ParserHardening: []string{"max_line_bytes", "pri_bounds", "nul_reject"},
		Provenance: map[string]string{
			"source.name":    source.Name,
			"source.address": hostOnly(env.SourceAddress),
			"auth.method":    authMethod,
			"format":         parsed.format,
		},
	}
	if env.TLSClientSubject != "" {
		event.Provenance["tls.client_subject"] = env.TLSClientSubject
		event.AuthPrincipal = env.TLSClientSubject
	}
	event.Fingerprint = syslogFingerprint(event)
	return r.store.RecordSyslog(ctx, event)
}

// ListenTLS serves newline-delimited syslog over a TLS listener until ctx is
// canceled. A nil TLS config fails closed: inbound listeners must be TLS-only.
func (r *SyslogReceiver) ListenTLS(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	if addr == "" {
		return errors.New("siem syslog ingest: listen address is required")
	}
	if tlsCfg == nil {
		return errors.New("siem syslog ingest: TLS config required")
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("siem syslog ingest: listen %q: %w", addr, err)
	}
	defer ln.Close()
	return r.serve(ctx, ln)
}

func (r *SyslogReceiver) serve(ctx context.Context, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			go r.handleConn(ctx, conn)
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

func (r *SyslogReceiver) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	subject := tlsClientSubject(conn)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, defaultSyslogReadBufferInitial), r.cfg.MaxLineBytes)
	for scanner.Scan() {
		_, _ = r.Record(ctx, SyslogEnvelope{
			Line:             append([]byte(nil), scanner.Bytes()...),
			SourceAddress:    conn.RemoteAddr().String(),
			TLSClientSubject: subject,
			ReceivedAt:       r.cfg.Now().UTC(),
		})
	}
}

func tlsClientSubject(conn net.Conn) string {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return ""
	}
	if err := tlsConn.Handshake(); err != nil {
		return ""
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.String()
}

func (r *SyslogReceiver) authenticate(env SyslogEnvelope) (SyslogSource, string, error) {
	for _, source := range r.sources {
		if !syslogAddressMatches(source.Address, env.SourceAddress) {
			continue
		}
		if source.HMACSecret != "" && verifySyslogSignature(source.HMACSecret, env.Line, env.Signature) {
			return source, "hmac-sha256", nil
		}
		if source.TLSClientSubject != "" && source.TLSClientSubject == env.TLSClientSubject {
			return source, "tls-client-cert", nil
		}
	}
	return SyslogSource{}, "", ErrSyslogUnauthenticated
}

func verifySyslogSignature(secret string, line []byte, sigHeader string) bool {
	if secret == "" || sigHeader == "" {
		return false
	}
	mac, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(sigHeader), "sha256="))
	if err != nil || len(mac) == 0 {
		return false
	}
	return crypto.Verify([]byte(secret), line, mac)
}

func (r *SyslogReceiver) allow(source SyslogSource, now time.Time) error {
	if source.RateLimit <= 0 {
		return nil
	}
	window := source.RateLimitWindow
	if window <= 0 {
		window = defaultSyslogRateLimitWindow
	}
	cutoff := now.Add(-window)
	r.mu.Lock()
	defer r.mu.Unlock()
	hits := r.hits[source.Name]
	kept := hits[:0]
	for _, hit := range hits {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= source.RateLimit {
		r.hits[source.Name] = kept
		return ErrSyslogRateLimited
	}
	kept = append(kept, now)
	r.hits[source.Name] = kept
	return nil
}

type parsedSyslog struct {
	format         string
	facility       int
	severity       int
	timestamp      time.Time
	hostname       string
	appName        string
	procID         string
	msgID          string
	structuredData string
	message        string
}

func parseSyslog(line []byte, receivedAt time.Time) (parsedSyslog, error) {
	body := strings.TrimRight(string(line), "\r\n")
	if body == "" {
		return parsedSyslog{}, fmt.Errorf("%w: empty line", ErrSyslogParse)
	}
	if strings.ContainsRune(body, '\x00') {
		return parsedSyslog{}, fmt.Errorf("%w: nul byte", ErrSyslogParse)
	}
	pri, rest, err := parseSyslogPRI(body)
	if err != nil {
		return parsedSyslog{}, err
	}
	out := parsedSyslog{facility: pri / 8, severity: pri % 8}
	if strings.HasPrefix(rest, "1 ") {
		return parseRFC5424(out, rest, receivedAt)
	}
	return parseRFC3164(out, rest, receivedAt)
}

func parseSyslogPRI(body string) (int, string, error) {
	if !strings.HasPrefix(body, "<") {
		return 0, "", fmt.Errorf("%w: missing pri", ErrSyslogParse)
	}
	end := strings.IndexByte(body, '>')
	if end < 2 || end > 4 {
		return 0, "", fmt.Errorf("%w: malformed pri", ErrSyslogParse)
	}
	pri, err := strconv.Atoi(body[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return 0, "", fmt.Errorf("%w: pri out of range", ErrSyslogParse)
	}
	if end+1 >= len(body) {
		return 0, "", fmt.Errorf("%w: missing syslog body", ErrSyslogParse)
	}
	return pri, body[end+1:], nil
}

func parseRFC5424(out parsedSyslog, rest string, receivedAt time.Time) (parsedSyslog, error) {
	fields, rem, ok := takeFields(rest, 6)
	if !ok || fields[0] != "1" {
		return parsedSyslog{}, fmt.Errorf("%w: malformed rfc5424 header", ErrSyslogParse)
	}
	ts, err := parseRFC5424Time(fields[1], receivedAt)
	if err != nil {
		return parsedSyslog{}, err
	}
	sd, msg, err := parseStructuredData(rem)
	if err != nil {
		return parsedSyslog{}, err
	}
	out.format = "rfc5424"
	out.timestamp = ts
	out.hostname = nilValue(fields[2])
	out.appName = nilValue(fields[3])
	out.procID = nilValue(fields[4])
	out.msgID = nilValue(fields[5])
	out.structuredData = nilValue(sd)
	out.message = msg
	return out, nil
}

func parseRFC5424Time(s string, receivedAt time.Time) (time.Time, error) {
	if s == "-" {
		return receivedAt, nil
	}
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid rfc5424 timestamp", ErrSyslogParse)
	}
	return ts, nil
}

func parseStructuredData(s string) (string, string, error) {
	if s == "" {
		return "", "", fmt.Errorf("%w: missing structured data", ErrSyslogParse)
	}
	if s[0] == '-' {
		return "-", strings.TrimPrefix(s[1:], " "), nil
	}
	if s[0] != '[' {
		return "", "", fmt.Errorf("%w: malformed structured data", ErrSyslogParse)
	}
	i := 0
	escaped := false
	for i < len(s) {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == ']':
			i++
			if i == len(s) || s[i] == ' ' {
				return s[:i], strings.TrimPrefix(s[i:], " "), nil
			}
			if s[i] != '[' {
				return "", "", fmt.Errorf("%w: malformed structured data suffix", ErrSyslogParse)
			}
			continue
		}
		i++
	}
	return "", "", fmt.Errorf("%w: unterminated structured data", ErrSyslogParse)
}

func parseRFC3164(out parsedSyslog, rest string, receivedAt time.Time) (parsedSyslog, error) {
	if len(rest) < len("Jan  2 15:04:05 ") {
		return parsedSyslog{}, fmt.Errorf("%w: short rfc3164 header", ErrSyslogParse)
	}
	stamp := rest[:15]
	ts, err := time.ParseInLocation("Jan _2 15:04:05", stamp, time.UTC)
	if err != nil {
		return parsedSyslog{}, fmt.Errorf("%w: invalid rfc3164 timestamp", ErrSyslogParse)
	}
	ts = time.Date(receivedAt.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, time.UTC)
	rem := strings.TrimSpace(rest[15:])
	host, rem, ok := cutField(rem)
	if !ok || host == "" {
		return parsedSyslog{}, fmt.Errorf("%w: missing rfc3164 host", ErrSyslogParse)
	}
	app, proc, msg := parseRFC3164Message(rem)
	out.format = "rfc3164"
	out.timestamp = ts
	out.hostname = host
	out.appName = app
	out.procID = proc
	out.message = msg
	return out, nil
}

func parseRFC3164Message(s string) (app, proc, msg string) {
	prefix, body, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", strings.TrimSpace(s)
	}
	app = strings.TrimSpace(prefix)
	msg = strings.TrimSpace(body)
	if start := strings.LastIndexByte(app, '['); start >= 0 && strings.HasSuffix(app, "]") {
		proc = app[start+1 : len(app)-1]
		app = app[:start]
	}
	return app, proc, msg
}

func takeFields(s string, n int) ([]string, string, bool) {
	fields := make([]string, 0, n)
	rem := s
	for len(fields) < n {
		f, rest, ok := cutField(rem)
		if !ok {
			return nil, "", false
		}
		fields = append(fields, f)
		rem = rest
	}
	return fields, rem, true
}

func cutField(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", true
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func syslogAddressMatches(want string, got string) bool {
	if want == "" {
		return true
	}
	return hostOnly(want) == hostOnly(got)
}

func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func syslogFingerprint(e SyslogEvent) string {
	h := fnv.New64a()
	writeHash := func(s string) { _, _ = h.Write([]byte(s)); _, _ = h.Write([]byte{0}) }
	writeHash(e.TenantID)
	writeHash(e.SourceName)
	writeHash(e.SourceAddress)
	writeHash(e.Format)
	writeHash(e.Timestamp.Format(time.RFC3339Nano))
	writeHash(e.Hostname)
	writeHash(e.AppName)
	writeHash(e.ProcID)
	writeHash(e.MsgID)
	writeHash(e.Message)
	return fmt.Sprintf("%016x", h.Sum64())
}

// MemorySyslogStore keeps accepted syslog rows partitioned by tenant.
type MemorySyslogStore struct {
	mu     sync.Mutex
	max    int
	seq    uint64
	events map[string][]SyslogEvent
}

// NewMemorySyslogStore returns a bounded tenant-partitioned syslog store.
func NewMemorySyslogStore(maxPerTenant int) *MemorySyslogStore {
	if maxPerTenant <= 0 {
		maxPerTenant = defaultMaxSyslogRowsTenant
	}
	return &MemorySyslogStore{max: maxPerTenant, events: map[string][]SyslogEvent{}}
}

// RecordSyslog stores a syslog row inside its tenant partition.
func (s *MemorySyslogStore) RecordSyslog(_ context.Context, event SyslogEvent) (SyslogEvent, error) {
	if event.TenantID == "" {
		return SyslogEvent{}, errors.New("siem syslog ingest: tenant_id is required")
	}
	if event.Fingerprint == "" {
		return SyslogEvent{}, errors.New("siem syslog ingest: fingerprint is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	event.ID = fmt.Sprintf("syslog-%d", s.seq)
	s.events[event.TenantID] = append([]SyslogEvent{event}, s.events[event.TenantID]...)
	if len(s.events[event.TenantID]) > s.max {
		s.events[event.TenantID] = s.events[event.TenantID][:s.max]
	}
	return event, nil
}

// ListSyslogEvents returns a copy of one tenant's syslog event partition.
func (s *MemorySyslogStore) ListSyslogEvents(tenantID string) []SyslogEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]SyslogEvent(nil), s.events[tenantID]...)
	for i := range out {
		out[i].Provenance = copyStringMap(out[i].Provenance)
		out[i].ParserHardening = append([]string(nil), out[i].ParserHardening...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ReceivedAt.After(out[j].ReceivedAt) })
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
