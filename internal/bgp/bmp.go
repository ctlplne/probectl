// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	probectlc "github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/wire"
)

const (
	bmpVersion            = 3
	bmpCommonHeaderLen    = 6
	bmpPeerHeaderLen      = 42
	bmpRouteMonitoring    = 0
	bmpPeerFlagIPv6       = 0x80
	bmpMaxMessageBytes    = 1 << 20
	bgpHeaderLen          = 19
	bgpMessageTypeUpdate  = 2
	bgpPathAttrASPath     = 2
	bgpPathAttrAS4Path    = 17
	bgpPathAttrExtended   = 0x10
	defaultBMPCollectorID = "bmp"

	// A single embedded UPDATE is capped independently from the outer BMP
	// frame. These fixed safety ceilings are deliberately not configurable:
	// an authenticated but faulty or compromised router must not turn one
	// syntactically valid UPDATE into unbounded parser or publication work.
	maxBMPASPathEntries      = 512
	maxBMPRouteAnnouncements = 4096
	maxBMPRoutePathEntries   = 1 << 18

	// Safe process-wide defaults for the unauthenticated handshake, each
	// authenticated BMP frame read, and concurrent admitted peer sessions.
	DefaultBMPHandshakeTimeout = 10 * time.Second
	DefaultBMPReadTimeout      = 2 * time.Minute
	DefaultBMPMaxSessions      = 256
	// DefaultBMPIdleTimeout is 0: an authenticated router session may stay
	// quiet indefinitely (BGP tables are quiet most of the time); TCP
	// keepalive detects a dead peer. The read timeout bounds a frame in
	// progress only (DPR-060).
	DefaultBMPIdleTimeout = time.Duration(0)
	// DefaultBMPEventSuppression republishes an unchanged route from the same
	// peer at most once per window: a reconnecting router re-dumps its whole
	// table (DPR-060).
	DefaultBMPEventSuppression = 5 * time.Minute
	bmpKeepAlivePeriod         = 30 * time.Second
	bmpMaxSuppressionKeys      = 100_000
)

var (
	errPlaintextBMP          = errors.New("bgp bmp: plaintext connections are refused")
	errBMPASPathLimit        = errors.New("bgp bmp: AS_PATH entry limit exceeded")
	errBMPAnnouncementLimit  = errors.New("bgp bmp: announcement limit exceeded")
	errBMPRoutePathWorkLimit = errors.New("bgp bmp: route/path work limit exceeded")
)

// BMPListener accepts direct router BMP sessions over tenant-bound mTLS and
// publishes route-monitoring observations as tenant-keyed BGP events.
type BMPListener struct {
	ln               net.Listener
	pub              Publisher
	log              *slog.Logger
	collector        string
	now              func() time.Time
	inventory        *BMPPeerInventory
	handshakeTimeout time.Duration
	readTimeout      time.Duration
	idleTimeout      time.Duration
	suppression      time.Duration
	seenMu           sync.Mutex
	seen             map[bmpRouteKey]int64
	maxSessions      int
	sessionSlots     chan struct{}
	sessionMetrics   BMPSessionMetrics
	activeSessions   atomic.Int64
	verifyIssued     BMPIdentityVerifier
	revocations      *probectlc.RevocationList
}

// BMPSessionMetrics receives process-aggregate session health without tenant
// or peer labels. The shared agent metrics runtime implements this interface.
type BMPSessionMetrics interface {
	SessionTimeout()
	SessionAdmissionRejected()
	SetActiveSessions(int)
}

// BMPOption customizes a BMPListener.
type BMPOption func(*BMPListener)

// BMPIdentityVerifier checks the exact certificate identity against the
// operator-owned enrollment registry. Implementations must scope the lookup at
// the storage layer by tenant and fail closed on lookup errors.
type BMPIdentityVerifier = probectlc.IssuedIdentityVerifier

// WithBMPIssuedIdentityVerifier installs the authoritative registry check.
// Production listeners must provide one; Serve refuses to start without it.
func WithBMPIssuedIdentityVerifier(verify BMPIdentityVerifier) BMPOption {
	return func(l *BMPListener) { l.verifyIssued = verify }
}

// WithBMPRevocationList installs the existing registry-driven revocation list.
// The listener consults it before accepting any BMP payload bytes.
func WithBMPRevocationList(rl *probectlc.RevocationList) BMPOption {
	return func(l *BMPListener) {
		if rl != nil {
			l.revocations = rl
		}
	}
}

// withBMPPeerInventory injects the peer inventory updated by accepted BMP
// sessions. A nil inventory falls back to an empty in-process inventory.
func withBMPPeerInventory(inv *BMPPeerInventory) BMPOption {
	return func(l *BMPListener) {
		if inv != nil {
			l.inventory = inv
		}
	}
}

// WithBMPHandshakeTimeout bounds unauthenticated mTLS handshakes.
func WithBMPHandshakeTimeout(timeout time.Duration) BMPOption {
	return func(l *BMPListener) {
		if timeout > 0 {
			l.handshakeTimeout = timeout
		}
	}
}

// WithBMPReadTimeout bounds each authenticated BMP header and payload read.
func WithBMPReadTimeout(timeout time.Duration) BMPOption {
	return func(l *BMPListener) {
		if timeout > 0 {
			l.readTimeout = timeout
		}
	}
}

// WithBMPIdleTimeout bounds how long an authenticated session may wait for
// its next frame. 0 (the default) leaves quiet sessions open and relies on
// TCP keepalive to detect dead peers; the read timeout still bounds any frame
// once its first byte arrived (DPR-060).
func WithBMPIdleTimeout(timeout time.Duration) BMPOption {
	return func(l *BMPListener) {
		if timeout >= 0 {
			l.idleTimeout = timeout
		}
	}
}

// WithBMPEventSuppression republishes an unchanged route observation from the
// same peer at most once per window; 0 publishes every observation (DPR-060).
func WithBMPEventSuppression(window time.Duration) BMPOption {
	return func(l *BMPListener) {
		if window >= 0 {
			l.suppression = window
		}
	}
}

// WithBMPMaxSessions bounds process-wide concurrent BMP sessions.
func WithBMPMaxSessions(maxSessions int) BMPOption {
	return func(l *BMPListener) {
		if maxSessions > 0 {
			l.maxSessions = maxSessions
		}
	}
}

// WithBMPSessionMetrics exposes aggregate timeout, rejection, and active
// session state on the listener process's metrics surface.
func WithBMPSessionMetrics(m BMPSessionMetrics) BMPOption {
	return func(l *BMPListener) { l.sessionMetrics = m }
}

// NewBMPListener constructs a BMP listener around an already-created TLS
// listener. The caller owns TLS policy; production callers should use
// internal/crypto.ServerMTLSConfig so the tenant comes from the verified SPIFFE
// client certificate.
func NewBMPListener(ln net.Listener, pub Publisher, collector string, log *slog.Logger, opts ...BMPOption) *BMPListener {
	if collector == "" {
		collector = defaultBMPCollectorID
	}
	if log == nil {
		log = slog.Default()
	}
	l := &BMPListener{
		ln:               ln,
		pub:              pub,
		log:              log,
		collector:        collector,
		now:              time.Now,
		inventory:        NewBMPPeerInventory(),
		handshakeTimeout: DefaultBMPHandshakeTimeout,
		readTimeout:      DefaultBMPReadTimeout,
		idleTimeout:      DefaultBMPIdleTimeout,
		suppression:      DefaultBMPEventSuppression,
		seen:             make(map[bmpRouteKey]int64),
		maxSessions:      DefaultBMPMaxSessions,
		revocations:      probectlc.NewRevocationList(),
	}
	for _, opt := range opts {
		opt(l)
	}
	if l.inventory == nil {
		l.inventory = NewBMPPeerInventory()
	}
	l.sessionSlots = make(chan struct{}, l.maxSessions)
	return l
}

// Serve accepts BMP peer sessions until ctx is canceled or the listener fails.
func (l *BMPListener) Serve(ctx context.Context) error {
	if l.ln == nil {
		return errors.New("bgp bmp: listener is nil")
	}
	if l.pub == nil {
		return errors.New("bgp bmp: publisher is nil")
	}
	if l.verifyIssued == nil {
		return errors.New("bgp bmp: issued-identity registry verifier is required")
	}
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	for {
		conn, err := l.ln.Accept()
		enableTCPKeepAlive(conn)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("bgp bmp: accept: %w", err)
		}
		if !l.acquireSession() {
			l.log.Warn("bmp peer session rejected",
				"remote", bmpRemoteAddr(conn),
				"reason", "session_limit",
				"max_sessions", l.maxSessions,
			)
			_ = conn.Close()
			continue
		}
		go func() {
			defer l.releaseSession()
			if err := l.handleConn(ctx, conn); err != nil && ctx.Err() == nil {
				l.log.Warn("bmp peer session closed", "remote", bmpRemoteAddr(conn), "error", err)
			}
		}()
	}
}

func (l *BMPListener) acquireSession() bool {
	select {
	case l.sessionSlots <- struct{}{}:
		active := int(l.activeSessions.Add(1))
		if l.sessionMetrics != nil {
			l.sessionMetrics.SetActiveSessions(active)
		}
		return true
	default:
		if l.sessionMetrics != nil {
			l.sessionMetrics.SessionAdmissionRejected()
		}
		return false
	}
}

func (l *BMPListener) releaseSession() {
	<-l.sessionSlots
	active := int(l.activeSessions.Add(-1))
	if l.sessionMetrics != nil {
		l.sessionMetrics.SetActiveSessions(active)
	}
}

type bmpIdentity struct {
	TenantID string
	AgentID  string
	SPIFFEID string
	Serial   string
}

func (l *BMPListener) handleConn(ctx context.Context, conn net.Conn) (retErr error) {
	defer func() {
		// A TLS close_notify write must not let an already-timed-out peer keep
		// the session goroutine alive. Hard-close the underlying connection on
		// timeout/cancellation; graceful TLS Close may wait up to five seconds.
		if tlsConn, ok := conn.(*tls.Conn); ok && (ctx.Err() != nil || retErr != nil) {
			_ = tlsConn.NetConn().Close()
			return
		}
		// Non-timeout exits still get a bounded graceful close.
		expired := time.Now().Add(-time.Second)
		_ = conn.SetReadDeadline(expired)
		_ = conn.SetWriteDeadline(expired)
		_ = conn.Close()
	}()
	defer func() {
		if retErr != nil && ctx.Err() == nil && isBMPTimeout(retErr) && l.sessionMetrics != nil {
			l.sessionMetrics.SessionTimeout()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if err := conn.SetDeadline(time.Now().Add(l.handshakeTimeout)); err != nil {
		return fmt.Errorf("bgp bmp: set mtls handshake deadline: %w", err)
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, l.handshakeTimeout)
	id, err := bmpPeerIdentity(handshakeCtx, conn)
	if err != nil {
		cancel()
		return err
	}
	if l.revocations.IsRevoked(id.Serial, id.SPIFFEID) {
		cancel()
		return fmt.Errorf("bgp bmp: registry-revoked router identity refused")
	}
	if l.verifyIssued == nil {
		cancel()
		return errors.New("bgp bmp: issued-identity registry verifier is required")
	}
	issued, err := l.verifyIssued(
		handshakeCtx,
		id.TenantID,
		id.AgentID,
		id.SPIFFEID,
		id.Serial,
	)
	cancel()
	if err != nil {
		return fmt.Errorf("bgp bmp: verify issued router identity: %w", err)
	}
	if !issued {
		return errors.New("bgp bmp: unregistered router identity refused")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("bgp bmp: clear mtls handshake deadline: %w", err)
	}
	l.log.Info("bmp peer session admitted",
		"tenant_id", id.TenantID, "agent_id", id.AgentID, "spiffe_id", id.SPIFFEID, "remote", bmpRemoteAddr(conn))
	var published, suppressed uint64
	defer func() {
		l.log.Info("bmp peer session ended",
			"tenant_id", id.TenantID, "agent_id", id.AgentID, "remote", bmpRemoteAddr(conn),
			"routes_published", published, "routes_suppressed", suppressed)
	}()
	for {
		msgType, payload, err := readBMPMessageWithDeadline(conn, l.idleTimeout, l.readTimeout)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if msgType != bmpRouteMonitoring {
			l.log.Debug("skipping unsupported bmp message", "tenant_id", id.TenantID, "message_type", msgType)
			continue
		}
		obs, err := parseBMPRouteMonitoring(payload)
		if err != nil {
			l.log.Warn("skipping malformed bmp route-monitoring message", "tenant_id", id.TenantID, "error", err)
			continue
		}
		detectedAt := obs.peer.TimestampUnixNano
		if detectedAt == 0 {
			detectedAt = l.now().UnixNano()
		}
		l.inventory.Upsert(BMPPeerRecord{
			TenantID:           id.TenantID,
			AgentID:            id.AgentID,
			PeerASN:            obs.peer.ASN,
			PeerAddress:        obs.peer.Address,
			FirstSeenUnixNano:  detectedAt,
			LastSeenUnixNano:   detectedAt,
			RouteAnnouncements: uint64(len(obs.routes)),
		})

		for _, route := range obs.routes {
			if l.repeated(id, obs.peer, route, detectedAt) {
				suppressed++
				continue
			}
			ev := Event{
				TenantID:           id.TenantID,
				EventType:          "origin_change",
				Severity:           "info",
				Confidence:         0.5,
				Prefix:             route.Prefix,
				NewOriginASN:       route.OriginASN,
				NewASPath:          route.ASPath,
				RPKIStatus:         "unknown",
				Collector:          l.collectorFor(id.AgentID),
				PeerASN:            obs.peer.ASN,
				PeerAddress:        obs.peer.Address,
				Message:            "BMP route announcement observed from AS" + strconv.FormatUint(uint64(obs.peer.ASN), 10),
				DetectedAtUnixNano: detectedAt,
			}
			if err := PublishEvent(ctx, l.pub, ev); err != nil {
				return err
			}
			published++
			l.log.Info("bmp route event published",
				"tenant_id", ev.TenantID,
				"agent_id", id.AgentID,
				"prefix", ev.Prefix,
				"origin_asn", ev.NewOriginASN,
				"peer_asn", ev.PeerASN,
			)
		}
	}
}

func bmpRemoteAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	return conn.RemoteAddr().String()
}

func isBMPTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (l *BMPListener) collectorFor(agentID string) string {
	if agentID == "" {
		return l.collector
	}
	return l.collector + "/" + agentID
}

func bmpPeerIdentity(ctx context.Context, conn net.Conn) (bmpIdentity, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return bmpIdentity{}, errPlaintextBMP
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return bmpIdentity{}, fmt.Errorf("bgp bmp: mtls handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return bmpIdentity{}, errors.New("bgp bmp: mtls peer certificate missing")
	}
	leaf := state.PeerCertificates[0]
	id, err := probectlc.BMPSPIFFEIDFromCert(leaf)
	if err != nil {
		return bmpIdentity{}, fmt.Errorf("bgp bmp: peer identity: %w", err)
	}
	if id.TenantID == "" || id.AgentID == "" {
		return bmpIdentity{}, errors.New("bgp bmp: peer identity missing tenant or agent")
	}
	return bmpIdentity{
		TenantID: id.TenantID,
		AgentID:  id.AgentID,
		SPIFFEID: id.String(),
		Serial:   leaf.SerialNumber.Text(16),
	}, nil
}

func readBMPMessage(r io.Reader) (uint8, []byte, error) {
	msgType, payloadLen, err := readBMPHeader(r)
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

// readBMPMessageWithDeadline reads one BMP frame. Waiting for the frame is
// idle time bounded by idleTimeout only (0 = unbounded; TCP keepalive detects
// a dead peer). Once the first byte arrives the rest of the header and the
// payload must complete within frameTimeout, so a stalled or slow-dripping
// peer still cannot pin a session goroutine (DPR-060).
func readBMPMessageWithDeadline(conn net.Conn, idleTimeout, frameTimeout time.Duration) (uint8, []byte, error) {
	if frameTimeout <= 0 {
		return 0, nil, errors.New("bgp bmp: read timeout must be positive")
	}
	idleDeadline := time.Time{}
	if idleTimeout > 0 {
		idleDeadline = time.Now().Add(idleTimeout)
	}
	if err := conn.SetReadDeadline(idleDeadline); err != nil {
		return 0, nil, fmt.Errorf("bgp bmp: set idle read deadline: %w", err)
	}
	var header [bmpCommonHeaderLen]byte
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return 0, nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(frameTimeout)); err != nil {
		return 0, nil, fmt.Errorf("bgp bmp: set header read deadline: %w", err)
	}
	if _, err := io.ReadFull(conn, header[1:]); err != nil {
		return 0, nil, err
	}
	msgType, payloadLen, err := readBMPHeader(bytes.NewReader(header[:]))
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, payloadLen)
	if payloadLen == 0 {
		return msgType, payload, nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(frameTimeout)); err != nil {
		return 0, nil, fmt.Errorf("bgp bmp: set payload read deadline: %w", err)
	}
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

// enableTCPKeepAlive lets the kernel notice a router that vanished without a
// FIN while the session waits, unbounded, for its next frame (DPR-060).
func enableTCPKeepAlive(conn net.Conn) {
	if conn == nil {
		return
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(bmpKeepAlivePeriod)
	}
}

// bmpRouteKey identifies one unchanged route observation from one peer of one
// router: the unit of repeat suppression.
type bmpRouteKey struct {
	tenantID, agentID, peerAddress, prefix, asPath string
	peerASN, originASN                             uint32
}

// repeated reports whether the same observation was published less than the
// suppression window ago (by data time), remembering it otherwise. The map is
// bounded: past bmpMaxSuppressionKeys expired keys are swept, and if nothing
// expired it starts over (worst case: one extra event per key).
func (l *BMPListener) repeated(id bmpIdentity, peer bmpPeer, route bmpRouteAnnouncement, nowNano int64) bool {
	if l.suppression <= 0 {
		return false
	}
	key := bmpRouteKey{
		tenantID: id.TenantID, agentID: id.AgentID, peerAddress: peer.Address, prefix: route.Prefix,
		asPath: fmt.Sprint(route.ASPath), peerASN: peer.ASN, originASN: route.OriginASN,
	}
	window := l.suppression.Nanoseconds()
	l.seenMu.Lock()
	defer l.seenMu.Unlock()
	if last, ok := l.seen[key]; ok && nowNano-last >= 0 && nowNano-last < window {
		return true
	}
	if len(l.seen) >= bmpMaxSuppressionKeys {
		for k, t := range l.seen {
			if nowNano-t >= window {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= bmpMaxSuppressionKeys {
			l.seen = make(map[bmpRouteKey]int64)
		}
	}
	l.seen[key] = nowNano
	return false
}

func readBMPHeader(r io.Reader) (uint8, int, error) {
	var header [bmpCommonHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, err
	}
	if header[0] != bmpVersion {
		return 0, 0, fmt.Errorf("bgp bmp: unsupported version %d", header[0])
	}
	msgLen := int(binary.BigEndian.Uint32(header[1:5]))
	if msgLen < bmpCommonHeaderLen {
		return 0, 0, fmt.Errorf("bgp bmp: invalid message length %d", msgLen)
	}
	if msgLen > bmpMaxMessageBytes {
		return 0, 0, fmt.Errorf("bgp bmp: message length %d exceeds limit %d", msgLen, bmpMaxMessageBytes)
	}
	return header[5], msgLen - bmpCommonHeaderLen, nil
}

type bmpRouteMonitoringObservation struct {
	peer   bmpPeer
	routes []bmpRouteAnnouncement
}

type bmpPeer struct {
	ASN               uint32
	Address           string
	TimestampUnixNano int64
}

type bmpRouteAnnouncement struct {
	Prefix string
	// ASPath is the immutable, parse-owned path shared by every announcement
	// in one UPDATE. PublishEvent marshals it synchronously and never mutates
	// it, so sharing avoids route_count × path_length heap amplification.
	ASPath    []uint32
	OriginASN uint32
}

func parseBMPRouteMonitoring(payload []byte) (bmpRouteMonitoringObservation, error) {
	if len(payload) < bmpPeerHeaderLen {
		return bmpRouteMonitoringObservation{}, fmt.Errorf("bgp bmp: route-monitoring payload too short: %d", len(payload))
	}
	peer, err := parseBMPPeer(payload[:bmpPeerHeaderLen])
	if err != nil {
		return bmpRouteMonitoringObservation{}, err
	}
	routes, err := parseBGPUpdateRoutes(payload[bmpPeerHeaderLen:])
	if err != nil {
		return bmpRouteMonitoringObservation{}, err
	}
	return bmpRouteMonitoringObservation{peer: peer, routes: routes}, nil
}

func parseBMPPeer(header []byte) (bmpPeer, error) {
	if len(header) != bmpPeerHeaderLen {
		return bmpPeer{}, fmt.Errorf("bgp bmp: peer header length %d", len(header))
	}
	addrRaw := header[10:26]
	var addr netip.Addr
	if header[1]&bmpPeerFlagIPv6 != 0 {
		a, ok := netip.AddrFromSlice(addrRaw)
		if !ok {
			return bmpPeer{}, errors.New("bgp bmp: invalid ipv6 peer address")
		}
		addr = a
	} else {
		addr = netip.AddrFrom4([4]byte{addrRaw[12], addrRaw[13], addrRaw[14], addrRaw[15]})
	}
	sec := binary.BigEndian.Uint32(header[34:38])
	usec := binary.BigEndian.Uint32(header[38:42])
	var ts int64
	if sec != 0 || usec != 0 {
		ts = time.Unix(int64(sec), int64(usec)*1000).UnixNano()
	}
	return bmpPeer{
		ASN:               binary.BigEndian.Uint32(header[26:30]),
		Address:           addr.String(),
		TimestampUnixNano: ts,
	}, nil
}

func parseBGPUpdateRoutes(raw []byte) ([]bmpRouteAnnouncement, error) {
	if len(raw) < bgpHeaderLen {
		return nil, fmt.Errorf("bgp bmp: embedded bgp message too short: %d", len(raw))
	}
	for i := 0; i < 16; i++ {
		if raw[i] != 0xff {
			return nil, errors.New("bgp bmp: embedded bgp marker is invalid")
		}
	}
	msgLen := int(binary.BigEndian.Uint16(raw[16:18]))
	if msgLen < bgpHeaderLen || msgLen > len(raw) {
		return nil, fmt.Errorf("bgp bmp: invalid embedded bgp length %d", msgLen)
	}
	if raw[18] != bgpMessageTypeUpdate {
		return nil, fmt.Errorf("bgp bmp: embedded bgp message type %d is not UPDATE", raw[18])
	}
	body := raw[bgpHeaderLen:msgLen]
	if len(body) < 4 {
		return nil, errors.New("bgp bmp: update body too short")
	}
	withdrawnLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+withdrawnLen+2 {
		return nil, errors.New("bgp bmp: withdrawn-routes length exceeds update body")
	}
	pos := 2 + withdrawnLen
	attrLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+attrLen {
		return nil, errors.New("bgp bmp: path-attributes length exceeds update body")
	}
	attrs := body[pos : pos+attrLen]
	nlri := body[pos+attrLen:]
	if len(nlri) == 0 {
		return nil, nil
	}
	asPath, err := parseBGPASPath(attrs)
	if err != nil {
		return nil, err
	}
	if len(asPath) == 0 {
		return nil, errors.New("bgp bmp: empty AS_PATH")
	}
	prefixCount, err := countIPv4NLRI(nlri)
	if err != nil {
		return nil, err
	}
	if err := validateBMPUpdateCardinality(len(asPath), prefixCount); err != nil {
		return nil, err
	}
	// Decode prefix strings only after all cardinality and aggregate-work
	// checks pass. This keeps rejected one-past input allocation-light.
	prefixes := decodeIPv4NLRI(nlri, prefixCount)
	routes := make([]bmpRouteAnnouncement, 0, len(prefixes))
	origin := asPath[len(asPath)-1]
	for _, prefix := range prefixes {
		routes = append(routes, bmpRouteAnnouncement{
			Prefix:    prefix,
			ASPath:    asPath,
			OriginASN: origin,
		})
	}
	return routes, nil
}

// validateBMPUpdateCardinality bounds both independent dimensions and their
// aggregate publication work. Division is used before multiplication so
// attacker-controlled counts cannot overflow int while being checked.
func validateBMPUpdateCardinality(asPathEntries, announcements int) error {
	if asPathEntries < 0 || asPathEntries > maxBMPASPathEntries {
		return fmt.Errorf("%w: %d > %d", errBMPASPathLimit, asPathEntries, maxBMPASPathEntries)
	}
	if announcements < 0 || announcements > maxBMPRouteAnnouncements {
		return fmt.Errorf("%w: %d > %d", errBMPAnnouncementLimit, announcements, maxBMPRouteAnnouncements)
	}
	if asPathEntries != 0 && announcements > maxBMPRoutePathEntries/asPathEntries {
		return fmt.Errorf(
			"%w: %d AS_PATH entries across %d announcements exceeds %d",
			errBMPRoutePathWorkLimit,
			asPathEntries,
			announcements,
			maxBMPRoutePathEntries,
		)
	}
	return nil
}

func parseBGPASPath(attrs []byte) ([]uint32, error) {
	var as4Path []uint32
	for len(attrs) > 0 {
		if len(attrs) < 3 {
			return nil, errors.New("bgp bmp: malformed path attribute header")
		}
		flags, typ := attrs[0], attrs[1]
		headerLen := 3
		attrLen := int(attrs[2])
		if flags&bgpPathAttrExtended != 0 {
			if len(attrs) < 4 {
				return nil, errors.New("bgp bmp: malformed extended path attribute header")
			}
			headerLen = 4
			attrLen = int(binary.BigEndian.Uint16(attrs[2:4]))
		}
		if len(attrs) < headerLen+attrLen {
			return nil, errors.New("bgp bmp: path attribute length exceeds update")
		}
		value := attrs[headerLen : headerLen+attrLen]
		switch typ {
		case bgpPathAttrASPath:
			return parseBGPASPathValue(value)
		case bgpPathAttrAS4Path:
			path, err := parseBGPASPathValue(value)
			if err == nil && len(path) > 0 {
				as4Path = path
			}
		}
		attrs = attrs[headerLen+attrLen:]
	}
	if len(as4Path) > 0 {
		return as4Path, nil
	}
	return nil, errors.New("bgp bmp: update has no AS_PATH")
}

func parseBGPASPathValue(value []byte) ([]uint32, error) {
	if path, ok, err := parseBGPASPathValueWidth(value, 4); ok {
		if err != nil {
			return nil, err
		}
		return path, nil
	}
	if path, ok, err := parseBGPASPathValueWidth(value, 2); ok {
		if err != nil {
			return nil, err
		}
		return path, nil
	}
	return nil, errors.New("bgp bmp: malformed AS_PATH")
}

func parseBGPASPathValueWidth(value []byte, width int) ([]uint32, bool, error) {
	entryCount, ok := countBGPASPathEntries(value, width)
	if !ok {
		return nil, false, nil
	}
	if entryCount > maxBMPASPathEntries {
		return nil, true, fmt.Errorf("%w: %d > %d", errBMPASPathLimit, entryCount, maxBMPASPathEntries)
	}

	// The count pass above proved the framing; the decode pass reads it back
	// through the shared bounded reader (internal/wire) so the two passes
	// cannot disagree about where a segment ends.
	r := wire.New(value)
	path := make([]uint32, 0, entryCount)
	for !r.Empty() {
		r.Skip(1) // segment type (validated by the counting pass)
		count := int(r.U8())
		for i := 0; i < count; i++ {
			if width == 4 {
				path = append(path, r.U32())
			} else {
				path = append(path, uint32(r.U16()))
			}
		}
		if r.Err() != nil {
			return nil, false, nil
		}
	}
	return path, true, nil
}

// countBGPASPathEntries validates the segment framing without allocating the
// decoded path. The caller applies the entry ceiling before the second pass.
func countBGPASPathEntries(value []byte, width int) (int, bool) {
	if width <= 0 {
		return 0, false
	}
	entries := 0
	r := wire.New(value)
	for !r.Empty() {
		if r.Remaining() < 2 {
			return 0, false
		}
		segType, count := r.U8(), int(r.U8())
		if segType < 1 || segType > 4 {
			return 0, false
		}
		if count > r.Remaining()/width {
			return 0, false
		}
		r.Skip(count * width)
		entries += count
	}
	if r.Err() != nil {
		return 0, false
	}
	return entries, true
}

// countIPv4NLRI validates and counts announced prefixes without allocating
// strings. It rejects one-past before route or prefix construction.
func countIPv4NLRI(raw []byte) (int, error) {
	count := 0
	for len(raw) > 0 {
		bits := int(raw[0])
		if bits > 32 {
			return 0, fmt.Errorf("bgp bmp: invalid ipv4 prefix length %d", bits)
		}
		n := (bits + 7) / 8
		if len(raw) < 1+n {
			return 0, errors.New("bgp bmp: truncated ipv4 nlri")
		}
		if count == maxBMPRouteAnnouncements {
			return 0, fmt.Errorf(
				"%w: at least %d > %d",
				errBMPAnnouncementLimit,
				count+1,
				maxBMPRouteAnnouncements,
			)
		}
		count++
		raw = raw[1+n:]
	}
	return count, nil
}

func decodeIPv4NLRI(raw []byte, count int) []string {
	prefixes := make([]string, 0, count)
	for len(raw) > 0 {
		bits := int(raw[0])
		n := (bits + 7) / 8
		var octets [4]byte
		copy(octets[:], raw[1:1+n])
		prefix := netip.PrefixFrom(netip.AddrFrom4(octets), bits).Masked()
		prefixes = append(prefixes, prefix.String())
		raw = raw[1+n:]
	}
	return prefixes
}

// BMPPeerRecord is one tenant-scoped router peer observed by the BMP listener.
type BMPPeerRecord struct {
	TenantID           string
	AgentID            string
	PeerASN            uint32
	PeerAddress        string
	FirstSeenUnixNano  int64
	LastSeenUnixNano   int64
	RouteAnnouncements uint64
}

// BMPPeerInventory is the listener's in-process tenant-scoped peer inventory.
type BMPPeerInventory struct {
	mu    sync.RWMutex
	peers map[string]BMPPeerRecord
}

// NewBMPPeerInventory returns an empty BMP peer inventory.
func NewBMPPeerInventory() *BMPPeerInventory {
	return &BMPPeerInventory{peers: make(map[string]BMPPeerRecord)}
}

// Upsert records a peer observation without merging tenants or agents.
func (i *BMPPeerInventory) Upsert(record BMPPeerRecord) {
	if i == nil {
		return
	}
	key := bmpPeerInventoryKey(record)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.peers == nil {
		i.peers = make(map[string]BMPPeerRecord)
	}
	if prev, ok := i.peers[key]; ok {
		if record.FirstSeenUnixNano == 0 || (prev.FirstSeenUnixNano != 0 && prev.FirstSeenUnixNano < record.FirstSeenUnixNano) {
			record.FirstSeenUnixNano = prev.FirstSeenUnixNano
		}
		if prev.LastSeenUnixNano > record.LastSeenUnixNano {
			record.LastSeenUnixNano = prev.LastSeenUnixNano
		}
		record.RouteAnnouncements += prev.RouteAnnouncements
	}
	i.peers[key] = record
}

// snapshot returns a deterministic copy of the inventory.
func (i *BMPPeerInventory) snapshot() []BMPPeerRecord {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]BMPPeerRecord, 0, len(i.peers))
	for _, p := range i.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].TenantID != out[b].TenantID {
			return out[a].TenantID < out[b].TenantID
		}
		if out[a].AgentID != out[b].AgentID {
			return out[a].AgentID < out[b].AgentID
		}
		if out[a].PeerASN != out[b].PeerASN {
			return out[a].PeerASN < out[b].PeerASN
		}
		return out[a].PeerAddress < out[b].PeerAddress
	})
	return out
}

func bmpPeerInventoryKey(record BMPPeerRecord) string {
	return record.TenantID + "\x00" + record.AgentID + "\x00" +
		strconv.FormatUint(uint64(record.PeerASN), 10) + "\x00" + record.PeerAddress
}
