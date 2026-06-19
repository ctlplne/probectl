// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const (
	// FreshnessSentAtHeader carries the sender's RFC3339Nano request timestamp.
	FreshnessSentAtHeader = "X-Probectl-OTLP-Sent-At"
	// FreshnessNonceHeader carries a per-request random nonce.
	FreshnessNonceHeader = "X-Probectl-OTLP-Nonce"
	// FreshnessSignatureHeader carries sha256=<hex HMAC> over the canonical request.
	FreshnessSignatureHeader = "X-Probectl-OTLP-Signature"

	freshnessMetadataSentAt    = "x-probectl-otlp-sent-at"
	freshnessMetadataNonce     = "x-probectl-otlp-nonce"
	freshnessMetadataSignature = "x-probectl-otlp-signature"

	// DefaultFreshnessWindow is the accepted timestamp skew and replay horizon.
	DefaultFreshnessWindow = 5 * time.Minute
	noncesPerTenant        = 4096
)

// FreshnessVerifier implements optional application-level replay protection for
// first-party OTLP senders. Stock OTel collectors remain compatible when the
// verifier is nil/disabled; when enabled, every request must carry a timestamp,
// nonce, and HMAC over the request body.
type FreshnessVerifier struct {
	key    []byte
	window time.Duration

	mu   sync.Mutex
	seen map[string]map[string]time.Time
	now  func() time.Time
}

// NewFreshnessVerifier returns a freshness verifier, or nil when key is empty.
func NewFreshnessVerifier(key []byte, window time.Duration) *FreshnessVerifier {
	if len(key) == 0 {
		return nil
	}
	if window <= 0 {
		window = DefaultFreshnessWindow
	}
	keyCopy := append([]byte(nil), key...)
	return &FreshnessVerifier{
		key:    keyCopy,
		window: window,
		seen:   map[string]map[string]time.Time{},
		now:    time.Now,
	}
}

// Enabled reports whether the verifier enforces signed timestamp+nonce headers.
func (v *FreshnessVerifier) Enabled() bool { return v != nil && len(v.key) > 0 }

// VerifyHTTP verifies the OTLP/HTTP freshness envelope for a bounded body.
func (v *FreshnessVerifier) VerifyHTTP(r *http.Request, tenant string, body []byte) error {
	if !v.Enabled() {
		return nil
	}
	sentAt, nonce, sig, err := parseFreshnessEnvelope(
		r.Header.Get(FreshnessSentAtHeader),
		r.Header.Get(FreshnessNonceHeader),
		r.Header.Get(FreshnessSignatureHeader),
	)
	if err != nil {
		return err
	}
	canonical := canonicalFreshnessData("http", r.Method+" "+r.URL.Path, sentAt, nonce, body)
	return v.verify(tenant, nonce, sentAt, sig, canonical)
}

// VerifyGRPC verifies the OTLP/gRPC freshness metadata for a unary protobuf request.
func (v *FreshnessVerifier) VerifyGRPC(ctx context.Context, method, tenant string, req any) error {
	if !v.Enabled() {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("missing OTLP freshness metadata")
	}
	msg, ok := req.(proto.Message)
	if !ok {
		return fmt.Errorf("OTLP freshness cannot sign non-protobuf request %T", req)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal OTLP request for freshness: %w", err)
	}
	sentAt, nonce, sig, err := parseFreshnessEnvelope(
		firstMetadata(md, freshnessMetadataSentAt),
		firstMetadata(md, freshnessMetadataNonce),
		firstMetadata(md, freshnessMetadataSignature),
	)
	if err != nil {
		return err
	}
	canonical := canonicalFreshnessData("grpc", method, sentAt, nonce, body)
	return v.verify(tenant, nonce, sentAt, sig, canonical)
}

func firstMetadata(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func parseFreshnessEnvelope(sentAt, nonce, signature string) (time.Time, string, []byte, error) {
	if strings.TrimSpace(sentAt) == "" || strings.TrimSpace(nonce) == "" || strings.TrimSpace(signature) == "" {
		return time.Time{}, "", nil, fmt.Errorf("missing OTLP freshness envelope")
	}
	parsed, err := time.Parse(time.RFC3339Nano, sentAt)
	if err != nil {
		return time.Time{}, "", nil, fmt.Errorf("invalid OTLP freshness timestamp")
	}
	sigHex := strings.TrimSpace(strings.TrimPrefix(signature, "sha256="))
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) == 0 {
		return time.Time{}, "", nil, fmt.Errorf("invalid OTLP freshness signature")
	}
	return parsed, strings.TrimSpace(nonce), sig, nil
}

func canonicalFreshnessData(surface, operation string, sentAt time.Time, nonce string, body []byte) []byte {
	return []byte(strings.Join([]string{
		"probectl-otlp-freshness-v1",
		surface,
		operation,
		sentAt.UTC().Format(time.RFC3339Nano),
		nonce,
		hex.EncodeToString(crypto.Hash(body)),
	}, "\n"))
}

func (v *FreshnessVerifier) verify(tenant, nonce string, sentAt time.Time, sig, canonical []byte) error {
	now := v.now()
	if sentAt.Before(now.Add(-v.window)) || sentAt.After(now.Add(v.window)) {
		return fmt.Errorf("stale OTLP freshness envelope: sent %s outside +/- %s", sentAt.UTC().Format(time.RFC3339Nano), v.window)
	}
	if !crypto.Verify(v.key, canonical, sig) {
		return fmt.Errorf("invalid OTLP freshness signature")
	}
	return v.remember(tenant, nonce, now)
}

func (v *FreshnessVerifier) remember(tenant, nonce string, now time.Time) error {
	scope := tenant
	if scope == "" {
		scope = "<unknown>"
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	tenantSeen := v.seen[scope]
	if tenantSeen == nil {
		tenantSeen = map[string]time.Time{}
		v.seen[scope] = tenantSeen
	}
	cutoff := now.Add(-v.window)
	for n, seenAt := range tenantSeen {
		if seenAt.Before(cutoff) {
			delete(tenantSeen, n)
		}
	}
	if _, ok := tenantSeen[nonce]; ok {
		return fmt.Errorf("replayed OTLP freshness nonce")
	}
	if len(tenantSeen) >= noncesPerTenant {
		return fmt.Errorf("OTLP freshness nonce cache exhausted for tenant")
	}
	tenantSeen[nonce] = now
	return nil
}

// FreshnessHTTPHeaders signs test/client OTLP/HTTP freshness headers.
func FreshnessHTTPHeaders(key []byte, sentAt time.Time, nonce, method, path string, body []byte) http.Header {
	h := http.Header{}
	canonical := canonicalFreshnessData("http", method+" "+path, sentAt, nonce, body)
	h.Set(FreshnessSentAtHeader, sentAt.UTC().Format(time.RFC3339Nano))
	h.Set(FreshnessNonceHeader, nonce)
	h.Set(FreshnessSignatureHeader, "sha256="+hex.EncodeToString(crypto.Sign(key, canonical)))
	return h
}

// FreshnessGRPCMetadata signs test/client OTLP/gRPC freshness metadata.
func FreshnessGRPCMetadata(key []byte, sentAt time.Time, nonce, method string, msg proto.Message) (metadata.MD, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	canonical := canonicalFreshnessData("grpc", method, sentAt, nonce, body)
	return metadata.Pairs(
		freshnessMetadataSentAt, sentAt.UTC().Format(time.RFC3339Nano),
		freshnessMetadataNonce, nonce,
		freshnessMetadataSignature, "sha256="+hex.EncodeToString(crypto.Sign(key, canonical)),
	), nil
}
