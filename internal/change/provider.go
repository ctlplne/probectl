// SPDX-License-Identifier: LicenseRef-probectl-TBD

package change

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// ErrNormalize is returned when an (untrusted) webhook body cannot be parsed into
// any change event. The control plane maps it to a 400; a verified-but-empty
// delivery (e.g. a GitHub ping) is not an error — it yields zero events.
var ErrNormalize = errors.New("change: cannot normalize webhook body")

// Provider verifies + normalizes one source's webhook deliveries. It is the seam
// for heterogeneous sources (the hard part of S29): each provider authenticates
// with its own scheme and maps its payload onto the canonical Event.
type Provider interface {
	Name() string
	// Verify authenticates a delivery against the per-webhook secret using the
	// provider's scheme (an HMAC signature header, or a shared token), in constant
	// time. It returns false for a missing, malformed, or forged signature — the
	// caller MUST reject the request when Verify is false (fail closed).
	Verify(secret string, body []byte, h http.Header, now time.Time) bool
	// DeliveryID returns the provider's stable delivery identifier. The control
	// plane records it before writing change/audit rows so replays become
	// idempotent successes instead of duplicate mutations.
	DeliveryID(h http.Header) (string, bool)
	// Normalize parses an UNTRUSTED body into change events. The tenant is stamped
	// by the caller from the verified credential and is never read from the payload.
	Normalize(body []byte, h http.Header, now time.Time) ([]Event, error)
}

var providers = map[string]Provider{
	ProviderGeneric: genericProvider{},
	ProviderGitHub:  githubProvider{},
	ProviderGitLab:  gitlabProvider{},
}

// Provider names.
const (
	ProviderGeneric = "generic"
	ProviderGitHub  = "github"
	ProviderGitLab  = "gitlab"
)

// ProviderByName returns the adapter for a provider (ok=false if unknown).
func ProviderByName(name string) (Provider, bool) {
	p, ok := providers[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// ProviderNames lists the supported providers (sorted for stable docs/tests).
func ProviderNames() []string { return []string{ProviderGeneric, ProviderGitHub, ProviderGitLab} }

const deliveryIDMaxLen = 256

// deliveryHeader returns a bounded, non-empty delivery identifier from the first
// matching header. It fails closed for control characters or suspiciously large
// IDs; providers use it before any storage mutation.
func deliveryHeader(h http.Header, names ...string) (string, bool) {
	for _, name := range names {
		id := strings.TrimSpace(h.Get(name))
		if id == "" {
			continue
		}
		if len(id) > deliveryIDMaxLen || strings.ContainsAny(id, "\r\n") {
			return "", false
		}
		return id, true
	}
	return "", false
}

// verifyHMAC checks a "sha256=<hex>" signature header against HMAC-SHA256(secret,
// payload) in constant time. Empty secret or header fails closed.
func verifyHMAC(secret string, payload []byte, sigHeader string) bool {
	if secret == "" || sigHeader == "" {
		return false
	}
	mac, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(sigHeader), "sha256="))
	if err != nil || len(mac) == 0 {
		return false
	}
	return crypto.Verify([]byte(secret), payload, mac)
}

// --- generic (probectl / CI) provider ---

// genericProvider is probectl's own webhook contract: an HMAC-SHA256 signature in
// X-Probectl-Signature over "timestamp.body", plus a fresh timestamp and stable
// delivery ID. This is the path a CI job, an IaC apply (Terraform/Atlantis), or a
// network-automation tool uses to report a change with an explicit correlation
// Target (host/IP/service) or Prefix.
type genericProvider struct{}

// Generic webhook headers.
const (
	GenericDeliveryIDHeader = "X-Probectl-Delivery"
	GenericSignatureHeader  = "X-Probectl-Signature"
	GenericTimestampHeader  = "X-Probectl-Timestamp"
)

const genericSignatureFreshness = 5 * time.Minute

func (genericProvider) Name() string { return ProviderGeneric }

func (genericProvider) Verify(secret string, body []byte, h http.Header, now time.Time) bool {
	ts := strings.TrimSpace(h.Get(GenericTimestampHeader))
	at, ok := parseGenericTimestamp(ts)
	if !ok || !freshGenericTimestamp(at, now) {
		return false
	}
	return verifyHMAC(secret, genericSignedPayload(ts, body), h.Get(GenericSignatureHeader))
}

func (genericProvider) DeliveryID(h http.Header) (string, bool) {
	return deliveryHeader(h, GenericDeliveryIDHeader)
}

func parseGenericTimestamp(ts string) (time.Time, bool) {
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0).UTC(), true
}

func freshGenericTimestamp(at, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	at = at.UTC()
	return !at.Before(now.Add(-genericSignatureFreshness)) && !at.After(now.Add(genericSignatureFreshness))
}

func genericSignedPayload(timestamp string, body []byte) []byte {
	out := make([]byte, 0, len(timestamp)+1+len(body))
	out = append(out, timestamp...)
	out = append(out, '.')
	out = append(out, body...)
	return out
}

// genericEvent is the wire schema — deliberately WITHOUT a tenant_id field, so a
// payload can never select or spoof a tenant (it is stamped from the credential).
type genericEvent struct {
	Kind       string            `json:"kind"`
	Title      string            `json:"title"`
	Summary    string            `json:"summary"`
	Target     string            `json:"target"`
	Prefix     string            `json:"prefix"`
	Actor      string            `json:"actor"`
	Ref        string            `json:"ref"`
	URL        string            `json:"url"`
	Attributes map[string]string `json:"attributes"`
	OccurredAt time.Time         `json:"occurred_at"`
}

func (e genericEvent) toChange(now time.Time) Event {
	c := Event{
		Source: ProviderGeneric, Kind: Kind(e.Kind), Title: e.Title, Summary: e.Summary,
		Target: e.Target, Prefix: e.Prefix, Actor: e.Actor, Ref: e.Ref, URL: e.URL,
		Attributes: e.Attributes, OccurredAt: e.OccurredAt,
	}
	c.normalize(ProviderGeneric, now)
	return c
}

func (genericProvider) Normalize(body []byte, _ http.Header, now time.Time) ([]Event, error) {
	// Accept {"events":[...]}, a bare array, or a single object.
	var env struct {
		Events []genericEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err == nil && len(env.Events) > 0 {
		return collectGeneric(env.Events, now), nil
	}
	var arr []genericEvent
	if err := json.Unmarshal(body, &arr); err == nil && len(arr) > 0 {
		return collectGeneric(arr, now), nil
	}
	var one genericEvent
	if err := json.Unmarshal(body, &one); err != nil {
		return nil, ErrNormalize
	}
	if one.Title == "" {
		return nil, ErrNormalize
	}
	return []Event{one.toChange(now)}, nil
}

func collectGeneric(in []genericEvent, now time.Time) []Event {
	out := make([]Event, 0, len(in))
	for _, e := range in {
		if e.Title == "" {
			continue // skip malformed entries (untrusted input)
		}
		out = append(out, e.toChange(now))
	}
	return out
}
