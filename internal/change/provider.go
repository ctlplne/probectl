package change

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
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
	Verify(secret string, body []byte, h http.Header) bool
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

// verifyHMAC checks a "sha256=<hex>" signature header against HMAC-SHA256(secret,
// body) in constant time (the GitHub / probectl scheme). Empty secret or header
// fails closed.
func verifyHMAC(secret string, body []byte, sigHeader string) bool {
	if secret == "" || sigHeader == "" {
		return false
	}
	mac, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(sigHeader), "sha256="))
	if err != nil || len(mac) == 0 {
		return false
	}
	return crypto.Verify([]byte(secret), body, mac)
}

// --- generic (probectl / CI) provider ---

// genericProvider is probectl's own webhook contract: an HMAC-SHA256 signature in
// X-Probectl-Signature (mirroring the S16 outbound alert webhook) over a body that
// is already in probectl's change schema. This is the path a CI job, an IaC apply
// (Terraform/Atlantis), or a network-automation tool uses to report a change with
// an explicit correlation Target (host/IP/service) or Prefix.
type genericProvider struct{}

// GenericSignatureHeader carries the HMAC of the body (matches alert.SignatureHeader).
const GenericSignatureHeader = "X-Probectl-Signature"

func (genericProvider) Name() string { return ProviderGeneric }

func (genericProvider) Verify(secret string, body []byte, h http.Header) bool {
	return verifyHMAC(secret, body, h.Get(GenericSignatureHeader))
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
