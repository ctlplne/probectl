package siem

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
)

// Sender delivers one formatted record to the SIEM. A non-nil error means the
// caller should retry (the Forwarder handles that).
type Sender interface {
	Send(ctx context.Context, payload []byte) error
}

// Doer is the subset of *http.Client an HTTP sender needs (injectable for tests).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Preset adapts the forwarder to a specific SIEM's HTTP ingest (auth scheme +
// default format). The endpoint is operator-supplied (e.g. the Splunk HEC URL,
// the Sentinel/Chronicle ingestion URL, the Elasticsearch endpoint).
type Preset string

const (
	PresetGeneric   Preset = "generic"
	PresetSplunk    Preset = "splunk"
	PresetSentinel  Preset = "sentinel"
	PresetElastic   Preset = "elastic"
	PresetChronicle Preset = "chronicle"
)

// ParsePreset validates a preset name.
func ParsePreset(s string) (Preset, bool) {
	switch p := Preset(strings.ToLower(strings.TrimSpace(s))); p {
	case PresetGeneric, PresetSplunk, PresetSentinel, PresetElastic, PresetChronicle:
		return p, true
	default:
		return "", false
	}
}

// DefaultFormat is the format a preset's SIEM parses natively (used when the
// operator doesn't pin one): Elastic → ECS, Chronicle → OTLP, others → CEF.
func (p Preset) DefaultFormat() string {
	switch p {
	case PresetElastic:
		return "ecs"
	case PresetChronicle:
		return "otlp"
	default:
		return "cef"
	}
}

// authHeader returns the Authorization header for a preset's token (Splunk HEC
// uses "Splunk", Elastic uses "ApiKey", the rest use Bearer).
func (p Preset) authHeader(token string) (name, value string) {
	if token == "" {
		return "", ""
	}
	switch p {
	case PresetSplunk:
		return "Authorization", "Splunk " + token
	case PresetElastic:
		return "Authorization", "ApiKey " + token
	default:
		return "Authorization", "Bearer " + token
	}
}

// HTTPSender posts each record to a SIEM's HTTP ingest endpoint over hardened TLS.
type HTTPSender struct {
	url         string
	contentType string
	authName    string
	authValue   string
	client      Doer
}

// NewHTTPSender builds a preset-aware HTTP sender. A nil client uses the hardened
// (cert-validating) HTTP client.
func NewHTTPSender(preset Preset, endpoint, token, contentType string, client Doer) *HTTPSender {
	if client == nil {
		client = crypto.HardenedHTTPClient(15 * time.Second)
	}
	name, value := preset.authHeader(token)
	return &HTTPSender{url: endpoint, contentType: contentType, authName: name, authValue: value, client: client}
}

func (h *HTTPSender) Send(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", h.contentType)
	req.Header.Set("User-Agent", "netctl-siem")
	if h.authName != "" {
		req.Header.Set(h.authName, h.authValue)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("siem: %s returned status %d", h.url, resp.StatusCode)
	}
	return nil
}
