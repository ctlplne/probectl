// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package siem

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
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

// Auth schemes an operator can pin with PROBECTL_SIEM_AUTH_SCHEME when their
// target does not use the preset's default (DPR-115). The reason this exists:
// the elastic preset always sent "ApiKey", which Elasticsearch understands and
// OpenSearch — the self-hosted target most operators actually run, and the one
// this project's own docs name — does not. It authenticates with HTTP Basic,
// so an unconfigurable scheme meant the shipped preset could not reach it.
const (
	AuthSchemeDefault = ""       // the preset's own scheme
	AuthSchemeAPIKey  = "apikey" // Authorization: ApiKey <token>
	AuthSchemeBearer  = "bearer" // Authorization: Bearer <token>
	AuthSchemeSplunk  = "splunk" // Authorization: Splunk <token>
	AuthSchemeBasic   = "basic"  // Authorization: Basic base64(token); token is user:password
	AuthSchemeNone    = "none"   // no Authorization header, whatever the token is
)

// authHeader returns the Authorization header for a preset's token (Splunk HEC
// uses "Splunk", Elastic uses "ApiKey", the rest use Bearer), unless the
// operator pinned a scheme.
func (p Preset) authHeader(token, scheme string) (name, value string) {
	if token == "" || scheme == AuthSchemeNone {
		return "", ""
	}
	switch strings.ToLower(scheme) {
	case AuthSchemeAPIKey:
		return "Authorization", "ApiKey " + token
	case AuthSchemeBearer:
		return "Authorization", "Bearer " + token
	case AuthSchemeSplunk:
		return "Authorization", "Splunk " + token
	case AuthSchemeBasic:
		// The token is user:password; it is base64'd here so an operator never
		// has to pre-encode a credential into their configuration.
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
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
// scheme pins the Authorization scheme (DPR-115); empty keeps the preset's own.
func NewHTTPSender(preset Preset, endpoint, token, scheme, contentType string, client Doer) *HTTPSender {
	if client == nil {
		client = crypto.HardenedHTTPClient(15 * time.Second)
	}
	name, value := preset.authHeader(token, scheme)
	return &HTTPSender{url: endpoint, contentType: contentType, authName: name, authValue: value, client: client}
}

func (h *HTTPSender) Send(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", h.contentType)
	req.Header.Set("User-Agent", "probectl-siem")
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
