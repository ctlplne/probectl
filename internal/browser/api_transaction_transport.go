// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/ctlplne/probectl/internal/crypto"
)

var (
	errAPIEndpoint = errors.New("transaction endpoint is invalid or unavailable")
	errAPIRedirect = errors.New("transaction redirect refused by origin policy")
	errAPIHeader   = errors.New("rendered transaction header is invalid")
	errAPIBody     = errors.New("transaction JSON body is invalid")
)

// WithAPITransactionCAFile trusts the operator-supplied app CA bundle for the
// API driver. Hostname verification and the API destination guard still apply.
func WithAPITransactionCAFile(caFile string) (HTTPDriverOption, error) {
	config, err := crypto.HardenedClientTLSConfigWithCAFile(caFile)
	if err != nil {
		return nil, errors.New("browser: API transaction CA bundle is unavailable or invalid")
	}
	return func(driver *HTTPDriver) {
		if driver.guard != nil {
			transport := guardedTransport(driver.guard)
			transport.TLSClientConfig = config.Clone()
			driver.transport = transport
		}
	}, nil
}

func resolveAPIEndpoint(base, endpoint string) (*url.URL, string, error) {
	if strings.Contains(endpoint, "${") || strings.Contains(base, "${") {
		return nil, "", errAPIEndpoint
	}
	target, err := url.Parse(endpoint)
	if err != nil || target.User != nil || target.Fragment != "" || target.Opaque != "" {
		return nil, "", errAPIEndpoint
	}
	if !target.IsAbs() {
		if target.Host != "" {
			return nil, "", errAPIEndpoint
		}
		parent, err := url.Parse(base)
		if err != nil || apiOrigin(parent) == "" {
			return nil, "", errAPIEndpoint
		}
		target = parent.ResolveReference(target)
	}
	origin := apiOrigin(target)
	if origin == "" {
		return nil, "", errAPIEndpoint
	}
	return target, origin, nil
}

// apiOrigin strips paths and queries so metadata never includes request data.
// It also normalizes default ports for origin checks on redirects and captures.
func apiOrigin(target *url.URL) string {
	if target == nil || target.User != nil || target.Opaque != "" || target.Fragment != "" ||
		(target.Scheme != "https" && target.Scheme != "http") {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" || strings.Contains(host, "%") {
		return ""
	}
	port := target.Port()
	if port == "" {
		port = "443"
		if target.Scheme == "http" {
			port = "80"
		}
	}
	return target.Scheme + "://" + net.JoinHostPort(host, port)
}

func apiRedirectGuard(guard TargetGuard) func(*http.Request, []*http.Request) error {
	return func(next *http.Request, via []*http.Request) error {
		if len(via) == 0 || len(via) >= 10 {
			return errAPIRedirect
		}
		origin := apiOrigin(next.URL)
		if origin == "" || origin != apiOrigin(via[0].URL) {
			return errAPIRedirect
		}
		if guard != nil && guard.CheckHost(next.URL.Hostname()) != nil {
			return errAPIRedirect
		}
		return nil
	}
}

func renderAPIRequest(ctx context.Context, target *url.URL, spec APIRequestStep, values apiTransactionValues, budget int) (*http.Request, error) {
	remaining := budget
	headers := make(http.Header, len(spec.Headers))
	for name, list := range spec.Headers {
		if credentialAPIHeader(http.CanonicalHeaderKey(name)) && !strings.HasPrefix(values.origin, "https://") {
			return nil, errAPIHeader
		}
		for _, template := range list {
			remaining -= len(name)
			rendered, err := values.render(ctx, template, remaining)
			if err != nil {
				return nil, err
			}
			if !httpguts.ValidHeaderFieldValue(rendered) {
				return nil, errAPIHeader
			}
			headers.Add(name, rendered)
			remaining -= len(rendered)
		}
	}
	var body []byte
	if spec.Body != nil {
		text, err := values.render(ctx, *spec.Body, remaining)
		if err != nil {
			return nil, err
		}
		body = []byte(text)
	}
	if len(spec.JSONBody) != 0 {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(spec.JSONBody))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return nil, errAPIBody
		}
		var encoded bytes.Buffer
		if err := appendAPIJSON(ctx, &encoded, value, &values, remaining); err != nil {
			return nil, err
		}
		body = encoded.Bytes()
		if headers.Get("Content-Type") == "" {
			headers.Set("Content-Type", "application/json")
		}
	}
	req, err := http.NewRequestWithContext(ctx, spec.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errAPIEndpoint
	}
	req.Header = headers
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "probectl-browser-synthetic")
	}
	return req, nil
}

func appendAPIJSON(ctx context.Context, dst *bytes.Buffer, node any, values *apiTransactionValues, limit int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	appendText := func(text string) error {
		if len(text) > limit-dst.Len() {
			return errAPIRequestValueTooLarge
		}
		dst.WriteString(text)
		return nil
	}
	switch value := node.(type) {
	case map[string]any:
		if err := appendText("{"); err != nil {
			return err
		}
		for i, key := range slices.Sorted(maps.Keys(value)) {
			if i != 0 {
				if err := appendText(","); err != nil {
					return err
				}
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return errAPIBody
			}
			if err := appendText(string(encoded) + ":"); err != nil {
				return err
			}
			if err := appendAPIJSON(ctx, dst, value[key], values, limit); err != nil {
				return err
			}
		}
		return appendText("}")
	case []any:
		if err := appendText("["); err != nil {
			return err
		}
		for i, element := range value {
			if i != 0 {
				if err := appendText(","); err != nil {
					return err
				}
			}
			if err := appendAPIJSON(ctx, dst, element, values, limit); err != nil {
				return err
			}
		}
		return appendText("]")
	case string:
		if values != nil {
			encoded, err := values.renderJSONString(ctx, value, limit-dst.Len())
			if err != nil {
				return err
			}
			dst.Write(encoded)
			return nil
		}
		if len(value) > limit-dst.Len() {
			return errAPIRequestValueTooLarge
		}
		return appendAPIJSONScalar(value, appendText)
	default:
		return appendAPIJSONScalar(value, appendText)
	}
}

func appendAPIJSONScalar(value any, appendText func(string) error) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errAPIBody
	}
	return appendText(string(encoded))
}

var (
	errAPIResponseTooLarge = errors.New("transaction response exceeds its limit")
	errAPIResponseRead     = errors.New("transaction response could not be read completely")
	errAPIRequestFailed    = errors.New("transaction request failed")
)

// requestAPI uses the same transport and waterfall tracing as the existing HTTP
// canary. Its returned error is safe for step results, logs and telemetry.
func (d *HTTPDriver) requestAPI(ctx context.Context, clients map[string]*http.Client, base string, step Step,
	values apiTransactionValues, start time.Time, remaining int) (ResourceTiming, httpResp, int, error) {
	target, origin, err := resolveAPIEndpoint(base, step.URL)
	if err != nil || d.guard == nil || d.guard.CheckHost(target.Hostname()) != nil {
		return ResourceTiming{}, httpResp{}, remaining, errAPIEndpoint
	}
	values.origin = origin
	req, err := renderAPIRequest(ctx, target, *step.APIRequest, values, remaining)
	if err != nil {
		return ResourceTiming{}, httpResp{}, remaining, err
	}
	remaining64 := int64(remaining) - int64(len(target.RequestURI())) - req.ContentLength - apiHeaderSize(req.Header)
	if remaining64 < 0 {
		return ResourceTiming{}, httpResp{}, remaining, errAPIRequestValueTooLarge
	}
	client := clients[origin]
	if client == nil {
		jar, _ := cookiejar.New(nil)
		client = crypto.HardenedHTTPClient(0)
		client.Transport = d.transport
		client.Jar = jar
		client.CheckRedirect = apiRedirectGuard(d.guard)
		clients[origin] = client
	}
	timing, response, err := d.exchange(client, req, ResourceTiming{Method: req.Method, URL: origin}, start, remaining64, true)
	if err != nil {
		switch {
		case errors.Is(err, errAPIResponseTooLarge), errors.Is(err, errAPIResponseRead):
			return timing, httpResp{}, 0, err
		case errors.Is(err, errAPIRedirect):
			return timing, httpResp{}, int(remaining64), errAPIRedirect
		case ctx.Err() != nil:
			return timing, httpResp{}, int(remaining64), ctx.Err()
		default:
			return timing, httpResp{}, int(remaining64), errAPIRequestFailed
		}
	}
	remaining64 -= timing.SizeBytes + apiHeaderSize(response.header)
	return timing, response, int(remaining64), nil
}

func apiHeaderSize(header http.Header) int64 {
	var total int64
	for name, values := range header {
		for _, value := range values {
			total += int64(len(name)) + int64(len(value)) + 4 // colon, space, CRLF
		}
	}
	return total
}

// CanonicalAPISecretOrigin validates the agent-owned credential destination.
func CanonicalAPISecretOrigin(raw string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "https" || (target.Path != "" && target.Path != "/") ||
		target.RawPath != "" || target.RawQuery != "" || target.ForceQuery || strings.Contains(raw, "#") {
		return "", errAPIEndpoint
	}
	if origin := apiOrigin(target); origin != "" {
		return origin, nil
	}
	return "", errAPIEndpoint
}

// APIResultTarget reports the script's original origin. It is shared by the
// agent and the receiver so result identity stays stable through later steps.
func (s Script) APIResultTarget() (string, error) {
	_, origin, err := resolveAPIEndpoint(s.StartURL, "")
	return origin, err
}

// ValidateAPIEndpoints checks literal destinations without opening a connection.
// The runtime repeats the target check on each request, redirect and dial.
func (s Script) ValidateAPIEndpoints(guard TargetGuard) error {
	if _, err := s.APIResultTarget(); err != nil {
		return err
	}
	for _, step := range s.Steps {
		if step.Action != Request {
			continue
		}
		target, _, err := resolveAPIEndpoint(s.StartURL, step.URL)
		if err != nil || (guard != nil && guard.CheckHost(target.Hostname()) != nil) {
			return errAPIEndpoint
		}
	}
	return nil
}
