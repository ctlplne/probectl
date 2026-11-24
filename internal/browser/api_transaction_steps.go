// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	Request       Action = "request"
	Capture       Action = "capture"
	AssertJSON    Action = "assert_json"
	AssertLatency Action = "assert_latency"
)

type APIRequestStep struct {
	Method   string              `json:"method"`
	Headers  map[string][]string `json:"headers,omitempty"`
	Body     *string             `json:"body,omitempty"`
	JSONBody json.RawMessage     `json:"json_body,omitempty"`
}

type APICaptureStep struct {
	Name     string `json:"name"`
	JSONPath string `json:"json_path,omitempty"`
	Header   string `json:"header,omitempty"`
	Regex    string `json:"regex,omitempty"`
	Group    *int   `json:"group,omitempty"`
}

type APIJSONAssertion struct {
	Path     string          `json:"path"`
	Operator string          `json:"operator"`
	Expected json.RawMessage `json:"expected,omitempty"`
}

type APILatencyAssertion struct {
	MaximumMS int64 `json:"maximum_ms"`
}

func (s Script) IsAPITransaction() bool {
	for _, step := range s.Steps {
		if apiAction(step.Action) || step.APIRequest != nil || step.APICapture != nil || step.APIJSON != nil || step.APILatency != nil {
			return true
		}
	}
	return false
}

func apiAction(action Action) bool {
	switch action {
	case Request, Capture, AssertJSON, AssertLatency:
		return true
	default:
		return false
	}
}

func validateAPITransactionSteps(s Script) error {
	seenCapture := make(map[string]bool)
	hasRequested := false
	for i, step := range s.Steps {
		if err := validateAPITransactionStep(step, hasRequested); err != nil {
			return fmt.Errorf("browser: API transaction step %d: %w", i+1, err)
		}
		if step.Action == Request {
			hasRequested = true
		}
		if step.Action == Capture {
			name := step.APICapture.Name
			if seenCapture[name] {
				return fmt.Errorf("browser: API transaction step %d: capture alias is already defined", i+1)
			}
			seenCapture[name] = true
		}
	}
	return nil
}

func validateAPITransactionStep(step Step, hasRequested bool) error {
	if step.Action != Request && !hasRequested {
		return errors.New("an API request must precede captures and assertions")
	}
	count := 0
	for _, supplied := range []bool{step.APIRequest != nil, step.APICapture != nil, step.APIJSON != nil, step.APILatency != nil} {
		if supplied {
			count++
		}
	}
	if apiAction(step.Action) && count != 1 || !apiAction(step.Action) && count != 0 {
		return errors.New("API action fields do not match the action")
	}
	switch step.Action {
	case Request:
		return validateAPIRequest(step.URL, step.APIRequest)
	case Capture:
		return validateAPICapture(step.APICapture)
	case AssertJSON:
		return validateAPIJSONAssertion(step.APIJSON)
	case AssertLatency:
		if step.APILatency == nil || step.APILatency.MaximumMS <= 0 || step.APILatency.MaximumMS > math.MaxInt64/int64(time.Millisecond) {
			return errors.New("latency maximum must be a positive representable number of milliseconds")
		}
	case AssertStatus, AssertText:
	default:
		return errors.New("this action is unavailable in an API transaction")
	}
	return nil
}

func validateAPIRequest(endpoint string, request *APIRequestStep) error {
	if request == nil || request.Method == "" || !httpguts.ValidHeaderFieldName(request.Method) {
		return errors.New("request requires a valid HTTP method")
	}
	target, err := url.Parse(endpoint)
	if err != nil || strings.Contains(endpoint, "${") || target.User != nil || target.Opaque != "" || target.Fragment != "" ||
		(target.IsAbs() && (target.Hostname() == "" || target.Scheme != "http" && target.Scheme != "https")) ||
		(!target.IsAbs() && target.Host != "") {
		return errors.New("request URL must be a literal HTTP endpoint or relative path")
	}
	if request.Body != nil && len(request.JSONBody) != 0 || len(request.JSONBody) != 0 && !json.Valid(request.JSONBody) {
		return errors.New("request must have one valid body representation")
	}
	names := make(map[string]bool, len(request.Headers))
	for key, values := range request.Headers {
		canonical := http.CanonicalHeaderKey(key)
		if !httpguts.ValidHeaderFieldName(key) || names[canonical] || blockedAPIHeader(canonical) || len(values) == 0 {
			return errors.New("request has an invalid, duplicate or transport-owned header")
		}
		names[canonical] = true
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) || (credentialAPIHeader(canonical) && !validAPICredentialValue(canonical, value)) {
				return errors.New("request contains an invalid header value")
			}
		}
	}
	return nil
}

func credentialAPIHeader(canonical string) bool {
	switch canonical {
	case "Authorization", "Cookie", "X-Api-Key", "X-Auth-Token":
		return true
	default:
		return false
	}
}

// Known credential headers accept references and the literal wire syntax
// needed to carry them. An unrelated or unfinished reference cannot make a
// stored literal credential valid.
func validAPICredentialValue(header, value string) bool {
	value = strings.TrimSpace(value)
	switch header {
	case "Authorization":
		if scheme, credential, ok := strings.Cut(value, " "); ok {
			return httpguts.ValidHeaderFieldName(scheme) && wholeAPIValueReference(strings.TrimSpace(credential))
		}
	case "Cookie":
		if wholeAPIValueReference(value) {
			return true
		}
		for pair := range strings.SplitSeq(value, ";") {
			name, credential, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || !httpguts.ValidHeaderFieldName(name) || !wholeAPIValueReference(credential) {
				return false
			}
		}
		return true
	}
	return wholeAPIValueReference(value)
}

func wholeAPIValueReference(value string) bool {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return false
	}
	_, err := parseAPIValueReference(value[2 : len(value)-1])
	return err == nil
}

func blockedAPIHeader(canonical string) bool {
	switch canonical {
	case "Host", "Content-Length", "Transfer-Encoding", "Trailer", "Connection", "Upgrade", "Proxy-Connection", "Proxy-Authorization":
		return true
	default:
		return false
	}
}

func validateAPICapture(capture *APICaptureStep) error {
	if capture == nil || !validAPIAlias(capture.Name) {
		return errors.New("capture requires a valid alias")
	}
	sources := 0
	for _, choice := range []string{capture.JSONPath, capture.Header, capture.Regex} {
		if choice != "" {
			sources++
		}
	}
	if sources != 1 || capture.Group != nil && capture.Regex == "" {
		return errors.New("capture requires exactly one JSON path, header or regular expression")
	}
	if capture.JSONPath != "" {
		if _, err := parseAPIJSONPath(capture.JSONPath); err != nil {
			return err
		}
	}
	if capture.Header != "" && !httpguts.ValidHeaderFieldName(capture.Header) {
		return errors.New("capture requires a valid response header")
	}
	if capture.Regex != "" {
		expression, err := regexp.Compile(capture.Regex)
		if err != nil {
			return errors.New("capture regular expression is invalid")
		}
		if group := capture.group(); group < 0 || group > expression.NumSubexp() {
			return errors.New("capture group is outside the regular expression")
		}
	}
	return nil
}

func (c APICaptureStep) group() int {
	if c.Group != nil {
		return *c.Group
	}
	return 0
}

func validateAPIJSONAssertion(assertion *APIJSONAssertion) error {
	if assertion == nil || strings.TrimSpace(assertion.Path) == "" {
		return errors.New("JSON assertion requires a path")
	}
	if _, err := parseAPIJSONPath(assertion.Path); err != nil {
		return err
	}
	switch assertion.Operator {
	case "exists", "missing":
		if len(assertion.Expected) != 0 {
			return errors.New("existence assertion takes no expected value")
		}
	case "eq", "ne":
		if !json.Valid(assertion.Expected) {
			return errors.New("equality assertion requires a valid JSON value")
		}
	default:
		return errors.New("JSON assertion operator is invalid")
	}
	return nil
}
