// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

const defaultAPITransactionBytes = 30 << 20

var (
	errAPIMissingResponse = errors.New("no complete response is available for this step")
	errAPIAssertion       = errors.New("transaction assertion failed")
	errAPICaptureMissing  = errors.New("transaction capture found no value")
)

// WithAPITransactionResources binds an agent-owned admission budget and
// tenant-scoped secret resolver to HTTP API runs. Values live for one run.
func WithAPITransactionResources(maxBytes int, resolve apiSecretResolver) HTTPDriverOption {
	return func(driver *HTTPDriver) {
		if maxBytes > 0 {
			driver.apiBytes = maxBytes
		}
		driver.apiSecret = resolve
	}
}

type apiTransactionRun struct {
	remaining int
	values    apiTransactionValues
	response  *httpResp
	jsonBody  any
	jsonRead  bool
}

func (d *HTTPDriver) runAPITransaction(ctx context.Context, s Script) (RunOutput, error) {
	if err := s.Validate(); err != nil {
		return RunOutput{}, err
	}
	clients := make(map[string]*http.Client)
	run := apiTransactionRun{
		remaining: d.apiBytes,
		values:    apiTransactionValues{secret: d.apiSecret, captures: make(map[string]apiCapturedValue)},
	}
	target, err := s.APIResultTarget()
	if err != nil {
		return RunOutput{}, err
	}
	start := time.Now()
	var steps []StepResult
	var waterfall []ResourceTiming
	for i, step := range s.Steps {
		stepStart := time.Now()
		var detail string
		var err error
		if step.Action == Request {
			run.response, run.jsonBody, run.jsonRead = nil, nil, false
			var timing ResourceTiming
			var response httpResp
			timing, response, run.remaining, err = d.requestAPI(ctx, clients, s.StartURL, step, run.values, start, run.remaining)
			if timing.URL != "" {
				waterfall = append(waterfall, timing)
			}
			if err == nil {
				run.response, run.values.origin = &response, timing.URL
				detail = fmt.Sprintf("HTTP status %d", response.status)
			}
		} else {
			err = run.inspect(ctx, step)
			if err == nil {
				detail = "passed"
			}
		}
		if err != nil {
			detail = err.Error()
		}
		steps = append(steps, StepResult{Name: step.Name, Action: step.Action, Success: err == nil,
			DurationMs: time.Since(stepStart).Milliseconds(), Detail: detail})
		if err != nil && (!step.Optional || ctx.Err() != nil) {
			message := fmt.Sprintf("step %d (%s): %s", i+1, step.Action, detail)
			return RunOutput{Result: d.result(s, target, false, message, start, steps, waterfall)}, ctx.Err()
		}
	}
	return RunOutput{Result: d.result(s, target, true, "", start, steps, waterfall)}, nil
}

func (r *apiTransactionRun) inspect(ctx context.Context, step Step) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.response == nil {
		return errAPIMissingResponse
	}
	switch step.Action {
	case Capture:
		return r.capture(ctx, *step.APICapture)
	case AssertJSON:
		return r.assertJSON(ctx, *step.APIJSON)
	case AssertStatus:
		if step.Status == r.response.status {
			return nil
		}
	case AssertLatency:
		if r.response.elapsed <= time.Duration(step.APILatency.MaximumMS)*time.Millisecond {
			return nil
		}
	case AssertText:
		if bytes.Contains(r.response.body, []byte(step.Value)) {
			return nil
		}
	}
	return errAPIAssertion
}

func (r *apiTransactionRun) selectJSON(ctx context.Context, path string) ([]any, error) {
	segments, err := parseAPIJSONPath(path)
	if err != nil {
		return nil, err
	}
	if !r.jsonRead {
		r.jsonBody, err = decodeAPIJSON(ctx, r.response.body)
		if err != nil {
			return nil, err
		}
		r.jsonRead = true
	}
	return selectAPIJSON(ctx, r.jsonBody, segments, max(r.remaining, len(r.response.body)))
}

func (r *apiTransactionRun) capture(ctx context.Context, capture APICaptureStep) error {
	var captured any
	switch {
	case capture.JSONPath != "":
		values, err := r.selectJSON(ctx, capture.JSONPath)
		if err != nil {
			return err
		}
		switch len(values) {
		case 0:
			return errAPICaptureMissing
		case 1:
			captured = values[0]
		default:
			captured = values
		}
	case capture.Header != "":
		values := r.response.header.Values(capture.Header)
		switch len(values) {
		case 0:
			return errAPICaptureMissing
		case 1:
			captured = values[0]
		default:
			headerValues := make([]any, len(values))
			for i, value := range values {
				headerValues[i] = value
			}
			captured = headerValues
		}
	case capture.Regex != "":
		expression, err := regexp.Compile(capture.Regex)
		if err != nil {
			return errAPICaptureMissing
		}
		match := expression.FindSubmatchIndex(r.response.body)
		group := capture.group() * 2
		if group+1 >= len(match) || match[group] < 0 {
			return errAPICaptureMissing
		}
		captured = string(r.response.body[match[group]:match[group+1]])
	}
	var encoded bytes.Buffer
	if err := appendAPIJSON(ctx, &encoded, captured, nil, r.remaining); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errAPIResponseTooLarge
	}
	r.remaining -= encoded.Len()
	r.values.captures[capture.Name] = apiCapturedValue{value: encoded.Bytes(), origin: r.values.origin}
	return nil
}

func (r *apiTransactionRun) assertJSON(ctx context.Context, assertion APIJSONAssertion) error {
	selected, err := r.selectJSON(ctx, assertion.Path)
	if err != nil {
		return err
	}
	if assertion.Operator == "exists" && len(selected) != 0 || assertion.Operator == "missing" && len(selected) == 0 {
		return nil
	}
	if len(selected) == 0 || assertion.Operator == "exists" || assertion.Operator == "missing" {
		return errAPIAssertion
	}
	expected, err := decodeAPIJSON(ctx, assertion.Expected)
	if err != nil {
		return err
	}
	var got any = selected
	if len(selected) == 1 {
		got = selected[0]
	}
	equal, err := equalAPIJSON(ctx, expected, got)
	if err != nil {
		return err
	}
	if equal == (assertion.Operator == "eq") {
		return nil
	}
	return errAPIAssertion
}
