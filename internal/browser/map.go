// SPDX-License-Identifier: LicenseRef-probectl-TBD

package browser

import (
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

// ToCanaryResult maps a browser Result onto the canonical canary.Result envelope
// so a transaction run flows through the same pipeline → TSDB / incidents path as
// every other canary (type "browser"). Numeric timings become Metrics; the script
// name, error, and screenshot reference become Attributes (the screenshot blob
// itself lives in the object store, referenced by key).
func (r Result) ToCanaryResult() canary.Result {
	metrics := map[string]float64{
		"transaction.total_ms":  float64(r.TotalMs),
		"transaction.steps":     float64(len(r.Steps)),
		"transaction.resources": float64(len(r.Waterfall)),
	}
	if n := failedSteps(r.Steps); n > 0 {
		metrics["transaction.failed_steps"] = float64(n)
	}
	if !r.DOM.empty() {
		metrics["dom.content_loaded_ms"] = float64(r.DOM.DOMContentLoadedMs)
		metrics["dom.load_ms"] = float64(r.DOM.LoadMs)
		metrics["paint.first_ms"] = float64(r.DOM.FirstPaintMs)
		metrics["paint.first_contentful_ms"] = float64(r.DOM.FirstContentfulPaintMs)
	}

	attrs := map[string]string{
		"browser.script":     r.Script,
		"browser.step_count": strconv.Itoa(len(r.Steps)),
	}
	for i, step := range r.Steps {
		prefix := "browser.step." + strconv.Itoa(i)
		metrics["transaction.step."+strconv.Itoa(i)+".duration_ms"] = float64(step.DurationMs)
		if step.Name != "" {
			attrs[prefix+".name"] = step.Name
		}
		attrs[prefix+".action"] = string(step.Action)
		attrs[prefix+".success"] = strconv.FormatBool(step.Success)
		if step.Detail != "" {
			attrs[prefix+".detail"] = step.Detail
		}
	}
	if r.Screenshot != nil {
		attrs["browser.screenshot.key"] = r.Screenshot.Key
		attrs["browser.screenshot.content_type"] = r.Screenshot.ContentType
	}
	if !r.Success && r.Error != "" {
		attrs["browser.error"] = r.Error
	}

	return canary.Result{
		Type:       "browser",
		Target:     r.Target,
		Success:    r.Success,
		Error:      r.Error,
		StartedAt:  r.StartedAt,
		Duration:   time.Duration(r.TotalMs) * time.Millisecond,
		Metrics:    metrics,
		Attributes: attrs,
	}
}

func failedSteps(steps []StepResult) int {
	n := 0
	for _, s := range steps {
		if !s.Success {
			n++
		}
	}
	return n
}
