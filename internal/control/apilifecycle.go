// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"fmt"
	"net/http"
	"time"
)

const apiLifecycleDateLayout = "2006-01-02"

type apiLifecycle struct {
	Stage             string
	DeprecatedAt      string
	Sunset            string
	LTSUntil          string
	ReplacementMethod string
	ReplacementPath   string
	Policy            string
}

var deleteAgentLifecycle = apiLifecycle{
	Stage:             "deprecated",
	DeprecatedAt:      "2026-06-19",
	Sunset:            "2027-06-19",
	LTSUntil:          "2027-06-19",
	ReplacementMethod: http.MethodPost,
	ReplacementPath:   "/v1/agents/{id}/revoke",
	Policy:            "Deprecated /v1 operations stay available for at least 12 months, carry Deprecation/Sunset headers at runtime, and remain documented in OpenAPI until removal.",
}

func apiLifecycleFor(method, pattern string) (apiLifecycle, bool) {
	switch method + " " + pattern {
	case http.MethodDelete + " /v1/agents/{id}":
		return deleteAgentLifecycle, true
	default:
		return apiLifecycle{}, false
	}
}

func (l apiLifecycle) wrap(next apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		l.applyHeaders(w.Header())
		return next(w, r)
	}
}

func (l apiLifecycle) applyHeaders(h http.Header) {
	if v := structuredDate(l.DeprecatedAt); v != "" {
		h.Set("Deprecation", v)
	}
	if v := httpDate(l.Sunset); v != "" {
		h.Set("Sunset", v)
	}
	if l.ReplacementMethod != "" && l.ReplacementPath != "" {
		h.Set("X-Probectl-API-Replacement", l.ReplacementMethod+" "+l.ReplacementPath)
		h.Add("Link", fmt.Sprintf("<%s>; rel=\"successor-version\"; templated=\"true\"", l.ReplacementPath))
	}
	if l.LTSUntil != "" {
		h.Set("X-Probectl-API-LTS-Until", l.LTSUntil)
	}
	h.Add("Link", "</openapi.json>; rel=\"deprecation\"; type=\"application/vnd.oai.openapi+json\"")
}

func structuredDate(date string) string {
	t, err := time.Parse(apiLifecycleDateLayout, date)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("@%d", t.Unix())
}

func httpDate(date string) string {
	t, err := time.Parse(apiLifecycleDateLayout, date)
	if err != nil {
		return ""
	}
	return t.UTC().Format(http.TimeFormat)
}
