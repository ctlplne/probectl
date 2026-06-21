// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/ee/whitelabel"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
)

func FuzzProviderDecode(f *testing.F) {
	for _, seed := range providerDecodeSeeds() {
		f.Add(seed.family, seed.body)
	}

	f.Fuzz(func(_ *testing.T, family string, body []byte) {
		if len(body) > 1<<20+1 {
			return
		}
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/fuzz", bytes.NewReader(body))
		_ = decode(req, providerDecodeTarget(family))
	})
}

func providerDecodeTarget(family string) any {
	normalized := strings.ToLower(strings.TrimSpace(family))
	if normalized == "" {
		normalized = "bootstrap"
	}
	switch normalized {
	case "bootstrap":
		return &providerBootstrapInput{}
	case "enroll-start":
		return &providerTokenInput{}
	case "enroll-complete":
		return &providerEnrollCompleteInput{}
	case "login":
		return &providerLoginInput{}
	case "operator-create":
		return &providerCreateOperatorInput{}
	case "operator-status":
		return &providerStatusInput{}
	case "provision":
		return &providerProvisionInput{}
	case "configure":
		return &providerConfigureInput{}
	case "break-glass":
		return &providerBreakGlassInput{}
	case "consent":
		return &providerConsentInput{}
	case "erase":
		return &providerEraseInput{}
	case "governance":
		return &providerGovernanceInput{}
	case "quota":
		return &providerQuotaInput{}
	case "branding":
		return &whitelabel.Record{}
	case "fairness":
		return &fairness.Policy{}
	default:
		families := providerDecodeFamilies()
		return providerDecodeTarget(families[int(normalized[0])%len(families)])
	}
}

func providerDecodeFamilies() []string {
	return []string{
		"bootstrap",
		"enroll-start",
		"enroll-complete",
		"login",
		"operator-create",
		"operator-status",
		"provision",
		"configure",
		"break-glass",
		"consent",
		"erase",
		"governance",
		"quota",
		"branding",
		"fairness",
	}
}

func providerDecodeSeeds() []struct {
	family string
	body   []byte
} {
	return []struct {
		family string
		body   []byte
	}{
		{"bootstrap", []byte(`{"token":"root","email":"ops@example.com","name":"Ops"}`)},
		{"enroll-start", []byte(`{"token":"enroll"}`)},
		{"enroll-complete", []byte(`{"token":"enroll","password":"correct horse battery staple","totp":"123456"}`)},
		{"login", []byte(`{"email":"ops@example.com","password":"pw","totp":"123456"}`)},
		{"operator-create", []byte(`{"email":"new@example.com","name":"New Operator","role":"operator"}`)},
		{"operator-status", []byte(`{"status":"disabled"}`)},
		{"provision", []byte(`{"slug":"tenant-a","name":"Tenant A","isolation_model":"pooled","residency":"us"}`)},
		{"configure", []byte(`{"name":"Tenant A Renamed"}`)},
		{"break-glass", []byte(`{"tenant_id":"t-1","reason":"incident review","ttl_minutes":30}`)},
		{"consent", []byte(`{"decision":"approve"}`)},
		{"erase", []byte(`{"confirm":"tenant-a"}`)},
		{"governance", []byte(`{"classifications":{"email":"pii"},"redact_from":"pii","redact_export":true,"ai_remote_egress":false}`)},
		{"quota", []byte(`{"max_agents":10,"max_tests":50}`)},
		{"branding", []byte(`{"product_name":"probectl","token_overrides":{"color.bg":"#000000"},"email_from_name":"probectl"}`)},
		{"fairness", []byte(`{"results_per_sec":100,"flow_events_per_sec":200,"query_concurrency":4,"weight":1}`)},
		{"login", []byte(`{"email":"ops@example.com","extra":true}`)},
		{"quota", []byte(`not json`)},
	}
}

type providerBootstrapInput struct{ Token, Email, Name string }

type providerTokenInput struct {
	Token string `json:"token"`
}

type providerEnrollCompleteInput struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

type providerLoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

type providerCreateOperatorInput struct{ Email, Name, Role string }

type providerStatusInput struct {
	Status string `json:"status"`
}

type providerProvisionInput struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	IsolationModel string `json:"isolation_model"`
	Residency      string `json:"residency"`
}

type providerConfigureInput struct {
	Name string `json:"name"`
}

type providerBreakGlassInput struct {
	TenantID   string `json:"tenant_id"`
	Reason     string `json:"reason"`
	TTLMinutes int    `json:"ttl_minutes"`
}

type providerConsentInput struct {
	Decision string `json:"decision"`
}

type providerEraseInput struct {
	Confirm string `json:"confirm"`
}

type providerGovernanceInput struct {
	Overrides      map[string]string `json:"classifications"`
	RedactFrom     string            `json:"redact_from"`
	RedactExport   bool              `json:"redact_export"`
	AIRemoteEgress bool              `json:"ai_remote_egress"`
}

type providerQuotaInput struct {
	MaxAgents *int `json:"max_agents"`
	MaxTests  *int `json:"max_tests"`
}
