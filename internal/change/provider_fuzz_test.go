// SPDX-License-Identifier: LicenseRef-probectl-TBD

package change

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func FuzzChangeNormalize(f *testing.F) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for _, seed := range changeNormalizeSeeds() {
		f.Add(seed.provider, seed.event, seed.body)
	}

	f.Fuzz(func(t *testing.T, providerName, eventName string, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		p := changeFuzzProvider(providerName)
		events, err := p.Normalize(body, changeFuzzHeader(p.Name(), eventName), now)
		if err != nil {
			if !errors.Is(err, ErrNormalize) {
				t.Fatalf("%s returned unexpected error: %v", p.Name(), err)
			}
			return
		}
		for _, ev := range events {
			if ev.Source == "" {
				t.Fatalf("%s accepted event without source: %+v", p.Name(), ev)
			}
			if ev.Kind == "" {
				t.Fatalf("%s accepted event without kind: %+v", p.Name(), ev)
			}
			if ev.OccurredAt.IsZero() {
				t.Fatalf("%s accepted event without occurred_at default: %+v", p.Name(), ev)
			}
			if ev.TenantID != "" {
				t.Fatalf("%s accepted payload-selected tenant_id %q", p.Name(), ev.TenantID)
			}
		}
	})
}

func changeFuzzProvider(name string) Provider {
	if p, ok := ProviderByName(name); ok {
		return p
	}
	names := ProviderNames()
	if len(name) == 0 {
		p, _ := ProviderByName(names[0])
		return p
	}
	p, _ := ProviderByName(names[int(name[0])%len(names)])
	return p
}

func changeFuzzHeader(provider, event string) http.Header {
	h := http.Header{}
	switch provider {
	case ProviderGitHub:
		if event = strings.TrimSpace(event); event == "" {
			event = "push"
		}
		h.Set(githubEventHeader, event)
	case ProviderGitLab:
		if event = strings.TrimSpace(event); event == "" {
			event = "Push Hook"
		}
		h.Set(gitlabEventHeader, event)
	}
	return h
}

func changeNormalizeSeeds() []struct {
	provider string
	event    string
	body     []byte
} {
	return []struct {
		provider string
		event    string
		body     []byte
	}{
		{provider: ProviderGeneric, body: []byte(`{"kind":"deploy","title":"deploy api","target":"api.example.com","actor":"ci","ref":"abc123","tenant_id":"evil"}`)},
		{provider: ProviderGeneric, body: []byte(`{"events":[{"title":"a","target":"x"},{"target":"no-title"}]}`)},
		{provider: ProviderGeneric, body: []byte(`[{"title":"b"},{"title":"c"}]`)},
		{provider: ProviderGeneric, body: []byte(`not json`)},
		{provider: ProviderGeneric, body: []byte(strings.Repeat("x", 4096))},
		{provider: ProviderGitHub, event: "push", body: []byte(`{"ref":"refs/heads/main","compare":"https://gh/compare","pusher":{"name":"alice"},"repository":{"full_name":"acme/shop"},"head_commit":{"id":"deadbeef","message":"fix checkout\nbody","url":"https://gh/c/deadbeef"},"commits":[{"id":"deadbeef"}]}`)},
		{provider: ProviderGitHub, event: "deployment", body: []byte(`{"deployment":{"environment":"production","sha":"cafe","environment_url":"https://api.example.com/","creator":{"login":"bob"}},"repository":{"full_name":"acme/api"}}`)},
		{provider: ProviderGitHub, event: "ping", body: []byte(`{"zen":"hi"}`)},
		{provider: ProviderGitLab, event: "Push Hook", body: []byte(`{"ref":"refs/heads/main","user_name":"carol","checkout_sha":"99aa","project":{"path_with_namespace":"team/svc","web_url":"https://gl/team/svc"},"commits":[{"message":"bump","url":"https://gl/c/99aa"}]}`)},
		{provider: ProviderGitLab, event: "Deployment Hook", body: []byte(`{"environment":"prod","deployable_url":"https://svc.example.net/app","short_sha":"99aa","status":"success","user":{"name":"carol"},"project":{"path_with_namespace":"team/svc"}}`)},
		{provider: ProviderGitLab, event: "System Hook", body: []byte(`{"event_name":"project_create"}`)},
	}
}
