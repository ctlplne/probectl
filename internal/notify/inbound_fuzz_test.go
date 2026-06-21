// SPDX-License-Identifier: LicenseRef-probectl-TBD

package notify

import (
	"strings"
	"testing"
)

func FuzzParseInbound(f *testing.F) {
	for _, seed := range inboundParseSeeds() {
		f.Add(seed.provider, seed.body)
	}

	f.Fuzz(func(t *testing.T, provider string, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		result, ok := ParseInbound(inboundFuzzProvider(provider), body)
		if !ok {
			return
		}
		if strings.TrimSpace(result.ExternalRef) == "" {
			t.Fatalf("accepted inbound webhook without external ref: %+v", result)
		}
		if result.Resolved && result.Acked {
			t.Fatalf("accepted mutually-exclusive resolved+acked state: %+v", result)
		}
	})
}

func inboundFuzzProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "servicenow", "jira", "pagerduty", "opsgenie", "slack", "teams", "generic":
		return provider
	}
	names := []string{"servicenow", "jira", "pagerduty", "opsgenie", "generic"}
	if len(provider) == 0 {
		return names[0]
	}
	return names[int(provider[0])%len(names)]
}

func inboundParseSeeds() []struct {
	provider string
	body     []byte
} {
	return []struct {
		provider string
		body     []byte
	}{
		{provider: "servicenow", body: []byte(`{"sys_id":"sys-9","number":"INC1","state":"6"}`)},
		{provider: "servicenow", body: []byte(`{"sys_id":"sys-9","state":"2"}`)},
		{provider: "jira", body: []byte(`{"issue":{"key":"OPS-1","fields":{"status":{"statusCategory":{"key":"done"}}}}}`)},
		{provider: "jira", body: []byte(`{"issue":{"key":"OPS-2","fields":{"status":{"statusCategory":{"key":"indeterminate"}}}}}`)},
		{provider: "pagerduty", body: []byte(`{"external_ref":"probectl-i1","status":"resolved"}`)},
		{provider: "opsgenie", body: []byte(`{"external_ref":"probectl-i2","status":"acknowledged"}`)},
		{provider: "generic", body: []byte(`{"external_ref":"probectl-i3","status":"open"}`)},
		{provider: "jira", body: []byte(`not json`)},
		{provider: "servicenow", body: []byte(strings.Repeat("x", 4096))},
	}
}
