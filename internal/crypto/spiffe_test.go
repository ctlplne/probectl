package crypto

import "testing"

func TestSPIFFERoundTrip(t *testing.T) {
	uri := AgentSPIFFEID("tenant-123", "agent-abc")
	const want = "spiffe://probectl/tenant/tenant-123/agent/agent-abc"
	if uri != want {
		t.Fatalf("AgentSPIFFEID = %q, want %q", uri, want)
	}
	id, err := ParseSPIFFEID(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id.TrustDomain != "probectl" || id.TenantID != "tenant-123" || id.AgentID != "agent-abc" {
		t.Errorf("parsed = %+v", id)
	}
	if id.String() != uri {
		t.Errorf("String() = %q, want %q", id.String(), uri)
	}
}

func TestParseSPIFFEIDErrors(t *testing.T) {
	bad := []string{
		"https://probectl/tenant/x/agent/y", // wrong scheme
		"spiffe://probectl/org/x/agent/y",   // wrong segment label
		"spiffe://probectl/tenant/x",        // too short
	}
	for _, b := range bad {
		if _, err := ParseSPIFFEID(b); err == nil {
			t.Errorf("ParseSPIFFEID(%q) should fail", b)
		}
	}
}
