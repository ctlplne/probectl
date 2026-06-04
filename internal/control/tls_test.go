package control

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// The TLS posture consumer analyzes an HTTPS result's CAPTURED TLS into a
// threat-plane signal — an expired cert becomes a critical signal carrying a
// certctl handoff — and ignores non-HTTPS results.
func TestTLSPostureConsumerSignals(t *testing.T) {
	_, der, err := crypto.GenerateTestCert(crypto.TestCertOptions{
		CommonName: "old.example", DNSNames: []string{"old.example"}, NotAfter: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	cs := NewTLSPostureConsumer(nil, nil,
		BuildTLSAnalyzer(&config.Config{CertctlURL: "https://certctl.example", TLSExpiryWarning: 21 * 24 * time.Hour}), nil)

	r := &resultv1.Result{
		TenantId:          "t",
		CanaryType:        "http",
		ServerAddress:     "old.example",
		StartTimeUnixNano: time.Now().UnixNano(),
		Attributes: map[string]string{
			"tls.protocol.version": "1.3",
			"tls.cipher":           "TLS_AES_128_GCM_SHA256",
			"tls.server.verified":  "true",
			"tls.server.cert":      base64.StdEncoding.EncodeToString(der),
		},
	}
	sigs := cs.signals(context.Background(), r)

	var expired *incident.Signal
	for i := range sigs {
		if sigs[i].Kind == "tls.cert_expired" {
			expired = &sigs[i]
		}
	}
	if expired == nil {
		t.Fatalf("expected a tls.cert_expired signal, got %+v", sigs)
	}
	if expired.Plane != "threat" || expired.Severity != incident.SeverityCritical {
		t.Errorf("expired posture signal = %+v", expired)
	}
	if expired.Attributes["certctl.handoff_url"] == "" {
		t.Error("an expired-cert signal should carry a certctl handoff URL")
	}

	if cs.signals(context.Background(), &resultv1.Result{CanaryType: "icmp"}) != nil {
		t.Error("a non-HTTP result should yield no posture signals")
	}
}
