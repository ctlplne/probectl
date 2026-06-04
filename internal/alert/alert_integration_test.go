//go:build integration

package alert

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// TestThresholdFiresToWebhook is the S16 Done-when: a breached threshold fires an
// alert and delivers it to a webhook channel, end to end, with the payload's
// HMAC signature verifying against the configured secret.
func TestThresholdFiresToWebhook(t *testing.T) {
	const secret = "s3cret-key"
	received := make(chan WebhookPayload, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		sig := r.Header.Get(SignatureHeader)
		mac, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
		if err != nil || !crypto.Verify([]byte(secret), body, mac) {
			w.WriteHeader(http.StatusForbidden) // reject an unsigned/forged payload
			return
		}
		var p WebhookPayload
		if err := json.Unmarshal(body, &p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- p
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	rule := Rule{
		ID: "r1", TenantID: "t1", Name: "loss-high", Enabled: true,
		Metric: "probectl_probe_loss_ratio", Type: Threshold, Comparison: GT, Threshold: 0.5,
		Severity: SeverityCritical, ForN: 1,
		Channels: []ChannelSpec{{Type: "webhook", URL: srv.URL, Secret: secret}},
	}
	src := &fakeSource{samples: []Sample{sample(0.9, map[string]string{"server_address": "1.1.1.1"})}}
	en := NewEngine(src, NewNotifier(ChannelDeps{HTTPClient: srv.Client()}, discard()), discard())

	alerts, err := en.Evaluate(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].State != StateFiring {
		t.Fatalf("expected 1 firing alert, got %+v", alerts)
	}

	select {
	case p := <-received:
		if p.State != "firing" || p.Rule.Name != "loss-high" || p.Severity != "critical" {
			t.Errorf("payload = %+v", p)
		}
		if p.Value != 0.9 || p.Labels["server_address"] != "1.1.1.1" {
			t.Errorf("payload value/labels = %v / %v", p.Value, p.Labels)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook did not receive the alert")
	}
}
