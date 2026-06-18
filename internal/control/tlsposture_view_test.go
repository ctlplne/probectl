// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

func TestTLSPostureSinkPostureIsPureReadModel(t *testing.T) {
	_, der, err := crypto.GenerateTestCert(crypto.TestCertOptions{
		CommonName: "view.example", DNSNames: []string{"view.example"}, NotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	postures := threat.NewPostureStore(0)
	cs := NewTLSPostureConsumer(nil, nil, BuildTLSAnalyzer(&config.Config{}), nil).
		WithPostureStore(postures)

	err = cs.SinkPosture(context.Background(), &resultv1.Result{
		TenantId:          "t",
		CanaryType:        "http",
		ServerAddress:     "view.example",
		StartTimeUnixNano: time.Now().UnixNano(),
		Attributes: map[string]string{
			"tls.protocol.version":         "1.3",
			"tls.cipher.suite":             "TLS_AES_128_GCM_SHA256",
			"probectl.tls.server.verified": "true",
			"probectl.tls.server.cert":     base64.StdEncoding.EncodeToString(der),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := postures.Len("t"); got != 1 {
		t.Fatalf("postures.Len(t) = %d, want 1", got)
	}
}
