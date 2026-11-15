// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func streamingEvidenceFixture(t *testing.T, raw []byte) (Manifest, AttachmentSource, []byte) {
	t.Helper()
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	address := digest(raw)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	manifest := Manifest{Contract: ContractVersion, Profile: "carrier-sla", PackageID: "pkg_financial", TenantScopeDigest: digest([]byte("owned-tenant")), CreatedAt: now, Window: Window{From: now.AddDate(0, -1, 0), To: now}, Redaction: "operator text redacted; exact originals retained",
		Evidence:   []Record{{ID: "originals", Kind: "carrier.sla", State: StateObserved, Summary: "Selected original measurements", AttachmentDigest: address, Provenance: Provenance{Source: "authorized original probes", VantageID: "recorded source identities", VantageOwner: "operator-controlled", TrustTier: "authenticated-input-derived", Independence: "see each original source", CapturedAt: now, Freshness: "as of capture", ClockQuality: "original execution clocks", MissingIntervals: []MissingInterval{}}}},
		Statements: []Statement{{ID: "review", Text: "Conditional credit requires human review; no submission", Class: "fact", EvidenceIDs: []string{"originals"}}}}
	source := AttachmentSource{Digest: address, MediaType: "application/json", Bytes: int64(len(raw)), Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }}
	return manifest, source, private
}

func TestWriteSignedKeepsExactOriginalBytesAndExistingOfflineVerification(t *testing.T) {
	raw := []byte("{\"observations\":[\n{\"sequence\":\"9007199254740993\",\"rtt_nanos\":\"18446744073709551615\",\"text\":\"a}b\\\"c\"}\n],\"credit\":\"100000000000000000001/1000000000000000000\"}")
	manifest, source, private := streamingEvidenceFixture(t, raw)
	var output bytes.Buffer
	if err := WriteSigned(t.Context(), &output, manifest, []AttachmentSource{source}, private); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(output.Bytes())
	if err != nil || verified.Profile != "carrier-sla" || verified.Incident.ID != "" {
		t.Fatal("streamed non-incident originals lost common offline verification", err)
	}
	var pkg Package
	if err := json.Unmarshal(output.Bytes(), &pkg); err != nil {
		t.Fatal(err)
	}
	if len(pkg.Attachments) != 1 || !bytes.Equal(pkg.Attachments[0].Content, raw) {
		t.Fatal("streaming changed original whitespace, strings, wide values or exact credit")
	}
	changed := bytes.Replace(output.Bytes(), []byte("9007199254740993"), []byte("9007199254740994"), 1)
	if _, err := Verify(changed); err == nil {
		t.Fatal("tampered streamed originals retained a valid package")
	}
}

func TestWriteSignedRefusesIncompleteMalformedChangedAndUngroundedStages(t *testing.T) {
	for _, kind := range []string{"short stage", "long stage", "leading space", "trailing newline", "two values", "invalid JSON", "changed second read", "duplicate stage", "missing reference", "canceled", "writer failure"} {
		t.Run(kind, func(t *testing.T) {
			raw := []byte(`{"originals":[1,2,3]}`)
			switch kind {
			case "leading space":
				raw = append([]byte(" "), raw...)
			case "trailing newline":
				raw = append(raw, '\n')
			case "two values":
				raw = append(raw, raw...)
			case "invalid JSON":
				raw = []byte(`{"originals":[1,}`)
			}
			manifest, source, private := streamingEvidenceFixture(t, raw)
			ctx := t.Context()
			sources := []AttachmentSource{source}
			var output bytes.Buffer
			var target io.Writer = &output
			switch kind {
			case "short stage":
				sources[0].Bytes++
			case "long stage":
				sources[0].Bytes--
			case "changed second read":
				calls := 0
				sources[0].Open = func(context.Context) (io.ReadCloser, error) {
					calls++
					body := raw
					if calls > 1 {
						body = bytes.Replace(raw, []byte("1,2,3"), []byte("1,2,4"), 1)
					}
					return io.NopCloser(bytes.NewReader(body)), nil
				}
			case "duplicate stage":
				sources = append(sources, source)
			case "missing reference":
				manifest.Statements[0].EvidenceIDs = []string{"absent"}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "writer failure":
				target = evidenceShortWriter{}
			}
			if err := WriteSigned(ctx, target, manifest, sources, private); err == nil {
				t.Fatal("invalid original stage acquired a successful signed copy", kind)
			}
		})
	}
}

type evidenceShortWriter struct{}

func (evidenceShortWriter) Write(value []byte) (int, error) { return len(value) / 2, nil }

type evidenceNoReaderHash struct{ crypto.Provider }

func TestWriteSignedRefusesMissingConfiguredStreamingCryptoWithoutFallback(t *testing.T) {
	manifest, source, private := streamingEvidenceFixture(t, []byte(`{"originals":[]}`))
	old := crypto.Default
	crypto.Default = evidenceNoReaderHash{Provider: old}
	defer func() { crypto.Default = old }()
	var output bytes.Buffer
	if err := WriteSigned(t.Context(), &output, manifest, []AttachmentSource{source}, private); !errors.Is(err, crypto.ErrStreamingHashUnavailable) {
		t.Fatal("streaming digest bypassed the configured crypto provider", err)
	}
}
