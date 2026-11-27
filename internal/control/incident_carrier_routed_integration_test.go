// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func proveRoutedCarrierPack(t *testing.T, f *roleExplanationAPIFixture, tenant, sibling, incidentID string, from time.Time, healthy bool, definitions []testspec.ExecutableDefinition, originals [2]entity.Observation, discover Discoverer) {
	t.Helper()
	before := f.server.discover
	f.server.discover = discover
	defer func() { f.server.discover = before }()
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	for _, definition := range definitions {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/tests/"+definition.ID+"/path", bytes.NewBufferString("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		res, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var observed path.Path
		err = json.NewDecoder(res.Body).Decode(&observed)
		closeErr := res.Body.Close()
		if err != nil || closeErr != nil || res.StatusCode != http.StatusOK ||
			observed.Vantage != path.VantageControlPlane || observed.TargetIP != definition.Target ||
			observed.DestinationReached != healthy || observed.MeasurementFidelity == nil ||
			observed.MeasurementFidelity.AcquisitionMode != "raw_icmp" || !containsRoutedCarrierHop(observed) {
			t.Fatal("the control-plane discovery did not retain the routed path and destination outcome",
				res.StatusCode, observed.TargetIP, observed.DestinationReached, err, closeErr)
		}
	}
	to := f.observedAt(tenant)
	shipped.Await(t, "the carrier export window is in the past", 5*time.Second, func() bool {
		return !to.After(time.Now())
	})

	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithEvidenceSigningKey(private)
	request := sdk.ExportIncidentEvidenceBytesRequest{Id: incidentID, Body: &sdk.IncidentEvidenceExportInput{
		Carrier: &sdk.IncidentCarrierInput{From: from.Format(time.RFC3339Nano), To: to.Format(time.RFC3339Nano)},
	}}
	owner := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	raw, err := owner.ExportIncidentEvidenceBytes(t.Context(), request)
	if err != nil {
		t.Fatal("the routed fault did not produce a carrier pack", err)
	}
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest.Profile != "carrier" || manifest.Incident.ID != incidentID ||
		!manifest.Window.From.Equal(from) || !manifest.Window.To.Equal(to) {
		t.Fatal("the routed carrier pack did not verify offline with the exact window", err)
	}
	var bundle evidence.Package
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.Signing.PublicKey != string(public) ||
		len(bundle.Attachments) != 1 || bytes.Contains(raw, []byte(tenant)) || bytes.Contains(raw, []byte(sibling)) {
		t.Fatal("the routed carrier pack lost its independently trusted key or disclosed a tenant", err)
	}
	var pack incident.CarrierPack
	if err := json.Unmarshal(bundle.Attachments[0].Content, &pack); err != nil || len(pack.Vantages) != len(definitions) ||
		pack.Coverage.Traces != "control_plane_only" {
		t.Fatal("the routed carrier pack lost its actual probe population or trace provenance", err)
	}
	replies, lost := "0", "3"
	if healthy {
		replies, lost = "3", "0"
	}
	byTest := make(map[string]entity.Observation, len(originals))
	for _, original := range originals {
		byTest[original.Source.SourceRef] = original
	}
	for _, vantage := range pack.Vantages {
		packets := vantage.Measurements.Packets
		original, present := byTest[vantage.TestID]
		if packets == nil || packets.Transmitted != "3" || packets.Replies != replies || packets.Lost != lost ||
			vantage.Measurements.CompleteExecutions != 1 || len(vantage.Traces) != 1 ||
			vantage.Traces[0].Vantage != path.VantageControlPlane || vantage.Traces[0].Path.DestinationReached != healthy ||
			!containsRoutedCarrierHop(vantage.Traces[0].Path) || !present {
			t.Fatal("the carrier pack changed a measured loss population or the actual traced path")
		}
		delete(byTest, vantage.TestID)
		observed := vantage.Measurements.Observations
		samples := original.ICMP.RoundTrips
		if len(observed) != 1 || observed[0].ObservationID != original.ID || observed[0].RoundTrips == nil ||
			observed[0].RoundTrips.ExecutionNanos != strconv.FormatUint(samples.ExecutionNanos, 10) ||
			len(observed[0].RoundTrips.Nanos) != len(samples.Nanos) {
			t.Fatal("the signed carrier pack lost the authenticated original execution")
		}
		for i, nanos := range samples.Nanos {
			if observed[0].RoundTrips.Nanos[i] != strconv.FormatUint(nanos, 10) {
				t.Fatal("the signed pack changed a measured round trip")
			}
		}
	}
	bundle.Attachments[0].Content = json.RawMessage(`{"summary":"changed after signing"}`)
	tampered, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.Verify(tampered); err == nil {
		t.Fatal("the offline verifier accepted a modified routed carrier pack")
	}
	foreign := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[sibling]))
	if raw, err := foreign.ExportIncidentEvidenceBytes(t.Context(), request); err == nil || len(raw) != 0 {
		t.Fatal("the sibling tenant obtained the routed carrier pack")
	}
}

func containsRoutedCarrierHop(observed path.Path) bool {
	for _, hop := range observed.Hops {
		for _, node := range hop.Nodes {
			if node.IP == "10.250.0.1" && node.Received > 0 {
				return true
			}
		}
	}
	return false
}
