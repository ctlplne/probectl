// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/hex"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The only packet destinations are the two loopback IPFIX listeners.
// APNIC addresses appear as fields in synthetic observations.
func TestShippedAPNICAllocationEnrichment(t *testing.T) {
	dir := stageAPNICSnapshot(t)
	st := shipped.Start(t, shipped.Options{Name: "apnic-allocation", TenantBand: 4,
		Env: map[string]string{"PROBECTL_FLOW_ENRICH_RIR_DIR": dir}})
	operator := st.OnboardOperator(t, "root@msp-apnic.example")
	run := "apnic-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := [...]*nativeLane{{name: "red"}, {name: "blue"}}
	addresses := [...]string{"1.0.0.1", "1.0.1.1"}
	countries := [...]string{"AU", "CN"}
	statuses := [...]string{"assigned", "allocated"}
	dates := [...]string{"20110811", "20110414"}
	counters := [...]uint32{1000, 3000}
	for i, lane := range lanes {
		lane.provision(t, st, operator, run)
		var enrichment opendata.Enrichment
		lane.do(t, st, http.MethodGet, "/v1/opendata/enrichment?ip="+addresses[i], nil, &enrichment, http.StatusOK)
		if enrichment.IP != addresses[i] || enrichment.RIR != "apnic" || enrichment.CountryCode != countries[i] ||
			enrichment.AllocationStatus != statuses[i] || enrichment.AllocationDate != dates[i] ||
			len(enrichment.Sources) != 1 || enrichment.Sources[0].Source != "rir-stats" {
			t.Fatalf("%s lost the source's allocation values and provenance: %+v", lane.name, enrichment)
		}
	}

	at := time.Now().UTC().Truncate(time.Second)
	var plans [2]flow.QueryPlan
	for i, lane := range lanes {
		plan := nativeGoldenPlan(0, at, []string{"src_addr", "src_port", "src_country"})
		plan.DataSeries, plan.Filter = "raw", nil
		socket, err := net.DialTimeout("udp", lane.listeners["IPFIX"], 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		source := netip.MustParseAddr(addresses[i]).As4()
		var selectedPort string
		port := uint16(41000)
		// The flow cache warms asynchronously. Use separate original keys
		// so a cache miss can persist and a later receipt can be enriched.
		shipped.Await(t, "an original IPFIX report reached the warmed allocation cache", 30*time.Second, func() bool {
			result := lane.query(t, st, plan)
			for _, row := range result.Rows {
				if row.Group["src_addr"] != addresses[i] {
					t.Fatalf("%s raw rows include a foreign address: %v", lane.name, row.Group)
				}
				if row.Group["src_country"] == countries[i] {
					selectedPort = row.Group["src_port"]
					return selectedPort != ""
				}
			}
			frame := apnicIPFIX(t, source, port, at, counters[i])
			if n, err := socket.Write(frame); err != nil || n != len(frame) {
				t.Fatal("write the loopback IPFIX observation", n, err)
			}
			port++
			return false
		})
		plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "src_port", Op: flow.QueryIn, Values: []string{selectedPort}},
		}}
		plans[i] = plan
	}

	st.RestartControl(t, "apnic-allocation-restart", nil)
	for i, lane := range lanes {
		for _, series := range []string{"raw", "rollup"} {
			plan := plans[i]
			plan.DataSeries = series
			wantBytes := strconv.FormatUint(uint64(counters[i]), 10)
			result := apnicFlowQuery(t, st, lane, plan)
			if len(result.Rows) != 1 || result.Rows[0].Group["src_addr"] != addresses[i] ||
				result.Rows[0].Group["src_country"] != countries[i] || result.Totals["bytes:total"] != wantBytes ||
				result.Totals["packets:total"] != "7" || result.Totals["flows:total"] != "1" {
				t.Fatalf("%s %s lost an original enriched row: %v", lane.name, series, result)
			}
			var cli struct {
				Flow flowstore.PlanResult `json:"flow"`
			}
			st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &cli, "explorer", "query",
				"--body-file", st.SecretFile(t, map[string]any{"source": "flow", "flow": plan}))
			if cli.Flow.Source != series || !reflect.DeepEqual(cli.Flow.Rows, result.Rows) {
				t.Fatalf("%s %s CLI lost the scoped row", lane.name, series)
			}
			foreign := plan
			foreign.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
				{Field: "src_addr", Op: flow.QueryIn, Values: []string{addresses[1-i]}},
			}}
			if selection := apnicFlowQuery(t, st, lane, foreign); len(selection.Rows) != 0 {
				t.Fatalf("%s %s read the sibling's original address", lane.name, series)
			}
			var saved flow.SavedQueryView
			lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{
				Name: "APNIC allocation " + series, Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan,
			}}, &saved, http.StatusCreated)
			lanes[1-i].do(t, st, http.MethodGet, "/v1/explorer/flow-views/"+saved.ID, nil, nil, http.StatusNotFound)
			for _, theme := range []string{"light", "dark"} {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: st.BaseURL + "/ui/explore?flow_view=" + saved.ID, Theme: theme, Accessibility: true,
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
					TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Expect: []string{"Native flow query"},
					Steps: []testsupport.RenderStep{{
						Click: "Run flow query", Expect: []string{"Exact flow details", addresses[i]},
						Absent: []string{addresses[1-i]},
					}},
				})
			}
		}
	}
}

func stageAPNICSnapshot(t *testing.T) string {
	t.Helper()
	const input = "PROBECTL_TEST_PUBLIC_APNIC_SNAPSHOT"
	const size = 9_315_393
	const digest = "6912f6b9ec4b92923c56bb1119bc02ef2fa351979134c0116037001147d82132"
	path := os.Getenv(input)
	if path == "" {
		testsupport.SkipOptIn(t, input, "requires the offline, signature-verified APNIC extended delegation report for 2026-11-22")
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	data, err := io.ReadAll(io.LimitReader(source, size+1))
	if err != nil || len(data) != size || hex.EncodeToString(crypto.Hash(data)) != digest {
		t.Fatal("the supplied file differs from the pinned APNIC original", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "delegated-apnic-extended-20261122"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func apnicFlowQuery(t *testing.T, st *shipped.Stack, lane *nativeLane, plan flow.QueryPlan) flowstore.PlanResult {
	t.Helper()
	var result struct {
		Flow flowstore.PlanResult `json:"flow"`
	}
	lane.do(t, st, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan}, &result, http.StatusOK)
	if result.Flow.Source != plan.DataSeries || result.Flow.Coverage == nil || !result.Flow.Coverage.CompleteInputs {
		t.Fatal("the requested source did not provide complete original rows", plan.DataSeries)
	}
	return result.Flow
}

func apnicIPFIX(t *testing.T, source [4]byte, port uint16, at time.Time, amount uint32) []byte {
	t.Helper()
	const templateID = uint16(256)
	fields := [...]uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 4, 2, 4}
	template := nativeWire(t, templateID, uint16(len(fields)/2), fields)
	record := nativeWire(t, source, [4]byte{192, 0, 2, 1}, port, uint16(443), uint8(6), amount, uint32(7))
	size, seconds := 24+len(template)+len(record), at.Unix()
	if size > math.MaxUint16 || len(template) > math.MaxUint16-4 || len(record) > math.MaxUint16-4 ||
		seconds < 0 || seconds > math.MaxUint32 {
		t.Fatal("the observation does not fit the IPFIX packet")
	}
	body := nativeWire(t, uint16(10), uint16(size), uint32(seconds), uint32(port), uint32(35),
		uint16(2), uint16(4+len(template)), template)
	return append(body, nativeWire(t, templateID, uint16(4+len(record)), record)...)
}
