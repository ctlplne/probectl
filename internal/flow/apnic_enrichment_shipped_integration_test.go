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
	"slices"
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
	observations := [2][2]apnicObservation{
		{
			{address: "1.0.0.1", country: "AU", status: "assigned", date: "20110811", bytes: 1000},
			{address: "2001:200::1", country: "JP", status: "allocated", date: "19990813", bytes: 2000},
		},
		{
			{address: "1.0.1.1", country: "CN", status: "allocated", date: "20110414", bytes: 3000},
			{address: "2001:360::1", country: "AU", status: "allocated", date: "20011211", bytes: 4000},
		},
	}
	var addresses [2][2]string
	for i, lane := range lanes {
		lane.provision(t, st, operator, run)
		for j, item := range observations[i] {
			addresses[i][j] = item.address
			var enrichment opendata.Enrichment
			lane.do(t, st, http.MethodGet, "/v1/opendata/enrichment?ip="+item.address, nil, &enrichment, http.StatusOK)
			if enrichment.IP != item.address || enrichment.RIR != "apnic" || enrichment.CountryCode != item.country ||
				enrichment.AllocationStatus != item.status || enrichment.AllocationDate != item.date ||
				len(enrichment.Sources) != 1 || enrichment.Sources[0].Source != "rir-stats" {
				t.Fatalf("%s lost %s original allocation values: %+v", lane.name, item.address, enrichment)
			}
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
		var selectedPorts [2]string
		port := uint16(41000)
		// Use separate original keys while the flow cache warms. Once a
		// family has an enriched row, keep its original observation.
		shipped.Await(t, "both original IPFIX address families reached the allocation cache", 30*time.Second, func() bool {
			result := lane.query(t, st, plan)
			for _, row := range result.Rows {
				index := slices.Index(addresses[i][:], row.Group["src_addr"])
				if index < 0 {
					t.Fatalf("%s raw rows include a foreign address: %v", lane.name, row.Group)
				}
				if selectedPorts[index] == "" && row.Group["src_country"] == observations[i][index].country {
					selectedPorts[index] = row.Group["src_port"]
				}
			}
			if selectedPorts[0] != "" && selectedPorts[1] != "" {
				return true
			}
			for index, item := range observations[i] {
				if selectedPorts[index] != "" {
					continue
				}
				frame := apnicIPFIX(t, netip.MustParseAddr(item.address), port, at, item.bytes)
				if n, err := socket.Write(frame); err != nil || n != len(frame) {
					t.Fatal("write the loopback IPFIX observation", n, err)
				}
				port++
			}
			return false
		})
		plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "src_port", Op: flow.QueryIn, Values: selectedPorts[:]},
		}}
		plans[i] = plan
	}

	st.RestartControl(t, "apnic-allocation-restart", nil)
	for i, lane := range lanes {
		for _, series := range []string{"raw", "rollup"} {
			plan := plans[i]
			plan.DataSeries = series
			result := apnicFlowQuery(t, st, lane, plan)
			wantBytes := uint64(observations[i][0].bytes) + uint64(observations[i][1].bytes)
			if len(result.Rows) != 2 || result.Totals["bytes:total"] != strconv.FormatUint(wantBytes, 10) ||
				result.Totals["packets:total"] != "14" || result.Totals["flows:total"] != "2" {
				t.Fatalf("%s %s lost a packet or original allocation record: %v", lane.name, series, result)
			}
			var seen [2]bool
			for _, row := range result.Rows {
				index := slices.Index(addresses[i][:], row.Group["src_addr"])
				if index < 0 || seen[index] {
					t.Fatalf("%s %s returned a foreign or duplicate row: %v", lane.name, series, row.Group)
				}
				seen[index] = true
				item := observations[i][index]
				if row.Group["src_country"] != item.country || row.Metrics["bytes:total"] != strconv.FormatUint(uint64(item.bytes), 10) ||
					row.Metrics["packets:total"] != "7" || row.Metrics["flows:total"] != "1" {
					t.Fatalf("%s %s lost the source fields or counters for %s: %v", lane.name, series, item.address, row)
				}
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
				{Field: "src_addr", Op: flow.QueryIn, Values: addresses[1-i][:]},
			}}
			if selection := apnicFlowQuery(t, st, lane, foreign); len(selection.Rows) != 0 {
				t.Fatalf("%s %s read the sibling's original address", lane.name, series)
			}
			var saved flow.SavedQueryView
			lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{
				Name: "APNIC allocation " + series, Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan,
			}}, &saved, http.StatusCreated)
			lanes[1-i].do(t, st, http.MethodGet, "/v1/explorer/flow-views/"+saved.ID, nil, nil, http.StatusNotFound)
			expected := make([]string, 0, 4)
			for _, item := range observations[i] {
				expected = append(expected, "src_addr: "+item.address, "src_country: "+item.country)
			}
			for _, theme := range []string{"light", "dark"} {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: st.BaseURL + "/ui/explore?flow_view=" + saved.ID, Theme: theme, Accessibility: true,
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
					TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Expect: []string{"Native flow query"},
					Steps: []testsupport.RenderStep{{
						Click: "Run flow query", Expect: expected, ExpectWithin: `table:has(caption:text-is("Exact flow details"))`,
						Absent: addresses[1-i][:],
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

type apnicObservation struct {
	address, country, status, date string
	bytes                          uint32
}

func apnicIPFIX(t *testing.T, source netip.Addr, port uint16, at time.Time, amount uint32) []byte {
	t.Helper()
	templateID := uint16(256)
	fields := [...]uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 4, 2, 4}
	var endpoints []byte
	if source.Is4() {
		endpoints = nativeWire(t, source.As4(), [4]byte{192, 0, 2, 1})
	} else {
		templateID++
		fields[0], fields[1], fields[2], fields[3] = 27, 16, 28, 16
		endpoints = nativeWire(t, source.As16(), netip.MustParseAddr("2001:db8::1").As16())
	}
	template := nativeWire(t, templateID, uint16(len(fields)/2), fields)
	record := append(endpoints, nativeWire(t, port, uint16(443), uint8(6), amount, uint32(7))...)
	size, seconds := 24+len(template)+len(record), at.Unix()
	if size > math.MaxUint16 || len(template) > math.MaxUint16-4 || len(record) > math.MaxUint16-4 ||
		seconds < 0 || seconds > math.MaxUint32 {
		t.Fatal("the observation does not fit the IPFIX packet")
	}
	body := nativeWire(t, uint16(10), uint16(size), uint32(seconds), uint32(port), uint32(35),
		uint16(2), uint16(4+len(template)), template)
	return append(body, nativeWire(t, templateID, uint16(4+len(record)), record)...)
}
