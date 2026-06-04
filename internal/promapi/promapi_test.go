package promapi

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func TestParseSelector(t *testing.T) {
	ok := map[string]string{
		"up":                         `up{tenant_id="t"}`,
		"  probectl_result_rtt_ms  ": `probectl_result_rtt_ms{tenant_id="t"}`,
		`m{a="1"}`:                   `m{a="1",tenant_id="t"}`,
		`m{a="1", b!="2",}`:          `m{a="1",b!="2",tenant_id="t"}`,
		`m{a=~"x.*", b!~"y"}`:        `m{a=~"x.*",b!~"y",tenant_id="t"}`,
		`{__name__="m", a='q'}`:      `{__name__="m",a="q",tenant_id="t"}`,
		`m{a="es\"caped\\quote"}`:    `m{a="es\"caped\\quote",tenant_id="t"}`,
		`m{tenant_id="EVIL"}`:        `m{tenant_id="t"}`,       // forced override
		`m{tenant_id!="x", a="1"}`:   `m{a="1",tenant_id="t"}`, // negation stripped too
		`m{tenant_id=~".*"}`:         `m{tenant_id="t"}`,       // regex escape stripped
		"m{}":                        `m{tenant_id="t"}`,
	}
	for expr, want := range ok {
		sel, err := ParseSelector(expr)
		if err != nil {
			t.Fatalf("ParseSelector(%q): %v", expr, err)
		}
		if got := ForceTenant(sel, "t").String(); got != want {
			t.Errorf("ParseSelector(%q) forced = %s, want %s", expr, got, want)
		}
	}

	bad := []string{
		"", "rate(m[5m])", "m + 1", "sum(m)", "m[5m]", "m offset 5m",
		"m @ 100", `m{a=}`, `m{a="unterminated}`, `m{="v"}`, `m{a=="v"}`,
		`m{a=~"(((((bad"}`, "1+1*3", `m{a="v"} or vector(1)`,
		`m{a=~"` + strings.Repeat("x", 300) + `"}`, // regex length cap
	}
	for _, expr := range bad {
		if _, err := ParseSelector(expr); err == nil {
			t.Errorf("ParseSelector(%q) accepted, want error", expr)
		}
	}
}

func snapshotFixture() []tsdb.Series {
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixMilli()
	return []tsdb.Series{
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": "t-a", "agent_id": "a1", "target": "db"}, Value: 12, TimeMillis: at - 60_000},
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": "t-a", "agent_id": "a1", "target": "db"}, Value: 15, TimeMillis: at - 30_000},
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": "t-a", "agent_id": "a2", "target": "web"}, Value: 40, TimeMillis: at - 30_000},
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": "t-b", "agent_id": "b1", "target": "db"}, Value: 99, TimeMillis: at - 30_000},
		{Metric: "probectl_device_cpu", Labels: map[string]string{"tenant_id": "t-a", "device": "sw1"}, Value: 55, TimeMillis: at - 600_000}, // outside lookback
	}
}

func TestInstantTenantScopedLatest(t *testing.T) {
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	sel, _ := ParseSelector(`probectl_result_rtt_ms`)
	res, err := Instant(snapshotFixture(), ForceTenant(sel, "t-a"), at, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("series = %d, want 2 (t-a only): %+v", len(res), res)
	}
	for _, rs := range res {
		if rs.Labels["tenant_id"] != "t-a" {
			t.Fatalf("CROSS-TENANT LEAK: %+v", rs)
		}
		if len(rs.Points) != 1 {
			t.Fatalf("instant must return one point, got %d", len(rs.Points))
		}
		if rs.Labels["agent_id"] == "a1" && rs.Points[0].Value != 15 {
			t.Errorf("latest sample = %v, want 15", rs.Points[0].Value)
		}
	}
}

func TestRangeAndLookbackAndCap(t *testing.T) {
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	sel, _ := ParseSelector(`probectl_result_rtt_ms{agent_id=~"a.*"}`)
	res, err := Range(snapshotFixture(), ForceTenant(sel, "t-a"), at.Add(-2*time.Minute), at, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("series = %d", len(res))
	}
	for _, rs := range res {
		if rs.Labels["agent_id"] == "a1" && len(rs.Points) != 2 {
			t.Errorf("a1 points = %d, want 2", len(rs.Points))
		}
	}

	// Device metric outside the lookback window yields an empty instant vector.
	dsel, _ := ParseSelector("probectl_device_cpu")
	dres, err := Instant(snapshotFixture(), ForceTenant(dsel, "t-a"), at, 0, 0)
	if err != nil || len(dres) != 0 {
		t.Fatalf("lookback: res=%v err=%v", dres, err)
	}

	// Cardinality cap fails closed.
	if _, err := Range(snapshotFixture(), ForceTenant(Selector{}, "t-a"), at.Add(-time.Hour), at, 1); err == nil {
		t.Fatal("cardinality cap not enforced")
	}
}

func TestLabelsSeriesValues(t *testing.T) {
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	sels := []Selector{ForceTenant(Selector{}, "t-a")}
	names, err := LabelNames(snapshotFixture(), sels, at.Add(-time.Hour), at, 0)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"__name__", "agent_id", "target", "tenant_id"} {
		if !strings.Contains(joined, want) {
			t.Errorf("labels missing %s: %v", want, names)
		}
	}
	vals, err := LabelValues(snapshotFixture(), "__name__", sels, at.Add(-time.Hour), at, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 2 { // rtt + device metric, t-a only
		t.Fatalf("metric names = %v", vals)
	}
	series, err := Series(snapshotFixture(), sels, at.Add(-time.Hour), at, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, rs := range series {
		if rs.Labels["tenant_id"] != "t-a" {
			t.Fatalf("CROSS-TENANT LEAK in series: %+v", rs)
		}
	}
}

func TestFederationExposition(t *testing.T) {
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	sel, _ := ParseSelector(`probectl_result_rtt_ms{agent_id="a1"}`)
	res, err := Instant(snapshotFixture(), ForceTenant(sel, "t-a"), at, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteFederation(&buf, res); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	want := `probectl_result_rtt_ms{agent_id="a1",target="db",tenant_id="t-a"} 15 ` // + ts
	if !strings.HasPrefix(line, want) {
		t.Fatalf("exposition = %q, want prefix %q", line, want)
	}
	wantTS := strconv.FormatInt(at.Add(-30*time.Second).UnixMilli(), 10)
	if !strings.HasSuffix(line, wantTS) {
		t.Fatalf("exposition timestamp: %q, want suffix %s", line, wantTS)
	}
}

func TestDecodeRemoteWrite(t *testing.T) {
	wr := &prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
		Labels: []*prompb.Label{
			{Name: "__name__", Value: "external_metric"},
			{Name: "job", Value: "node"},
			{Name: "tenant_id", Value: "EVIL-OTHER-TENANT"},
		},
		Samples: []*prompb.Sample{{Value: 7, Timestamp: 1700000000000}, {Value: 8, Timestamp: 1700000015000}},
	}}}
	raw, _ := proto.Marshal(wr)
	body := snappy.Encode(nil, raw)

	series, err := DecodeRemoteWrite(body, "t-a", WriteLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 2 {
		t.Fatalf("series = %d", len(series))
	}
	for _, s := range series {
		if s.Metric != "external_metric" || s.Labels["job"] != "node" {
			t.Fatalf("decoded = %+v", s)
		}
		if s.Labels["tenant_id"] != "t-a" {
			t.Fatalf("tenant not forced: %+v", s)
		}
	}
	if series[0].Value != 7 || series[0].TimeMillis != 1700000000000 {
		t.Fatalf("sample = %+v", series[0])
	}

	// Limits fail closed.
	if _, err := DecodeRemoteWrite(body, "t", WriteLimits{MaxSamples: 1}); err == nil {
		t.Fatal("MaxSamples not enforced")
	}
	if _, err := DecodeRemoteWrite([]byte("not snappy"), "t", WriteLimits{}); err == nil {
		t.Fatal("garbage accepted")
	}
	noName := &prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
		Labels:  []*prompb.Label{{Name: "job", Value: "x"}},
		Samples: []*prompb.Sample{{Value: 1, Timestamp: 1}},
	}}}
	rawNN, _ := proto.Marshal(noName)
	if _, err := DecodeRemoteWrite(snappy.Encode(nil, rawNN), "t", WriteLimits{}); err == nil {
		t.Fatal("nameless series accepted")
	}
}
