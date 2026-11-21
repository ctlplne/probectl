// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFastDDoSPollingBoundsWorkersAndDrainsPendingTenants(t *testing.T) {
	const limit = 8
	sup := AlertEvaluatorSupervisor{maxConcurrent: limit, evaluators: make(map[string]*tenantEvaluator)}
	release := make(map[string]chan struct{})
	for i := range limit + 2 {
		id := fmt.Sprintf("tenant-%02d", i)
		sup.evaluators[id] = &tenantEvaluator{tenant: tenancy.ID(id)}
		release[id] = make(chan struct{})
	}
	started := make(chan string, limit+2)
	ticks := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.pollFastDDoS(ctx, ticks, func(ctx context.Context, te *tenantEvaluator) {
			id := te.tenant.String()
			started <- id
			select {
			case <-ctx.Done():
			case <-release[id]:
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-done })
	ticks <- time.Now()
	waitForStart := func() string {
		t.Helper()
		select {
		case id := <-started:
			return id
		case <-time.After(3 * time.Second):
			t.Fatal("no tenant took the available fast scheduler slot")
			return ""
		}
	}
	firstRound := make(map[string]bool, limit)
	for range limit {
		id := waitForStart()
		if id > "tenant-07" || firstRound[id] {
			t.Fatal("the first round skipped or repeated a waiting tenant", id)
		}
		firstRound[id] = true
	}
	select {
	case id := <-started:
		t.Fatal("the fast scheduler exceeded its tenant slot limit", id)
	case <-time.After(50 * time.Millisecond):
	}
	close(release["tenant-00"])
	if got := waitForStart(); got != "tenant-08" {
		t.Fatal("the oldest pending tenant did not take the free slot", got)
	}
	close(release["tenant-01"])
	if got := waitForStart(); got != "tenant-09" {
		t.Fatal("the final pending tenant did not take the free slot", got)
	}
}

type fakeQuerier struct{ rows []tsdb.Series }

func (f fakeQuerier) Query(metric string, match map[string]string) []tsdb.Series {
	var out []tsdb.Series
	for _, s := range f.rows {
		if s.Metric != metric {
			continue
		}
		ok := true
		for k, v := range match {
			if s.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

func TestMetricSourceLatestPerSeriesAndTenantScope(t *testing.T) {
	rows := []tsdb.Series{
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 0.1},
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 0.9}, // latest for a
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "b"}, Value: 0.2},
		{Metric: "m", Labels: map[string]string{"tenant_id": "t2", "server_address": "a"}, Value: 0.5}, // other tenant
	}
	src := metricSource{q: fakeQuerier{rows: rows}, tenant: "t1"}

	samples, err := src.Current(context.Background(), "m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want 2 (latest per series, tenant-scoped): %+v", len(samples), samples)
	}
	got := map[string]float64{}
	for _, s := range samples {
		if s.Labels["tenant_id"] != "t1" {
			t.Errorf("leaked another tenant's series: %+v", s.Labels)
		}
		got[s.Labels["server_address"]] = s.Value
	}
	if got["a"] != 0.9 || got["b"] != 0.2 {
		t.Errorf("latest values = %+v, want a=0.9 b=0.2", got)
	}
}

func TestMetricSourceAddsMatchLabels(t *testing.T) {
	rows := []tsdb.Series{
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 1},
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "b"}, Value: 2},
	}
	src := metricSource{q: fakeQuerier{rows: rows}, tenant: "t1"}
	samples, _ := src.Current(context.Background(), "m", map[string]string{"server_address": "b"})
	if len(samples) != 1 || samples[0].Value != 2 {
		t.Fatalf("match filter not applied: %+v", samples)
	}
}

var _ tsdbQuerier = fakeQuerier{}
var _ alert.MetricSource = metricSource{}

func TestBuildAlertChannelDeps(t *testing.T) {
	log := statusQuietLog()

	deps, err := BuildAlertChannelDeps(&config.Config{}, nil, log)
	if err != nil || deps.Mail != nil {
		t.Fatalf("unconfigured SMTP must yield a nil sender, got (%v, %v)", deps.Mail, err)
	}

	deps, err = BuildAlertChannelDeps(&config.Config{
		AlertSMTPAddr: "mail.example.test:587",
		AlertSMTPFrom: "probectl@example.test",
	}, nil, log)
	if err != nil || deps.Mail == nil {
		t.Fatalf("configured SMTP must yield a sender, got (%v, %v)", deps.Mail, err)
	}

	resolveFail := func(context.Context, string) (string, error) {
		return "", errors.New("backend down")
	}
	_, err = BuildAlertChannelDeps(&config.Config{
		AlertSMTPAddr:     "mail.example.test:587",
		AlertSMTPFrom:     "probectl@example.test",
		AlertSMTPUsername: "alerts",
		AlertSMTPPassword: "secret://mail-password",
	}, resolveFail, log)
	if err == nil {
		t.Fatal("an unresolvable configured credential must fail the boot, not build a credential-less sender")
	}
}
