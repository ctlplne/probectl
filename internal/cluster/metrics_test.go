// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

type clusterGlobalOnlyWriter struct {
	series []tsdb.Series
}

func (w *clusterGlobalOnlyWriter) Write(context.Context, []tsdb.Series) error {
	return errors.New("tenant Write called for cluster global metrics")
}

func (w *clusterGlobalOnlyWriter) WriteGlobal(_ context.Context, s []tsdb.Series) error {
	w.series = append(w.series, s...)
	return nil
}

func (w *clusterGlobalOnlyWriter) Close() error { return nil }

// TestWriteSeries: cluster accounting lands in the TSDB as region-labeled
// series — the multi-region observability leg.
func TestWriteSeries(t *testing.T) {
	w := tsdb.NewMemory()
	writer := &fakeProbe{p: Probe{Epoch: 4, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 4, LagSeconds: 2.5}}
	m := NewManager(Topology{Region: "us-east", ReplicationMode: ReplicationSync}, writer, reader)
	m.Refresh(context.Background())

	if err := WriteSeries(context.Background(), w, m); err != nil {
		t.Fatal(err)
	}
	usable := w.Query("probectl_cluster_writes_usable", map[string]string{"region": "us-east"})
	if len(usable) == 0 || usable[0].Value != 1 {
		t.Fatalf("writes_usable series: %+v", usable)
	}
	role := w.Query("probectl_cluster_writer_role", map[string]string{"region": "us-east"})
	if len(role) == 0 || role[0].Value != 1 {
		t.Fatalf("writer_role (writer=1) series: %+v", role)
	}
	lag := w.Query("probectl_cluster_replica_lag_seconds", map[string]string{"region": "us-east"})
	if len(lag) == 0 || lag[0].Value != 2.5 {
		t.Fatalf("replica lag series: %+v", lag)
	}

	// A fenced writer drives writer_role negative (an alert can fire on < 1).
	writer.set(Probe{Epoch: 3}) // lower epoch than the high-water 4 -> stale
	m.Refresh(context.Background())
	_ = WriteSeries(context.Background(), w, m)
	role = w.Query("probectl_cluster_writer_role", map[string]string{"region": "us-east"})
	if latest := role[len(role)-1].Value; latest >= 1 {
		t.Fatalf("a stale writer must report role < 1: %v in %+v", latest, role)
	}

	// nil writer / nil manager are no-ops.
	if err := WriteSeries(context.Background(), nil, m); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeries(context.Background(), w, nil); err != nil {
		t.Fatal(err)
	}
}

// TestRunMetricsLoop: the loop writes on its ticker and stops with ctx.
func TestRunMetricsLoop(t *testing.T) {
	w := tsdb.NewMemory()
	m := NewManager(Topology{Region: "eu-west"}, &fakeProbe{p: Probe{Epoch: 1}}, nil)
	m.Refresh(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunMetrics(ctx, w, m, 5*time.Millisecond, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.Query("probectl_cluster_epoch", map[string]string{"region": "eu-west"})) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if len(w.Query("probectl_cluster_epoch", map[string]string{"region": "eu-west"})) == 0 {
		t.Fatal("the metrics loop must write cluster series")
	}
}

// TestRunRefreshesInitial: Run does an immediate Refresh before the first tick,
// then stops cleanly on ctx cancel.
func TestRunRefreshesInitial(t *testing.T) {
	m := NewManager(Topology{Region: "us-east"}, &fakeProbe{p: Probe{InRecovery: true}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, time.Hour); close(done) }() // long tick: only the initial refresh runs
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := m.WriterUsable(); !ok {
			break // the initial refresh resolved the standby -> fenced
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if ok, _ := m.WriterUsable(); ok {
		t.Fatal("Run must perform an immediate initial refresh")
	}
}

func TestWriteSeriesUsesExplicitGlobalWriter(t *testing.T) {
	w := &clusterGlobalOnlyWriter{}
	m := NewManager(Topology{Region: "us-east"}, &fakeProbe{p: Probe{Epoch: 1}}, nil)
	m.Refresh(context.Background())

	if err := WriteSeries(context.Background(), w, m); err != nil {
		t.Fatal(err)
	}
	if len(w.series) == 0 {
		t.Fatal("cluster metrics did not reach the explicit global writer")
	}
	for _, s := range w.series {
		if _, ok := s.Labels[tsdb.TenantLabel]; ok {
			t.Fatalf("cluster global metric carried tenant_id: %+v", s)
		}
	}
}
