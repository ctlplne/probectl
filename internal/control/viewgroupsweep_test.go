// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
)

// fakeJanitor is a bus that can list and delete consumer groups.
type fakeJanitor struct {
	empty    []string
	deleted  []string
	listErr  error
	delErr   error
	refuseIn map[string]bool
}

func (f *fakeJanitor) Publish(context.Context, string, []byte, []byte) error        { return nil }
func (f *fakeJanitor) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (f *fakeJanitor) Close() error                                                 { return nil }
func (f *fakeJanitor) ListEmptyGroups(context.Context) ([]string, error) {
	return f.empty, f.listErr
}
func (f *fakeJanitor) DeleteGroups(_ context.Context, groups []string) ([]string, error) {
	var ok []string
	for _, g := range groups {
		if f.refuseIn[g] {
			continue
		}
		ok = append(ok, g)
	}
	f.deleted = append(f.deleted, ok...)
	sort.Strings(f.deleted)
	return ok, f.delErr
}

// TestTheSweepDeletesOnlyAbandonedViewGroups (DPR-109): a per-replica view
// group belongs to one process, so every restart and every rolling upgrade
// abandons a whole set of them, each holding its committed offsets until the
// broker's offset retention expires — on the QA lab, 1,459 of 1,573 consumer
// groups were dead, and every one of them read as a five-figure permanent lag.
// The sweep removes exactly those, and nothing else: a SHARED durable group
// losing its offsets would replay its side effects.
func TestTheSweepDeletesOnlyAbandonedViewGroups(t *testing.T) {
	bases := []string{"topology-ebpf", "topology-device", "topology-device-neighbors", "compliance-flow"}
	own := []string{"topology-ebpf-probectl-live-aaa", "compliance-flow-probectl-live-aaa"}

	abandoned := []string{
		"topology-ebpf-probectl-dead-bbb-t-acme",
		"topology-device-probectl-dead-bbb-t-acme",
		"topology-device-neighbors-probectl-dead-bbb-t-globex",
		"compliance-flow-probectl-dead-ccc-t-acme",
	}
	for _, g := range abandoned {
		if !abandonedViewGroup(g, bases, own) {
			t.Errorf("%q is a view group of a process that is gone and must be swept", g)
		}
	}

	kept := map[string]string{
		"topology-ebpf-probectl-live-aaa-t-acme": "this process's own group, momentarily empty during a rebalance",
		"topology-ebpf-probectl-live-aaa":        "this process's own group",
		"topology-ebpf-t-acme":                   "the shared-name form a single-replica deployment uses",
		"topology-ebpf":                          "the bare base",
		"ndr-flow-t-acme":                        "a durable group whose offsets carry side effects",
		"incident-correlator-t-acme":             "a durable group",
		"result-fan-t-acme":                      "a durable group",
		"topology-bgp-probectl-dead-bbb-t-acme":  "a view base this process never registered",
	}
	for g, why := range kept {
		if abandonedViewGroup(g, bases, own) {
			t.Errorf("%q must never be swept (%s)", g, why)
		}
	}
}

// TestNoDurableGroupHidesUnderAViewGroupPrefix (DPR-109): the sweep decides by
// prefix, so the invariant it rests on has to be enforced in the source, not
// assumed — a future shared group named "<some view base>-something" would be
// deleted along with the abandoned view groups and would then replay its side
// effects from the start of the stream.
func TestNoDurableGroupHidesUnderAViewGroupPrefix(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	viewRE := regexp.MustCompile(`viewGroup\("([a-z0-9-]+)"\)`)
	// A group literal passed to a lane runner WITHOUT viewGroup is shared and
	// durable: RunLanes(ctx, bus, topic, "name", ...) / Subscribe(..., "name", ...).
	durableRE := regexp.MustCompile(`(?:RunLanes|RunLane|Subscribe|runResultSinkLanes)\([^)]*?"([a-z0-9-]+)"`)
	var views, durables []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(b)
		for _, m := range viewRE.FindAllStringSubmatch(src, -1) {
			views = append(views, m[1])
		}
		for _, line := range strings.Split(src, "\n") {
			if strings.Contains(line, "viewGroup(") {
				continue
			}
			for _, m := range durableRE.FindAllStringSubmatch(line, -1) {
				durables = append(durables, m[1])
			}
		}
	}
	if len(views) == 0 {
		t.Fatal("no viewGroup call sites found — the scan is broken, not the code")
	}
	for _, d := range durables {
		for _, v := range views {
			if d == v {
				t.Errorf("group %q is used BOTH as a per-replica view group and as a shared group", d)
			}
			if strings.HasPrefix(d, v+"-") && !strings.HasPrefix(d, v+"-t-") {
				// Only a fault when it is not itself a view group.
				isView := false
				for _, v2 := range views {
					if d == v2 {
						isView = true
					}
				}
				if !isView {
					t.Errorf("shared durable group %q sits under view base %q: the sweep would delete its offsets and replay its side effects", d, v)
				}
			}
		}
	}
}

// TestTheSweepSurvivesABrokerThatRefusesIt (DPR-109): group administration is
// a privilege a deployment may not grant. A refusal is logged, never fatal, and
// the groups that did delete still count.
func TestTheSweepSurvivesABrokerThatRefusesIt(t *testing.T) {
	viewGroupMu.Lock()
	viewGroupBases["topology-ebpf"] = struct{}{}
	viewGroupOwn["topology-ebpf-live"] = struct{}{}
	viewGroupMu.Unlock()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	refusing := &fakeJanitor{listErr: errors.New("CLUSTER_AUTHORIZATION_FAILED")}
	sweepViewGroups(context.Background(), refusing, nil, log)
	if len(refusing.deleted) != 0 {
		t.Error("a broker that refuses the listing must delete nothing")
	}

	partial := &fakeJanitor{
		empty:    []string{"topology-ebpf-dead-t-acme", "topology-ebpf-live-t-acme", "ndr-flow-t-acme"},
		refuseIn: map[string]bool{},
		delErr:   errors.New("GROUP_AUTHORIZATION_FAILED"),
	}
	sweepViewGroups(context.Background(), partial, nil, log)
	if len(partial.deleted) != 1 || partial.deleted[0] != "topology-ebpf-dead-t-acme" {
		t.Errorf("only the abandoned view group may be deleted, got %v", partial.deleted)
	}
}

// TestTheSweepRunsOnlyWhenItCanAndIsAsked (DPR-109).
func TestTheSweepRunsOnlyWhenItCanAndIsAsked(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// every <= 0 means off, and it must return rather than spin.
		RunViewGroupSweep(context.Background(), &fakeJanitor{}, 0, nil, nil)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a disabled sweep must return immediately")
	}
}
