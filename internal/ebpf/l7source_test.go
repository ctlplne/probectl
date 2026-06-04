package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
)

func TestFixtureL7SourceReplays(t *testing.T) {
	s, err := NewFixtureL7Source("testdata/l7.json")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ch, err := s.L7Events(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var reqs, resps int
	for ev := range ch {
		if ev.Data.Kind == l7.Request {
			reqs++
			if ev.Destination.Port != 8443 || ev.Source.Workload != "checkout" || !ev.Encrypted {
				t.Errorf("request event missing connection context: %+v", ev)
			}
		} else {
			resps++
		}
	}
	if reqs != 2 || resps != 2 {
		t.Errorf("replayed %d requests + %d responses, want 2 + 2", reqs, resps)
	}
	if s.Drops() != 0 {
		t.Errorf("fixture drops = %d, want 0", s.Drops())
	}
}

func TestFixtureL7SourceMissingFile(t *testing.T) {
	if _, err := NewFixtureL7Source("testdata/does-not-exist.json"); err == nil {
		t.Error("expected error for missing l7 fixture")
	}
}
