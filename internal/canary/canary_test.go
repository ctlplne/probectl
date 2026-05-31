package canary

import (
	"context"
	"testing"
)

func TestNoop(t *testing.T) {
	c, err := NewNoop(Config{Type: "noop", Target: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Describe().Type != "noop" {
		t.Errorf("Describe().Type = %q, want noop", c.Describe().Type)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Success || res.Type != "noop" || res.Target != "x" {
		t.Errorf("result = %+v", res)
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.Register("noop", NewNoop)

	c, err := r.New(Config{Type: "noop"})
	if err != nil || c == nil {
		t.Fatalf("new: %v / %v", c, err)
	}
	if _, err := r.New(Config{Type: "missing"}); err == nil {
		t.Error("an unknown canary type should error")
	}
	if types := r.Types(); len(types) != 1 || types[0] != "noop" {
		t.Errorf("Types() = %v, want [noop]", types)
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a duplicate registration should panic")
		}
	}()
	r := NewRegistry()
	r.Register("noop", NewNoop)
	r.Register("noop", NewNoop) // must panic
}
