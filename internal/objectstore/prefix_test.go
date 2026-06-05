package objectstore

import (
	"context"
	"testing"
)

// The S-T5 prefix surface: List + DeletePrefix on both implementations —
// tenant-scoped deletion removes exactly one namespace and verifies empty.
func runPrefixSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	seed := map[string]string{
		TenantKey("tnA", "browser", "a1.png"):         "a1",
		TenantKey("tnA", "browser", "deep", "a2.png"): "a2",
		"silo/tnA/browser/a3.png":                     "a3",
		TenantKey("tnB", "browser", "b1.png"):         "b1",
	}
	for k, body := range seed {
		if err := s.Put(ctx, k, "image/png", []byte(body)); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}

	// List is prefix-exact and sorted.
	keys, err := s.List(ctx, "tenant/tnA/")
	if err != nil || len(keys) != 2 {
		t.Fatalf("list tnA: %v %v", keys, err)
	}
	if keys[0] != "tenant/tnA/browser/a1.png" || keys[1] != "tenant/tnA/browser/deep/a2.png" {
		t.Fatalf("list order/content: %v", keys)
	}
	if keys, _ := s.List(ctx, "tenant/ghost/"); len(keys) != 0 {
		t.Fatalf("ghost prefix must list empty: %v", keys)
	}

	// DeletePrefix removes exactly the namespace, across nesting.
	n, err := s.DeletePrefix(ctx, "tenant/tnA/")
	if err != nil || n != 2 {
		t.Fatalf("delete tnA: n=%d err=%v", n, err)
	}
	if keys, _ := s.List(ctx, "tenant/tnA/"); len(keys) != 0 {
		t.Fatalf("tnA must verify empty: %v", keys)
	}
	// The silo namespace and tenant B are untouched until asked.
	if keys, _ := s.List(ctx, "silo/tnA/"); len(keys) != 1 {
		t.Fatalf("silo namespace must be untouched: %v", keys)
	}
	if keys, _ := s.List(ctx, "tenant/tnB/"); len(keys) != 1 {
		t.Fatalf("tenant B must be untouched: %v", keys)
	}
	if n, err := s.DeletePrefix(ctx, "silo/tnA/"); err != nil || n != 1 {
		t.Fatalf("delete silo: n=%d err=%v", n, err)
	}
	// Idempotent: deleting an already-empty prefix is a clean zero.
	if n, err := s.DeletePrefix(ctx, "tenant/tnA/"); err != nil || n != 0 {
		t.Fatalf("re-delete: n=%d err=%v", n, err)
	}
	// Empty prefix is a refused no-op (never a wipe-everything).
	if n, err := s.DeletePrefix(ctx, ""); err != nil || n != 0 {
		t.Fatalf("empty prefix: n=%d err=%v", n, err)
	}
	if keys, _ := s.List(ctx, "tenant/tnB/"); len(keys) != 1 {
		t.Fatalf("tenant B survived everything: %v", keys)
	}
}

func TestMemStorePrefixes(t *testing.T) { runPrefixSuite(t, NewMemory()) }

func TestFSStorePrefixes(t *testing.T) {
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runPrefixSuite(t, s)

	// Traversal defense: a hostile prefix is refused, never walked.
	if _, err := s.DeletePrefix(context.Background(), "../escape/"); err == nil {
		t.Fatal("traversal prefix must be refused")
	}
}
