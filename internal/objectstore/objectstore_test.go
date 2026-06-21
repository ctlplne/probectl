// SPDX-License-Identifier: LicenseRef-probectl-TBD

package objectstore

import (
	"context"
	"errors"
	"testing"
)

func TestTenantKey(t *testing.T) {
	if got := TenantKey("t1", "browser", "run-9.png"); got != "tenant/t1/browser/run-9.png" {
		t.Fatalf("TenantKey = %q", got)
	}
}

func TestValidKey(t *testing.T) {
	for _, bad := range []string{"", "/abs", "a/../../etc/passwd", "x\x00y", "..", "a/.."} {
		if err := validKey(bad); err == nil {
			t.Fatalf("validKey(%q) should reject", bad)
		}
	}
	for _, ok := range []string{"a", "tenant/t1/browser/r.png", "a/b/c"} {
		if err := validKey(ok); err != nil {
			t.Fatalf("validKey(%q) should accept: %v", ok, err)
		}
	}
}

// runStoreSuite exercises the Store contract against any implementation.
func runStoreSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	key := TenantKey("t1", "browser", "login-1.png")

	if _, _, err := s.Stat(ctx, key); err != nil {
		t.Fatalf("stat missing: %v", err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing should be ErrNotFound, got %v", err)
	}

	data := []byte("\x89PNG fake screenshot bytes")
	if err := s.Put(ctx, key, "image/png", data); err != nil {
		t.Fatalf("put: %v", err)
	}
	o, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(o.Data) != string(data) || o.ContentType != "image/png" || o.Size != int64(len(data)) {
		t.Fatalf("round-trip mismatch: %+v", o)
	}
	if size, exists, err := s.Stat(ctx, key); err != nil || !exists || size != int64(len(data)) {
		t.Fatalf("stat: size=%d exists=%v err=%v", size, exists, err)
	}

	// Tenant isolation: a different tenant's key is a different object.
	other := TenantKey("t2", "browser", "login-1.png")
	if _, exists, _ := s.Stat(ctx, other); exists {
		t.Fatal("tenant t2 must not see tenant t1's object")
	}

	// Default content type when empty.
	_ = s.Put(ctx, "tenant/t1/x", "", []byte("x"))
	if o, _ := s.Get(ctx, "tenant/t1/x"); o.ContentType != "application/octet-stream" {
		t.Fatalf("default content type: %q", o.ContentType)
	}

	// Path traversal is rejected.
	if err := s.Put(ctx, "tenant/t1/../../escape", "text/plain", []byte("x")); err == nil {
		t.Fatal("traversal key must be rejected")
	}
}

func TestMemStore(t *testing.T) { runStoreSuite(t, NewMemory()) }

func TestFSStore(t *testing.T) {
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("new fs: %v", err)
	}
	runStoreSuite(t, s)
}

func TestFSStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	s1, _ := NewFS(dir)
	_ = s1.Put(context.Background(), "tenant/t1/a.txt", "text/plain", []byte("hello"))

	s2, _ := NewFS(dir) // a fresh handle on the same dir
	o, err := s2.Get(context.Background(), "tenant/t1/a.txt")
	if err != nil || string(o.Data) != "hello" || o.ContentType != "text/plain" {
		t.Fatalf("persisted get: %+v err=%v", o, err)
	}
}

func runTenantStoreSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	ta, err := ForTenant(s, "tnA")
	if err != nil {
		t.Fatalf("tenant A handle: %v", err)
	}
	tb, err := ForTenant(s, "tnB")
	if err != nil {
		t.Fatalf("tenant B handle: %v", err)
	}
	if err := ta.Put(ctx, "browser/a.png", "image/png", []byte("a")); err != nil {
		t.Fatalf("put tenant A: %v", err)
	}
	if err := tb.Put(ctx, "browser/b.png", "image/png", []byte("b")); err != nil {
		t.Fatalf("put tenant B: %v", err)
	}

	got, err := ta.Get(ctx, "browser/a.png")
	if err != nil || string(got.Data) != "a" {
		t.Fatalf("tenant A get own object: %q err=%v", got.Data, err)
	}
	if _, err := ta.Get(ctx, "browser/b.png"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant A must not read tenant B relative path: %v", err)
	}
	if _, err := ta.Get(ctx, "tenant/tnB/browser/b.png"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant A must not escape through B-shaped key text: %v", err)
	}
	if _, err := ta.Get(ctx, "../tnB/browser/b.png"); err == nil {
		t.Fatal("tenant-bound paths must reject traversal")
	}

	keys, err := ta.List(ctx, "")
	if err != nil {
		t.Fatalf("tenant A list: %v", err)
	}
	if len(keys) != 1 || keys[0] != "browser/a.png" {
		t.Fatalf("tenant A list must return only relative tenant A keys: %v", keys)
	}
	if ta.Key("browser/a.png") != "tenant/tnA/browser/a.png" {
		t.Fatalf("tenant A full key: %q", ta.Key("browser/a.png"))
	}

	n, err := ta.DeletePrefix(ctx, "")
	if err != nil || n != 1 {
		t.Fatalf("tenant A delete root: n=%d err=%v", n, err)
	}
	if keys, _ := ta.List(ctx, ""); len(keys) != 0 {
		t.Fatalf("tenant A should be empty after delete: %v", keys)
	}
	if keys, _ := tb.List(ctx, ""); len(keys) != 1 || keys[0] != "browser/b.png" {
		t.Fatalf("tenant B must survive tenant A delete: %v", keys)
	}

	siloA, err := ForTenantPrefix(s, "silo/tnA", "tnA")
	if err != nil {
		t.Fatalf("silo tenant A handle: %v", err)
	}
	siloB, err := ForTenantPrefix(s, "silo/tnB", "tnB")
	if err != nil {
		t.Fatalf("silo tenant B handle: %v", err)
	}
	_ = siloA.Put(ctx, "browser/a.png", "image/png", []byte("sa"))
	_ = siloB.Put(ctx, "browser/b.png", "image/png", []byte("sb"))
	if _, err := siloA.Get(ctx, "browser/b.png"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("silo tenant A must not read silo tenant B: %v", err)
	}
	if siloA.Key("browser/a.png") != "silo/tnA/browser/a.png" {
		t.Fatalf("silo tenant A full key: %q", siloA.Key("browser/a.png"))
	}
	if n, err := siloA.DeletePrefix(ctx, ""); err != nil || n != 1 {
		t.Fatalf("silo tenant A delete root: n=%d err=%v", n, err)
	}
	if keys, _ := siloB.List(ctx, ""); len(keys) != 1 {
		t.Fatalf("silo tenant B must survive tenant A delete: %v", keys)
	}
}

func TestMemTenantStoreIsolation(t *testing.T) { runTenantStoreSuite(t, NewMemory()) }

func TestFSTenantStoreIsolation(t *testing.T) {
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runTenantStoreSuite(t, s)
}

func TestTenantStoreRejectsInvalidScope(t *testing.T) {
	s := NewMemory()
	for _, tenantID := range []string{"", "a/b", "a\\b", "..", "a\x00b"} {
		if _, err := ForTenant(s, tenantID); err == nil {
			t.Fatalf("ForTenant(%q) should reject invalid tenant id", tenantID)
		}
	}
	if _, err := ForTenantPrefix(s, "../escape", "tnA"); err == nil {
		t.Fatal("ForTenantPrefix should reject traversal prefixes")
	}
	if _, err := ForTenant(nil, "tnA"); err == nil {
		t.Fatal("ForTenant should reject nil stores")
	}
}
