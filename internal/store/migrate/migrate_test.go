// SPDX-License-Identifier: LicenseRef-probectl-TBD

package migrate

import (
	"testing"
	"testing/fstest"
)

func TestParseName(t *testing.T) {
	cases := []struct {
		in       string
		wantVer  int64
		wantName string
		wantErr  bool
	}{
		{"0001_baseline.sql", 1, "baseline", false},
		{"0042_add_tenants.sql", 42, "add_tenants", false},
		{"nope.sql", 0, "", true},  // no underscore
		{"_x.sql", 0, "", true},    // empty version
		{"abc_x.sql", 0, "", true}, // non-numeric version
	}
	for _, c := range cases {
		ver, name, err := parseName(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr = %v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && (ver != c.wantVer || name != c.wantName) {
			t.Errorf("%s: got (%d, %q), want (%d, %q)", c.in, ver, name, c.wantVer, c.wantName)
		}
	}
}

func TestLoadSortsByVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"0002_b.sql": {Data: []byte("SELECT 2;")},
		"0001_a.sql": {Data: []byte("SELECT 1;")},
		"0010_c.sql": {Data: []byte("SELECT 10;")},
	}
	ms, err := New(fsys, nil).load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := []int64{ms[0].Version, ms[1].Version, ms[2].Version}
	want := []int64{1, 2, 10}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestLoadMarksNoTxMigrations(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_a.sql": {Data: []byte("-- probectl:no-tx: concurrent index cannot run inside a transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS i ON t (a);")},
		"0002_b.sql": {Data: []byte("-- probectl:no-tx\nCREATE INDEX CONCURRENTLY IF NOT EXISTS j ON t (b);")},
	}
	ms, err := New(fsys, nil).load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ms[0].NoTx {
		t.Fatal("reasoned no-tx directive was not recognized")
	}
	if ms[1].NoTx {
		t.Fatal("reason-less no-tx directive must not enable non-transactional mode")
	}
}

func TestLoadRejectsDuplicateVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_a.sql": {Data: []byte("x")},
		"0001_b.sql": {Data: []byte("y")},
	}
	if _, err := New(fsys, nil).load(); err == nil {
		t.Error("expected an error for duplicate migration versions")
	}
}
