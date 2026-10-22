// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

// TestSizedIntRangeParsers pins int32Range and int16Range, the loaders behind
// the pgx pool sizes and the bus topic partitions/replication. Each parses at
// its field's width, so a value too wide for the type falls back to the
// default with an out-of-range error instead of being narrowed, and every
// other input gets exactly intRange's result and message.
func TestSizedIntRangeParsers(t *testing.T) {
	const key = "PROBECTL_TEST_SIZED"
	const def, lo, hi = 25, -1, 1000
	for _, tc := range []struct {
		name    string
		raw     string
		want    int
		wantErr string
	}{
		{name: "unset keeps the default", raw: "", want: def},
		{name: "in range", raw: "7", want: 7},
		{name: "lower bound", raw: "-1", want: -1},
		{name: "upper bound", raw: "1000", want: 1000},
		{name: "above hi", raw: "1001", want: def, wantErr: key + ": 1001 out of range [-1,1000]"},
		{name: "below lo", raw: "-2", want: def, wantErr: key + ": -2 out of range [-1,1000]"},
		{name: "wider than int16", raw: "40000", want: def, wantErr: key + ": 40000 out of range [-1,1000]"},
		{name: "wider than int32", raw: "5000000000", want: def, wantErr: key + ": 5000000000 out of range [-1,1000]"},
		{name: "below int32", raw: "-5000000000", want: def, wantErr: key + ": -5000000000 out of range [-1,1000]"},
		{name: "not a number", raw: "lots", want: def, wantErr: key + `: invalid integer "lots"`},
		{name: "exponent form", raw: "1e3", want: def, wantErr: key + `: invalid integer "1e3"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := func(k string) string {
				if k == key {
					return tc.raw
				}
				return ""
			}
			base := &loader{getenv: env}
			wide := &loader{getenv: env}
			narrow := &loader{getenv: env}
			gotInt := base.intRange(key, def, lo, hi)
			got32 := wide.int32Range(key, def, lo, hi)
			got16 := narrow.int16Range(key, def, lo, hi)
			if gotInt != tc.want || int(got32) != tc.want || int(got16) != tc.want {
				t.Fatalf("intRange/int32Range/int16Range(%q) = %d/%d/%d, want %d", tc.raw, gotInt, got32, got16, tc.want)
			}
			for name, l := range map[string]*loader{"intRange": base, "int32Range": wide, "int16Range": narrow} {
				err := l.err()
				if tc.wantErr == "" {
					if err != nil {
						t.Errorf("%s(%q): unexpected error %v", name, tc.raw, err)
					}
					continue
				}
				if err == nil || err.Error() != tc.wantErr {
					t.Errorf("%s(%q) error = %v, want %q", name, tc.raw, err, tc.wantErr)
				}
			}
		})
	}
}

// TestSizedIntConfigKeys checks the wiring: the typed keys keep their defaults
// and bounds, and a value too wide for the field fails the load naming the key.
func TestSizedIntConfigKeys(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseMaxConns != 25 || cfg.DatabaseMinConns != 2 || cfg.BusTopicPartitions != 3 || cfg.BusTopicReplication != -1 {
		t.Fatalf("defaults = max %d / min %d / partitions %d / replication %d, want 25 / 2 / 3 / -1",
			cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.BusTopicPartitions, cfg.BusTopicReplication)
	}
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_BUS_TOPIC_PARTITIONS":  "1024",
		"PROBECTL_BUS_TOPIC_REPLICATION": "32",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BusTopicPartitions != 1024 || cfg.BusTopicReplication != 32 {
		t.Fatalf("upper bounds = %d / %d, want 1024 / 32", cfg.BusTopicPartitions, cfg.BusTopicReplication)
	}
	for key, raw := range map[string]string{
		"PROBECTL_DATABASE_MAX_CONNS":    "4294967298",
		"PROBECTL_DATABASE_MIN_CONNS":    "-4294967296",
		"PROBECTL_BUS_TOPIC_PARTITIONS":  "4294967297",
		"PROBECTL_BUS_TOPIC_REPLICATION": "65537",
	} {
		_, err := Load(envFunc(map[string]string{key: raw}))
		if err == nil || !strings.Contains(err.Error(), key+": "+raw+" out of range") {
			t.Errorf("%s=%s must fail as out of range, got %v", key, raw, err)
		}
	}
}
