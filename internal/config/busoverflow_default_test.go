// SPDX-License-Identifier: LicenseRef-probectl-TBD

package config

import "testing"

// TestBusMemoryOverflowDefaultsToBlock is the RESIL-002 config acceptance: the
// lightweight in-memory bus defaults to backpressure, not lossy ACKs. Operators
// can still explicitly select drop, but dropped publishes return an error.
func TestBusMemoryOverflowDefaultsToBlock(t *testing.T) {
	cfg, err := Load(func(string) string { return "" }) // empty env = all defaults
	if err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	if cfg.BusMemoryOverflow != "block" {
		t.Fatalf("default PROBECTL_BUS_MEMORY_OVERFLOW = %q, want \"block\" (RESIL-002)", cfg.BusMemoryOverflow)
	}
	// "drop" must still be selectable for operators who prefer stuck-subscriber
	// isolation with retryable publish errors.
	cfgDrop, err := Load(func(k string) string {
		if k == "PROBECTL_BUS_MEMORY_OVERFLOW" {
			return "drop"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load drop: %v", err)
	}
	if cfgDrop.BusMemoryOverflow != "drop" {
		t.Fatalf("explicit drop = %q, want \"drop\"", cfgDrop.BusMemoryOverflow)
	}
}
