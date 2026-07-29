// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import "testing"

// TestBusMemoryOverflowDefaultsToBlock is the RESIL-002 config acceptance: the
// lightweight in-memory bus defaults to backpressure, not lossy ACKs. Operators
// can still explicitly select drop, but dropped publishes return an error.
func TestBusMemoryOverflowDefaultsToBlock(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	if cfg.BusMemoryOverflow != "block" {
		t.Fatalf("default PROBECTL_BUS_MEMORY_OVERFLOW = %q, want \"block\" (RESIL-002)", cfg.BusMemoryOverflow)
	}
	// "drop" must still be selectable for operators who prefer stuck-subscriber
	// isolation with retryable publish errors.
	cfgDrop, err := Load(envFunc(map[string]string{"PROBECTL_BUS_MEMORY_OVERFLOW": "drop"}))
	if err != nil {
		t.Fatalf("Load drop: %v", err)
	}
	if cfgDrop.BusMemoryOverflow != "drop" {
		t.Fatalf("explicit drop = %q, want \"drop\"", cfgDrop.BusMemoryOverflow)
	}
}
