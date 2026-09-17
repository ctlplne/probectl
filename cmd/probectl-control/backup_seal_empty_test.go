// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestBackupSealRefusesEmptyInput (DPR-091): the backup CronJobs pipe a
// producer (pg_dump, clickhouse-client, tar) into backup-seal. When that
// producer writes nothing, sealing must fail without emitting a container,
// so the job fails instead of publishing an empty "successful" backup.
func TestBackupSealRefusesEmptyInput(t *testing.T) {
	t.Setenv("PROBECTL_ENVELOPE_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("PROBECTL_ENVELOPE_OPENER_KEYS", "")

	var out bytes.Buffer
	err := runBackupIO(nil, true, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "refusing to seal empty input") {
		t.Fatalf("empty input must be refused, got err=%v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("no container bytes may be written for empty input, got %d", out.Len())
	}

	out.Reset()
	if err := runBackupIO(nil, true, strings.NewReader("pg_dump payload"), &out); err != nil {
		t.Fatalf("non-empty input must seal: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("sealing non-empty input must emit a container")
	}
	var plain bytes.Buffer
	if err := runBackupIO(nil, false, bytes.NewReader(out.Bytes()), &plain); err != nil {
		t.Fatalf("open: %v", err)
	}
	if plain.String() != "pg_dump payload" {
		t.Fatalf("round trip mismatch: %q", plain.String())
	}
}
