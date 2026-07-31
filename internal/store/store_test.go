// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestOpenDatabaseParseErrorDoesNotDiscloseCredentials(t *testing.T) {
	const canary = "planted-query-credential-7c74"
	raw := "postgres://writer:" + canary + "@db.invalid/probectl" +
		"?sslmode=verify-full&password=" + canary +
		"&sslpassword=" + canary +
		"&pool_max_conns=not-an-integer"

	db, err := Open(context.Background(), raw, 4, 0, time.Second)
	if db != nil {
		db.Close()
	}
	if err == nil {
		t.Fatal("invalid PostgreSQL pool option was accepted")
	}
	message := err.Error()
	if strings.Contains(message, canary) || strings.Contains(message, raw) {
		t.Fatal("database parse error disclosed a planted credential")
	}
	if !strings.Contains(message, "parse database url") {
		t.Fatalf("database parse error lost bounded operator guidance: %q", message)
	}

	db, err = Open(
		context.Background(),
		"postgres://writer@db.invalid/probectl?sslmode=verify-full&pool_max_conns=4",
		4,
		0,
		time.Second,
	)
	if err != nil {
		t.Fatalf("valid PostgreSQL URL rejected: %v", err)
	}
	db.Close()
}
