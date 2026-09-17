// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"strings"
	"testing"
)

// DPR-007: a base64 password with '/' spliced into the URL (exactly what the
// old .env.example generator produced) must yield an actionable error that
// never echoes the credential.
func TestDatabaseURLParseErrorIsActionableAndSecretFree(t *testing.T) {
	const secret = "abc/def+ghi="
	env := map[string]string{
		"PROBECTL_DATABASE_URL": "postgres://probectl:" + secret + "@postgres:5432/probectl?sslmode=require",
	}
	_, err := Load(func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("a URL with an unencoded '/' in the password must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "percent-encoded") || !strings.Contains(msg, "openssl rand -hex 24") {
		t.Fatalf("error must tell the operator the likely cause and the fix, got: %s", msg)
	}
	if strings.Contains(msg, secret) || strings.Contains(msg, "abc/def") {
		t.Fatalf("error must not echo the credential, got: %s", msg)
	}
	if strings.Contains(msg, "must be a postgres:// or postgresql:// URL") {
		t.Fatalf("the old misleading wording is back: %s", msg)
	}
}
