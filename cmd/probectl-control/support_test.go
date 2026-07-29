// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/support"
)

func TestOfflineSupportRedactsDatabaseQueryCredentials(t *testing.T) {
	const writerQueryPassword = "offline_writer_query_password_7654"
	const writerSSLPassword = "offline_writer_ssl_password_7654"
	const readerQueryPassword = "offline_reader_query_password_7654"
	const readerSSLPassword = "offline_reader_ssl_password_7654"
	cfg := &config.Config{
		DatabaseURL:     "postgres://writer@db:5432/probectl?sslmode=require&password=" + writerQueryPassword + "&sslpassword=" + writerSSLPassword + "&application_name=offline-control",
		DatabaseReadURL: "postgres://reader@read-db:5432/probectl?sslmode=verify-full&password=" + readerQueryPassword + "&sslpassword=" + readerSSLPassword + "&application_name=offline-reader",
	}
	secrets := offlineSecrets(cfg)
	joinedSecrets := strings.Join(secrets, "\n")
	for _, secret := range []string{writerQueryPassword, writerSSLPassword, readerQueryPassword, readerSSLPassword} {
		if !strings.Contains(joinedSecrets, secret) {
			t.Fatalf("database query credential missing from offline defense-in-depth scrub list")
		}
	}

	var bundle bytes.Buffer
	if _, err := support.Generate(&bundle, support.Sources{
		ConfigRedacted: cfg.Redacted(),
		Notes:          []string{"scrub check " + writerQueryPassword + " " + readerSSLPassword},
		RedactValues:   secrets,
	}); err != nil {
		t.Fatal(err)
	}
	files, err := support.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	all := bytes.Buffer{}
	for _, body := range files {
		all.Write(body)
	}
	for _, secret := range []string{writerQueryPassword, writerSSLPassword, readerQueryPassword, readerSSLPassword} {
		if bytes.Contains(all.Bytes(), []byte(secret)) {
			t.Fatalf("database query credential leaked into offline support bundle")
		}
	}

	var redacted map[string]any
	if err := json.Unmarshal(files["config-redacted.json"], &redacted); err != nil {
		t.Fatal(err)
	}
	for key, metadata := range map[string][]string{
		"database_url":      {"sslmode=require", "application_name=offline-control"},
		"database_read_url": {"sslmode=verify-full", "application_name=offline-reader"},
	} {
		dsn, _ := redacted[key].(string)
		if !strings.Contains(dsn, "xxxxx") {
			t.Fatalf("%s did not contain a redaction marker: %q", key, dsn)
		}
		for _, want := range metadata {
			if !strings.Contains(dsn, want) {
				t.Fatalf("%s lost non-secret metadata %q: %q", key, want, dsn)
			}
		}
	}
}

func TestSupportBundleDatabaseCredentialsStayRedactedForInvalidKeywordDSN(t *testing.T) {
	const (
		writerPassword = "bundle_keyword_writer_secret_4321"
		readerPassword = "bundle keyword reader secret 4321"
	)
	cfg := &config.Config{
		DatabaseURL: "host=db user=writer password=" + writerPassword + " dbname=probectl",
		DatabaseReadURL: "host=read-db user=reader password='" + readerPassword +
			"' dbname=probectl",
	}

	var bundle bytes.Buffer
	if _, err := support.Generate(&bundle, support.Sources{
		ConfigRedacted: cfg.Redacted(),
		RedactValues:   offlineSecrets(cfg),
	}); err != nil {
		t.Fatal(err)
	}
	files, err := support.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		for _, secret := range []string{writerPassword, readerPassword} {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatalf("keyword/value database credential leaked into support file %s", name)
			}
		}
	}
}
