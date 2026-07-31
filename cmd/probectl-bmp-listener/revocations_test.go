// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	probectlc "github.com/imfeelingtheagi/probectl/internal/crypto"
)

type revocationSnapshot struct {
	serials []string
	ids     []string
	err     error
}

type scriptedRevocationSource struct {
	snapshots []revocationSnapshot
	next      int
}

func (s *scriptedRevocationSource) List(context.Context) ([]string, []string, error) {
	if s.next >= len(s.snapshots) {
		return nil, nil, errors.New("unexpected revocation snapshot read")
	}
	snapshot := s.snapshots[s.next]
	s.next++
	return snapshot.serials, snapshot.ids, snapshot.err
}

func TestBMPRevocationStartupRequiresAuthoritativeSnapshot(t *testing.T) {
	source := &scriptedRevocationSource{
		snapshots: []revocationSnapshot{{err: errors.New("database unavailable")}},
	}
	feed, err := newBMPRevocationFeed(
		source,
		probectlc.NewRevocationList(),
		time.Second,
		10*time.Millisecond,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.loadInitialRevocations(context.Background()); err == nil {
		t.Fatal("BMP startup accepted no authoritative revocation snapshot")
	}
}

func TestBMPRevocationReplaceRetainsLastValidSnapshotAndTenant(t *testing.T) {
	const (
		tenantAID = "spiffe://probectl/tenant/tenant-a/bmp/router-a"
		tenantBID = "spiffe://probectl/tenant/tenant-b/bmp/router-b"
	)
	source := &scriptedRevocationSource{
		snapshots: []revocationSnapshot{
			{serials: []string{"aa"}, ids: []string{tenantAID}},
			{err: errors.New("refresh timeout")},
			{serials: []string{"bb"}, ids: []string{tenantBID}},
		},
	}
	list := probectlc.NewRevocationList()
	feed, err := newBMPRevocationFeed(
		source,
		list,
		time.Second,
		10*time.Millisecond,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.loadInitialRevocations(context.Background()); err != nil {
		t.Fatalf("load initial snapshot: %v", err)
	}
	if !list.IsRevoked("aa", tenantAID) {
		t.Fatal("initial tenant-A revocation was not installed")
	}
	if list.IsRevoked("bb", tenantBID) {
		t.Fatal("unrelated tenant B was revoked by tenant A's snapshot")
	}

	if err := feed.replace(context.Background()); err == nil {
		t.Fatal("failed refresh unexpectedly succeeded")
	}
	if !list.IsRevoked("aa", tenantAID) {
		t.Fatal("failed refresh discarded the last valid tenant-A snapshot")
	}
	if list.IsRevoked("bb", tenantBID) {
		t.Fatal("failed refresh changed unrelated tenant B")
	}

	if err := feed.replace(context.Background()); err != nil {
		t.Fatalf("replace snapshot: %v", err)
	}
	if list.IsRevoked("aa", tenantAID) {
		t.Fatal("successful replacement retained stale tenant-A revocation")
	}
	if !list.IsRevoked("bb", tenantBID) {
		t.Fatal("successful replacement omitted tenant-B revocation")
	}
}

func TestBMPRevocationDatabaseURLRequiresVerifyFull(t *testing.T) {
	if err := validateBMPRevocationDatabaseURL(
		"postgres://bmp@db.internal:5432/probectl?sslmode=verify-full",
	); err != nil {
		t.Fatalf("verify-full URL rejected: %v", err)
	}
	for _, raw := range []string{
		"",
		"postgres://bmp@db.internal:5432/probectl",
		"postgres://bmp@db.internal:5432/probectl?sslmode=disable",
		"postgres://bmp@db.internal:5432/probectl?sslmode=require",
		"postgres://bmp@db.internal:5432/probectl?sslmode=verify-full&sslmode=disable",
		"http://db.internal/probectl?sslmode=verify-full",
	} {
		if err := validateBMPRevocationDatabaseURL(raw); err == nil {
			t.Errorf("unsafe revocation database URL accepted: %q", raw)
		}
	}
}

func TestBMPDatabaseURLsRequireVerifyFull(t *testing.T) {
	secure := "postgres://bmp@db.internal:5432/probectl?sslmode=verify-full"
	if err := validateBMPDatabaseURLs(secure, secure); err != nil {
		t.Fatalf("secure identity and revocation URLs rejected: %v", err)
	}

	for name, urls := range map[string][2]string{
		"identity missing sslmode": {
			"postgres://bmp@db.internal:5432/probectl",
			secure,
		},
		"identity does not verify server": {
			"postgres://bmp@db.internal:5432/probectl?sslmode=require",
			secure,
		},
		"revocation missing sslmode": {
			secure,
			"postgres://bmp@db.internal:5432/probectl",
		},
		"revocation does not verify server": {
			secure,
			"postgres://bmp@db.internal:5432/probectl?sslmode=require",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateBMPDatabaseURLs(urls[0], urls[1]); err == nil {
				t.Fatal("unsafe BMP database URL pair accepted")
			}
		})
	}
}
