// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestInstallCHReaderPolicyRequiresReaderUser(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	enableCalled := false

	err := installCHReaderPolicy(true, " \t", "flowstore", "RED-001", log,
		func() (func(context.Context, string) error, bool) {
			enableCalled = true
			return func(context.Context, string) error {
				t.Fatal("ensure must not be called with a blank reader user")
				return nil
			}, true
		})
	if err == nil {
		t.Fatal("blank reader user should fail closed")
	}
	if !strings.Contains(err.Error(), "reader user is unset") || !strings.Contains(err.Error(), "RED-001") {
		t.Fatalf("error %q missing fail-closed context", err)
	}
	if !enableCalled {
		t.Fatal("ClickHouse-backed lane should be detected before refusing the blank reader")
	}
}

func TestInstallCHReaderPolicySkipsNonClickHouseStore(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := installCHReaderPolicy(true, "", "pathstore", "RED-001", log,
		func() (func(context.Context, string) error, bool) {
			return nil, false
		}); err != nil {
		t.Fatalf("memory/non-ClickHouse store should be a no-op: %v", err)
	}
}

func TestInstallCHReaderPolicyInstallsTrimmedReaderPolicy(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gotUser string

	err := installCHReaderPolicy(true, " probectl_reader ", "otelstore", "RED-001", log,
		func() (func(context.Context, string) error, bool) {
			return func(_ context.Context, user string) error {
				gotUser = user
				return nil
			}, true
		})
	if err != nil {
		t.Fatalf("install policy: %v", err)
	}
	if gotUser != "probectl_reader" {
		t.Fatalf("reader user = %q, want trimmed probectl_reader", gotUser)
	}
}

func TestInstallCHReaderPolicyPropagatesInstallError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	installErr := errors.New("ddl denied")

	err := installCHReaderPolicy(true, "probectl_reader", "ebpfstore", "RED-001", log,
		func() (func(context.Context, string) error, bool) {
			return func(context.Context, string) error { return installErr }, true
		})
	if !errors.Is(err, installErr) {
		t.Fatalf("install error = %v, want %v", err, installErr)
	}
}
