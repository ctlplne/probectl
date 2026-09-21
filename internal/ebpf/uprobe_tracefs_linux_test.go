// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"strings"
	"testing"
)

// The tracefs command format is unforgiving and its failure mode is a bare
// EINVAL from write(2), which names nothing. These cases are the ones that
// produce that errno on a real kernel.
func TestUprobeEventLine(t *testing.T) {
	line, err := uprobeEventLine(false, "probectl", "SSL_write_ab12cd", "/usr/lib/x86_64-linux-gnu/libssl.so.3", 0x3b8f0)
	if err != nil {
		t.Fatalf("entry probe: %v", err)
	}
	if want := "p:probectl/SSL_write_ab12cd /usr/lib/x86_64-linux-gnu/libssl.so.3:0x3b8f0\n"; line != want {
		t.Errorf("entry probe line =\n  %q\nwant\n  %q", line, want)
	}
	ret, err := uprobeEventLine(true, "probectl", "SSL_read_ab12cd", "/lib/libssl.so.3", 0x10)
	if err != nil {
		t.Fatalf("return probe: %v", err)
	}
	if !strings.HasPrefix(ret, "r:") {
		t.Errorf("a return probe must start with r:, got %q", ret)
	}
}

func TestUprobeEventLineRefusesWhatTheKernelCannotParse(t *testing.T) {
	for _, tc := range []struct {
		name, group, event, path, want string
	}{
		{"a relative path", "probectl", "p1", "lib/libssl.so.3", "must be absolute"},
		{"a path with a space", "probectl", "p1", "/opt/my libs/libssl.so.3", "space, a colon or a newline"},
		{"a path with a colon", "probectl", "p1", "/opt/a:b/libssl.so.3", "space, a colon or a newline"},
		{"a newline in the path", "probectl", "p1", "/lib/libssl.so.3\np:evil/x /bin/sh:0x0", "space, a colon or a newline"},
		{"an empty path", "probectl", "p1", "", "library path is required"},
		{"a slash in the event name", "probectl", "a/b", "/lib/libssl.so.3", "may not contain"},
		{"an empty name", "probectl", "", "/lib/libssl.so.3", "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := uprobeEventLine(false, tc.group, tc.event, tc.path, 0x10)
			if err == nil {
				t.Fatal("expected a refusal with a sentence, got a line")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// The event name is kernel-global, so it has to be both legal and unique. A
// symbol like "SSL_write@@OPENSSL_3.0.0" is a realistic input.
func TestSanitizeEventName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"SSL_write", "SSL_write"},
		{"SSL_write@@OPENSSL_3.0.0", "SSL_write__OPENSSL_3_0_0"},
		{"", "probe"},
		{strings.Repeat("x", 80), strings.Repeat("x", 40)},
	} {
		if got := sanitizeEventName(tc.in); got != tc.want {
			t.Errorf("sanitizeEventName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// findTracefs must say what it looked for: "not mounted" sends an operator to
// their container spec, and the two paths tell them what to mount.
func TestFindTracefsNamesWhatItLookedFor(t *testing.T) {
	if _, err := findTracefs(); err != nil {
		for _, want := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing", "mounted"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	}
	// When tracefs IS present (a Linux CI host), there is nothing to assert
	// beyond it not lying about it, which the call above already covers.
}
