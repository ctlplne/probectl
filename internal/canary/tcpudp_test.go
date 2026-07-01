// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		target, port       string
		wantHost, wantPort string
		wantErr            bool
	}{
		{"example.com:443", "", "example.com", "443", false},
		{"example.com", "8080", "example.com", "8080", false},
		{"10.0.0.1:53", "", "10.0.0.1", "53", false},
		{"[::1]:80", "", "::1", "80", false},
		{"example.com", "", "", "", true}, // no port anywhere
		{"", "", "", "", true},            // empty target
		{"host", "99999", "", "", true},   // out-of-range port
	}
	for _, c := range cases {
		h, p, err := splitTarget(c.target, c.port)
		if c.wantErr {
			if err == nil {
				t.Errorf("splitTarget(%q,%q): want error", c.target, c.port)
			}
			continue
		}
		if err != nil || h != c.wantHost || p != c.wantPort {
			t.Errorf("splitTarget(%q,%q) = %q,%q,%v; want %q,%q", c.target, c.port, h, p, err, c.wantHost, c.wantPort)
		}
	}
}

func TestNewTCPParams(t *testing.T) {
	if _, err := NewTCP(Config{Type: "tcp"}); err == nil {
		t.Error("missing target should error")
	}
	if _, err := NewTCP(Config{Type: "tcp", Target: "h"}); err == nil {
		t.Error("target without a port should error")
	}
	got, err := NewTCP(Config{Type: "tcp", Target: "h:80"})
	if err != nil {
		t.Fatal(err)
	}
	if c := got.(*tcpCanary); c.count != 3 || c.host != "h" || c.port != "80" {
		t.Errorf("tcp defaults wrong: %+v", c)
	}
	if _, err := NewTCP(Config{Type: "tcp", Target: "h:80", Params: map[string]string{"dscp": "64"}}); err == nil {
		t.Error("dscp 64 (out of range) should error")
	}
}

func TestNewUDPParams(t *testing.T) {
	got, err := NewUDP(Config{Type: "udp", Target: "h", Params: map[string]string{"port": "9", "count": "7", "payload_bytes": "20"}})
	if err != nil {
		t.Fatal(err)
	}
	if c := got.(*udpCanary); c.count != 7 || c.payload != 20 || c.port != "9" {
		t.Errorf("udp params wrong: %+v", c)
	}
	if _, err := NewUDP(Config{Type: "udp", Target: "h:9", Params: map[string]string{"payload_bytes": "4"}}); err == nil {
		t.Error("payload_bytes below the header size should error")
	}
}

func TestUDPDialFailureReturnsFailedResult(t *testing.T) {
	c, err := NewUDP(Config{
		Type: "udp", Target: "127.0.0.1:0", Timeout: time.Millisecond,
		Params: map[string]string{"allow_private_targets": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("dial failure returned plugin error: %v", err)
	}
	if res.Success || res.Error == "" || !strings.Contains(res.Error, "dial") {
		t.Fatalf("dial failure result = %+v", res)
	}
	if res.Duration <= 0 || res.Type != udpType || res.Target != "127.0.0.1:0" {
		t.Fatalf("dial failure metadata = %+v", res)
	}
}
