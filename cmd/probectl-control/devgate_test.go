package main

import "testing"

// RED-001: dev auth may only ever bind loopback. Wildcards and empty hosts
// bind every interface and must be refused.
func TestLoopbackOnly(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":  true,
		"localhost:8080":  true,
		"[::1]:8080":      true,
		":8080":           false, // empty host = all interfaces
		"0.0.0.0:8080":    false,
		"[::]:8080":       false,
		"10.0.0.5:8080":   false,
		"192.168.1.2:443": false,
		"example.com:443": false,
		"127.0.0.1":       false, // no port = malformed for our listener
	}
	for addr, want := range cases {
		if got := loopbackOnly(addr); got != want {
			t.Errorf("loopbackOnly(%q) = %v, want %v", addr, got, want)
		}
	}
}
