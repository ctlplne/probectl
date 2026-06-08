package threat

import "testing"

// THREAT-001: CGNAT (100.64.0.0/10) classifies as INTERNAL alongside
// RFC1918 / loopback / link-local / ULA; genuine public addresses (incl. the
// ranges just outside CGNAT) stay external.
func TestIsInternalClassification(t *testing.T) {
	internal := []string{
		"10.0.0.1", "172.16.5.5", "192.168.1.1", // RFC1918
		"127.0.0.1", "169.254.1.1", "fc00::1", // loopback, link-local, ULA
		"100.64.0.1", "100.127.255.254", "100.64.1.2:443", // CGNAT (incl. host:port)
		"not-an-ip.svc.cluster.local", // non-IP entity → internal service name
	}
	for _, a := range internal {
		if !isInternal(a) {
			t.Errorf("%q should be internal", a)
		}
	}
	external := []string{
		"8.8.8.8", "1.1.1.1", "203.0.113.7", // public v4
		"100.63.255.255", "100.128.0.1", // just OUTSIDE 100.64/10
		"2606:4700::1111", // public v6
	}
	for _, a := range external {
		if isInternal(a) {
			t.Errorf("%q should be external", a)
		}
	}
}
