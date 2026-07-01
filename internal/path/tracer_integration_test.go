// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package path

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRunLoopback proves the tracer end to end against a reachable destination: a
// trace to loopback resolves, probes, parses the Echo Reply, and merges into a
// Path with the destination as a hop node. Full multi-hop ECMP/MPLS discovery
// needs raw sockets (privileged) and is covered by the merge/parse fixtures; this
// test runs on the unprivileged datagram socket and skips if even that is
// restricted.
func TestRunLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := Config{Target: "127.0.0.1", Mode: "icmp", TraceCount: 2, MaxHops: 5, PerHopTimeout: time.Second}
	p, err := Run(ctx, cfg)
	if err != nil {
		t.Skipf("path trace unavailable (sockets restricted): %v", err)
	}
	if p.TargetIP != "127.0.0.1" {
		t.Errorf("target ip = %q, want 127.0.0.1", p.TargetIP)
	}
	if p.TraceCount != 2 {
		t.Errorf("trace count = %d, want 2", p.TraceCount)
	}
	if !p.DestinationReached {
		t.Fatalf("loopback destination not reached: %+v", p)
	}
	found := false
	for _, h := range p.Hops {
		for _, n := range h.Nodes {
			if n.IP == "127.0.0.1" {
				found = true
				if n.Received == 0 {
					t.Errorf("destination node has no responses: %+v", n)
				}
			}
		}
	}
	if !found {
		t.Errorf("destination is not a hop node: %+v", p.Hops)
	}
}

// TestRunRawMultiHop proves the privileged raw-socket path against a real
// multi-hop Linux namespace fixture. The parent test creates:
//
//	src -> r1 -> r2 -> dst
//
// then re-execs this same test binary inside the src namespace. The child must
// open a raw ICMP socket (CAP_NET_RAW) and observe two intermediate TTL
// responders before the destination. Local non-Linux/unprivileged runs may skip;
// CI sets PROBECTL_TEST_REQUIRE_RAW_PATH=1 so missing privilege is a hard fail.
func TestRunRawMultiHop(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_PATH_RAW_CHILD") == "1" {
		runRawMultiHopChild(t)
		return
	}
	if runtime.GOOS != "linux" {
		rawPathUnavailable(t, "raw multi-hop fixture requires Linux network namespaces")
		return
	}
	if os.Geteuid() != 0 {
		rawPathUnavailable(t, "raw multi-hop fixture requires root to create namespaces and veth links")
		return
	}
	if _, err := exec.LookPath("ip"); err != nil {
		rawPathUnavailable(t, "raw multi-hop fixture requires iproute2: %v", err)
		return
	}

	fixture := setupRawMultiHopFixture(t)
	cmd := exec.Command("ip", "netns", "exec", fixture.srcNS, os.Args[0], "-test.run=^TestRunRawMultiHop$", "-test.v")
	cmd.Env = append(os.Environ(),
		"PROBECTL_TEST_PATH_RAW_CHILD=1",
		"PROBECTL_TEST_PATH_RAW_TARGET="+fixture.dstIP,
	)
	out, err := cmd.CombinedOutput()
	t.Logf("raw multi-hop child output:\n%s", out)
	if bytes.Contains(out, []byte("--- SKIP: TestRunRawMultiHop")) {
		t.Fatalf("raw multi-hop child skipped; privileged CI lane must be a hard signal")
	}
	if err != nil {
		t.Fatalf("raw multi-hop child failed: %v", err)
	}
}

func runRawMultiHopChild(t *testing.T) {
	target := os.Getenv("PROBECTL_TEST_PATH_RAW_TARGET")
	if target == "" {
		t.Fatal("PROBECTL_TEST_PATH_RAW_TARGET is required in child mode")
	}
	conn, raw, err := listenICMP(true)
	if err != nil {
		t.Fatalf("open raw ICMP socket: %v", err)
	}
	_ = conn.Close()
	if !raw {
		t.Fatal("CAP_NET_RAW missing: listenICMP(true) fell back to datagram ICMP")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg := Config{
		Target:        target,
		Mode:          "icmp",
		TraceCount:    1,
		MaxHops:       5,
		ProbesPerHop:  1,
		PerHopTimeout: time.Second,
		Privileged:    true,
	}
	p, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("run raw multi-hop trace: %v", err)
	}
	if !p.DestinationReached {
		t.Fatalf("destination not reached: %+v", p)
	}
	if !hopWithNonDestinationResponse(p, 1, target) || !hopWithNonDestinationResponse(p, 2, target) {
		t.Fatalf("expected two intermediate raw-socket hops before %s: %+v", target, p.Hops)
	}
	if !hopWithIPResponse(p, 3, target) {
		t.Fatalf("expected destination %s at TTL 3: %+v", target, p.Hops)
	}
	if len(p.Links) < 2 {
		t.Fatalf("expected multi-hop links, got %+v", p.Links)
	}
}

func rawPathUnavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PROBECTL_TEST_REQUIRE_RAW_PATH") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

type rawMultiHopFixture struct {
	srcNS string
	dstIP string
}

func setupRawMultiHopFixture(t *testing.T) rawMultiHopFixture {
	t.Helper()
	tag := strconv.Itoa(os.Getpid())
	srcNS := "pctl-src-" + tag
	r1NS := "pctl-r1-" + tag
	r2NS := "pctl-r2-" + tag
	dstNS := "pctl-dst-" + tag
	namespaces := []string{srcNS, r1NS, r2NS, dstNS}
	t.Cleanup(func() {
		for i := len(namespaces) - 1; i >= 0; i-- {
			_ = exec.Command("ip", "netns", "del", namespaces[i]).Run()
		}
	})
	for _, ns := range namespaces {
		runIP(t, "netns", "add", ns)
	}

	ifaceTag := strconv.Itoa(os.Getpid() % 100000)
	makeVethPair(t, "p"+ifaceTag+"s", "p"+ifaceTag+"a", srcNS, "src0", r1NS, "r1a")
	makeVethPair(t, "p"+ifaceTag+"b", "p"+ifaceTag+"c", r1NS, "r1b", r2NS, "r2a")
	makeVethPair(t, "p"+ifaceTag+"d", "p"+ifaceTag+"e", r2NS, "r2b", dstNS, "dst0")

	for _, ns := range namespaces {
		runNS(t, ns, "ip", "link", "set", "lo", "up")
		runNS(t, ns, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
	}
	assignAddr(t, srcNS, "src0", "10.250.0.2/30")
	assignAddr(t, r1NS, "r1a", "10.250.0.1/30")
	assignAddr(t, r1NS, "r1b", "10.250.1.1/30")
	assignAddr(t, r2NS, "r2a", "10.250.1.2/30")
	assignAddr(t, r2NS, "r2b", "10.250.2.1/30")
	assignAddr(t, dstNS, "dst0", "10.250.2.2/30")

	runNS(t, r1NS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	runNS(t, r2NS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	runNS(t, srcNS, "ip", "route", "add", "default", "via", "10.250.0.1")
	runNS(t, r1NS, "ip", "route", "add", "10.250.2.0/30", "via", "10.250.1.2")
	runNS(t, r2NS, "ip", "route", "add", "10.250.0.0/30", "via", "10.250.1.1")
	runNS(t, dstNS, "ip", "route", "add", "default", "via", "10.250.2.1")

	return rawMultiHopFixture{srcNS: srcNS, dstIP: "10.250.2.2"}
}

func makeVethPair(t *testing.T, leftTmp, rightTmp, leftNS, leftName, rightNS, rightName string) {
	t.Helper()
	runIP(t, "link", "add", leftTmp, "type", "veth", "peer", "name", rightTmp)
	runIP(t, "link", "set", leftTmp, "netns", leftNS)
	runIP(t, "link", "set", rightTmp, "netns", rightNS)
	runNS(t, leftNS, "ip", "link", "set", leftTmp, "name", leftName)
	runNS(t, rightNS, "ip", "link", "set", rightTmp, "name", rightName)
}

func assignAddr(t *testing.T, ns, iface, cidr string) {
	t.Helper()
	runNS(t, ns, "ip", "addr", "add", cidr, "dev", iface)
	runNS(t, ns, "ip", "link", "set", iface, "up")
}

func runNS(t *testing.T, ns string, args ...string) {
	t.Helper()
	runIP(t, append([]string{"netns", "exec", ns}, args...)...)
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func hopWithNonDestinationResponse(p *Path, ttl int, target string) bool {
	return hopWithResponse(p, ttl, func(n HopNode) bool { return n.IP != "" && n.IP != target })
}

func hopWithIPResponse(p *Path, ttl int, ip string) bool {
	return hopWithResponse(p, ttl, func(n HopNode) bool { return n.IP == ip })
}

func hopWithResponse(p *Path, ttl int, match func(HopNode) bool) bool {
	for _, h := range p.Hops {
		if h.TTL != ttl {
			continue
		}
		for _, n := range h.Nodes {
			if n.Received > 0 && match(n) {
				return true
			}
		}
	}
	return false
}
