// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux && ebpf

package ebpf

import (
	"context"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ipprotoMPTCP is IPPROTO_MPTCP (include/uapi/linux/in.h).
const ipprotoMPTCP = 262

// TestLiveSeedRecordsMPTCPListener is the ING-24 root-cause regression. Since
// Go 1.24 a net.Listen socket is MPTCP whenever the kernel has MPTCP enabled
// (every ci-kernels image and most distro kernels do): its sk_protocol is
// IPPROTO_MPTCP (262), not IPPROTO_TCP, and the seed used to drop it as "not
// TCP" — so on 5.15 and 6.6 no Go server that predated the agent was ever
// attributed, while the Docker Desktop kernel (CONFIG_MPTCP unset) passed.
// Each listener here predates the agent; the seed must record every one with
// this process as the owner, whichever protocol the kernel gave it.
func TestLiveSeedRecordsMPTCPListener(t *testing.T) {
	mptcpOn := mptcpEnabled()
	listeners := map[string]net.Listener{
		"go default listener":   listenWith(t, nil),
		"explicit MPTCP":        listenWith(t, boolPtr(true)),
		"explicit plain TCP":    listenWith(t, boolPtr(false)),
		"explicit MPTCP (IPv6)": listenWithNet(t, "tcp6", "[::1]:0", boolPtr(true)),
	}
	sawMPTCP := false
	for name, ln := range listeners {
		proto := soProtocol(t, ln)
		t.Logf("%s: port %d SO_PROTOCOL %d", name, ln.Addr().(*net.TCPAddr).Port, proto)
		sawMPTCP = sawMPTCP || proto == ipprotoMPTCP
	}
	if mptcpOn && !sawMPTCP {
		t.Fatal("net.mptcp.enabled=1 but no listener came back as IPPROTO_MPTCP: the regression would not exercise its case")
	}
	if !mptcpOn {
		t.Log("this kernel has no MPTCP (net.mptcp.enabled absent or 0): every listener is plain TCP here; the 5.15/6.6 matrix rows exercise the MPTCP case")
	}

	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Fatalf("l4flow load+attach: %v", err)
	}
	defer src.Close()
	live := src.(*liveSource)
	seed := live.ListenerSeedReport()
	t.Logf("seed: %+v", seed)
	if !seed.Attributed() || seed.FilesVisited == 0 {
		t.Fatalf("listener seed did not run: %+v", seed)
	}

	netns := netnsInode(t)
	wantComm := selfComm(t)
	for name, ln := range listeners {
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		var owner l4flowListenOwner
		if err := live.objs.Listeners.Lookup(l4flowListenKey{Netns: netns, Port: port}, &owner); err != nil {
			t.Errorf("%s (port %d, SO_PROTOCOL %d): not recorded by the listener seed: %v (seed %+v)", name, port, soProtocol(t, ln), err, seed)
			continue
		}
		if int(owner.Pid) != os.Getpid() || unix.ByteSliceToString(owner.Comm[:]) != wantComm {
			t.Errorf("%s (port %d): owner pid %d %q, want this process %d %q", name, port, owner.Pid,
				unix.ByteSliceToString(owner.Comm[:]), os.Getpid(), wantComm)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

func listenWith(t *testing.T, mptcp *bool) net.Listener {
	return listenWithNet(t, "tcp4", "127.0.0.1:0", mptcp)
}

// listenWithNet listens like a server would; mptcp nil keeps Go's default.
func listenWithNet(t *testing.T, network, addr string, mptcp *bool) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	if mptcp != nil {
		lc.SetMultipathTCP(*mptcp)
	}
	ln, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go drainListener(ln)
	return ln
}

func soProtocol(t *testing.T, ln net.Listener) int {
	t.Helper()
	rc, err := ln.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var proto int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		proto, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	return proto
}

func mptcpEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/mptcp/enabled")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func netnsInode(t *testing.T) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	return uint32(st.Ino)
}

func selfComm(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}
