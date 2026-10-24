// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux && ebpf

package ebpf

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ING-23: the shipped systemd units run the agent as a non-root user with
// exactly AmbientCapabilities=CAP_BPF CAP_PERFMON (and the same bounding set,
// NoNewPrivileges, LimitMEMLOCK=infinity). This test proves the L4 flow plane
// loads, attaches and observes real TCP traffic under exactly that identity,
// with tracefs out of reach — the case the classic tracepoint link failed,
// because it reads the event id from the root-only tracefs.
//
// Run as root (the kernel-matrix VM runs `go test` under sudo), the test
// re-execs its own binary as uid/gid 65534 through util-linux:
//
//	unshare --mount   -> a private mount namespace in which /sys/kernel/tracing
//	                     and /sys/kernel/debug are covered by an empty root-only
//	                     (0700) tmpfs, so no tracefs is reachable whatever mode
//	                     the host mounted it with;
//	setpriv           -> uid/gid 65534, no groups, no_new_privs, and CAP_BPF +
//	                     CAP_PERFMON only, in the bounding, inheritable and
//	                     ambient sets — what the unit grants, nothing more.
//
// The child asserts that identity before it loads anything. A missing tool is
// a failure, never a skip: a green run must mean the non-root path ran.
const (
	nonRootChildEnv     = "PROBECTL_TEST_NONROOT_L4"
	nonRootPreListenEnv = "PROBECTL_TEST_NONROOT_PRELISTEN" // "<pid>:<port>" of a root-owned listener
	nonRootUID          = "65534"
	nonRootTestName     = "TestLiveNonRootL4Attach"
)

// nonRootMaskScript runs in the private mount namespace: it hides tracefs
// (and the legacy debugfs path) behind empty root-only tmpfs mounts, then
// drops to the unit's identity and execs the test binary ("$@").
const nonRootMaskScript = `set -eu
for d in /sys/kernel/tracing /sys/kernel/debug; do
	if [ -d "$d" ]; then mount -t tmpfs -o mode=0700,size=16k probectl-no-tracefs "$d"; fi
done
exec setpriv --reuid=` + nonRootUID + ` --regid=` + nonRootUID + ` --clear-groups --no-new-privs \
	--bounding-set=` + nonRootUnitCaps + ` --inh-caps=` + nonRootUnitCaps + ` --ambient-caps=` + nonRootUnitCaps + ` -- "$@"`

func TestLiveNonRootL4Attach(t *testing.T) {
	if os.Getenv(nonRootChildEnv) == "child" {
		runNonRootL4Child(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root: the test drops itself to uid 65534 with the unit's capabilities (the kernel-matrix VM runs go test under sudo)")
	}
	for _, tool := range []string{"unshare", "setpriv", "mount"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s (util-linux) is required to run the L4 attach as the unit's non-root identity: %v", tool, err)
		}
	}

	// A listener owned by ANOTHER user (root) that predates the agent: the
	// non-root task_file iterator must still attribute it (ING-24 seed).
	pre, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-existing listener: %v", err)
	}
	defer pre.Close()
	go drainListener(pre)
	prePort := pre.Addr().(*net.TCPAddr).Port

	// LimitMEMLOCK=infinity, as the unit sets it (inherited across exec).
	inf := &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, inf); err != nil {
		t.Fatalf("set RLIMIT_MEMLOCK like the unit: %v", err)
	}

	self := nonRootSelfFD(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--propagation", "private", "--",
		"sh", "-c", nonRootMaskScript, "sh",
		nonRootSelfPath, "-test.run=^"+nonRootTestName+"$", "-test.v", "-test.count=1")
	cmd.ExtraFiles = []*os.File{self} // fd 3 in the child: nonRootSelfPath
	cmd.Dir = "/"
	cmd.Env = append(os.Environ(),
		nonRootChildEnv+"=child",
		fmt.Sprintf("%s=%d:%d", nonRootPreListenEnv, os.Getpid(), prePort))
	out, err := cmd.CombinedOutput()
	t.Logf("non-root child (uid %s, caps %s, no tracefs):\n%s", nonRootUID, nonRootUnitCaps, out)
	if err != nil {
		t.Fatalf("the L4 plane failed as the unit's non-root identity: %v", err)
	}
	// The child exiting 0 is not enough: a skipped child also exits 0.
	if !strings.Contains(string(out), "--- PASS: "+nonRootTestName) || strings.Contains(string(out), "--- SKIP") {
		t.Fatal("the non-root child did not run to a PASS")
	}
}

// nonRootSelfPath execs the test binary through an inherited descriptor
// (ExtraFiles[0] is fd 3). The binary lives in go's 0700 build directory,
// which uid 65534 cannot traverse, and it must NOT be copied: the kernel-matrix
// VMs' temp dir is RAM-backed and small (a binary copy starved them, 8e936d2).
// The /proc/self/fd magic link opens the file without a path walk.
const nonRootSelfPath = "/proc/self/fd/3"

func nonRootSelfFD(t *testing.T) *os.File {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func drainListener(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}(c)
	}
}

// runNonRootL4Child is the body that runs as the unit's identity.
func runNonRootL4Child(t *testing.T) {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		t.Fatalf("child still runs as root (uid %d euid %d)", os.Getuid(), os.Geteuid())
	}
	if want, got := capMask(1<<capBPF|1<<capPerfmon), effectiveCaps(); got != want {
		t.Fatalf("effective caps %#x, want exactly CAP_BPF|CAP_PERFMON %#x — the test must grant what the unit grants, no more", uint64(got), uint64(want))
	}
	if traceFSVisible() {
		t.Fatal("tracefs is visible to the child: the proof needs the agent unable to read it")
	}
	if c := Probe(); c.Mode != ModeLive {
		t.Fatalf("capability probe turns the non-root agent away: %s", c)
	}
	prePID, prePort := nonRootPreListener(t)

	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Fatalf("l4flow load+attach as uid %d with CAP_BPF+CAP_PERFMON: %v", os.Getuid(), err)
	}
	defer src.Close()
	seeded := src.(*liveSource).ListenersSeeded()
	t.Logf("non-root attach ok; task_file listener seed ran: %t", seeded)
	if !seeded {
		t.Error("the task_file listener iterator did not run as the unit's identity (ING-24 seed)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	flows, err := src.Flows(ctx)
	if err != nil {
		t.Fatalf("flows stream: %v", err)
	}

	// A listener opened AFTER the attach, owned by this (non-root) process.
	own, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer own.Close()
	go drainListener(own)
	ownPort := own.Addr().(*net.TCPAddr).Port
	liveTCPTransfer(t, "tcp4", own.Addr().String(), []byte(strings.Repeat("n", 2048)))
	liveTCPTransfer(t, "tcp4", "127.0.0.1:"+strconv.Itoa(prePort), []byte("probectl-ing-23"))

	me := uint32(os.Getpid())
	want := map[string]func(Flow) bool{
		"client flow from this process to its own listener": func(f Flow) bool {
			return f.Direction == DirectionEgress && f.Destination.Port == uint32(ownPort) && f.Source.PID == me &&
				f.Source.Address == "127.0.0.1"
		},
		"server flow on the listener opened after the attach, owned by this process": func(f Flow) bool {
			return f.Direction == DirectionIngress && f.Destination.Port == uint32(ownPort) && f.Destination.PID == me
		},
		"close flow carrying the tcp_sock byte/segment counters": func(f Flow) bool {
			return f.State == StateClose && f.Destination.Port == uint32(ownPort) && f.Bytes > 0 && f.Packets > 0
		},
		// ESTABLISHED (not CLOSE): at close the owner is also learned from the
		// close() caller, so only the established record proves the seed.
		"established server flow on the root-owned listener that predates the agent": func(f Flow) bool {
			return f.State == StateEstablished && f.Direction == DirectionIngress &&
				f.Destination.Port == uint32(prePort) && f.Destination.PID == prePID
		},
	}
	var seen []Flow
	for len(want) > 0 {
		f, ok := waitLiveFlow(ctx, flows, func(Flow) bool { return true })
		if !ok {
			break
		}
		seen = append(seen, f)
		for name, pred := range want {
			if pred(f) {
				t.Logf("observed %s: %s:%d -> %s:%d pid %d/%d state %s", name,
					f.Source.Address, f.Source.Port, f.Destination.Address, f.Destination.Port, f.Source.PID, f.Destination.PID, f.State)
				delete(want, name)
			}
		}
	}
	for name := range want {
		t.Errorf("not observed as the non-root unit identity: %s", name)
	}
	if t.Failed() {
		t.Logf("flows seen: %+v", seen)
	}
}

func nonRootPreListener(t *testing.T) (uint32, int) {
	t.Helper()
	pidS, portS, ok := strings.Cut(os.Getenv(nonRootPreListenEnv), ":")
	pid, perr := strconv.ParseUint(pidS, 10, 32)
	port, qerr := strconv.Atoi(portS)
	if !ok || perr != nil || qerr != nil || pid == 0 || port == 0 {
		t.Fatalf("%s=%q, want <pid>:<port>", nonRootPreListenEnv, os.Getenv(nonRootPreListenEnv))
	}
	return uint32(pid), port
}
