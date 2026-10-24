// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux && ebpf

package ebpf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helperListenEnv makes the test binary act as a TCP server child: it listens
// on the given address, prints the bound port, then accepts and drains
// connections until killed. A child is used so the SERVER process is a
// different process (with a different comm) from the client — the test can
// then tell a correct server attribution from the client's own pid.
const helperListenEnv = "PROBECTL_TEST_HELPER_LISTEN"

// TestHelperProcessListener is not a test: it is the server child that
// startListenerChild execs. Without the env var it returns immediately.
func TestHelperProcessListener(t *testing.T) {
	addr := os.Getenv(helperListenEnv)
	if addr == "" {
		t.Skip("helper process only")
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}(c)
	}
}

// startListenerChild copies the test binary under a distinct name (so the
// kernel comm differs from the client's) and starts it as a listener on
// loopback. It returns the child's pid, its comm and its port.
func startListenerChild(t *testing.T, name string) (int, string, int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), name)
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=^TestHelperProcessListener$")
	cmd.Env = append(os.Environ(), helperListenEnv+"=127.0.0.1:0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("listener child %s gave no port: %v", name, err)
	}
	var port int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &port); err != nil || port == 0 {
		t.Fatalf("listener child %s printed %q, want a port", name, line)
	}
	comm := name
	if len(comm) > 15 {
		comm = comm[:15] // TASK_COMM_LEN - 1
	}
	return cmd.Process.Pid, comm, port
}

// workloadOf is the edge identity the agent's enricher gives a local pid.
func workloadOf(pid int) string {
	ep := Endpoint{PID: uint32(pid)}
	NewProcEnricher("").EnrichEndpoint(&ep)
	return ep.ID()
}

func dialAndClose(t *testing.T, port, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", port, err)
		}
		_, _ = c.Write([]byte("probectl-ing-24"))
		_ = c.Close()
	}
}

// TestLiveInboundEdgeOrientation is the ING-24 live proof. Inbound connections
// to a listening port must yield ONE client -> server edge keyed on the LISTEN
// port, with the server endpoint attributed to the listening process — not one
// server -> client edge per ephemeral port with a softirq bystander's comm.
// Two servers cover both ways the owner is learned: one listening BEFORE the
// agent attached (seeded by the task_file iterator) and one AFTER (the
// tracepoint's LISTEN transition).
func TestLiveInboundEdgeOrientation(t *testing.T) {
	const conns = 5
	prePID, preComm, prePort := startListenerChild(t, "probectl-presrv")

	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	cfg.Host = "kernel-matrix-host"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Fatalf("l4flow load+attach: %v", err)
	}
	em := &captureEmitter{}
	cfg.FlushInterval = time.Hour // one final flush, after the traffic
	agent := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, NewProcEnricher(""), em)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	time.Sleep(300 * time.Millisecond) // the reader is running

	postPID, postComm, postPort := startListenerChild(t, "probectl-postsrv")
	dialAndClose(t, prePort, conns)
	dialAndClose(t, postPort, conns)
	time.Sleep(2 * time.Second) // close transitions (TIME_WAIT is the client's) and ring delivery
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("agent run: %v", err)
	}
	if !src.(*liveSource).ListenersSeeded() {
		t.Logf("listener iterator unavailable on this kernel; the pre-existing listener is attributed at close instead")
	}

	client := workloadOf(os.Getpid())
	for _, srv := range []struct {
		name string
		pid  int
		comm string
		port int
	}{{"pre-existing listener", prePID, preComm, prePort}, {"listener started after the agent", postPID, postComm, postPort}} {
		server := workloadOf(srv.pid)
		var onPort []ServiceEdge
		for _, e := range em.edges {
			if e.DestPort == uint32(srv.port) {
				onPort = append(onPort, e)
			}
			if e.Source == server || (e.DestPort != uint32(srv.port) && e.Destination == server) {
				t.Errorf("%s: edge %+v runs FROM the server or keys it on a port other than its listen port", srv.name, e)
			}
		}
		if len(onPort) != 1 {
			t.Fatalf("%s: %d edges keyed on listen port %d, want exactly 1 (all edges: %+v)", srv.name, len(onPort), srv.port, em.edges)
		}
		e := onPort[0]
		if e.Destination != server {
			t.Errorf("%s: edge destination %q, want the server workload %q", srv.name, e.Destination, server)
		}
		if e.Source != client {
			t.Errorf("%s: edge source %q, want the client process %q (host-local ends joined)", srv.name, e.Source, client)
		}
		if e.Connections != conns {
			t.Errorf("%s: edge counts %d connections, want %d", srv.name, e.Connections, conns)
		}
		serverSide := 0
		for _, f := range em.flows {
			if f.Direction != DirectionIngress || f.Destination.Port != uint32(srv.port) {
				continue
			}
			serverSide++
			if int(f.Destination.PID) != srv.pid || f.Destination.Process != srv.comm {
				t.Errorf("%s: server-side flow attributed to pid %d %q, want pid %d %q: %+v",
					srv.name, f.Destination.PID, f.Destination.Process, srv.pid, srv.comm, f)
			}
			if f.Source.Port == uint32(srv.port) {
				t.Errorf("%s: server-side flow keeps the listen port on the client side: %+v", srv.name, f)
			}
		}
		if serverSide < conns {
			t.Errorf("%s: %d server-side (ingress) flows, want at least %d", srv.name, serverSide, conns)
		}
	}
}
