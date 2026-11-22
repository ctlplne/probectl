// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func measureReleasePacketExporterClock(t *testing.T) {
	t.Helper()
	const deadline = 45 * time.Second
	loopback := netip.MustParseAddr("127.0.0.1")
	probeSource := netip.MustParseAddr("127.0.0.8")
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	name := "probectl-qa-beta-e2e-softflowd-clock-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	runCmd(t, "", nil, "docker", "create", "--name", name, "--network", "host", "--cap-add", "NET_RAW",
		"--read-only", "--tmpfs", "/tmp:rw,nosuid,noexec", releasePacketImage,
		"softflowd", "-d", "-N", "-i", "lo", "-v", "10", "-t", "icmp=2", "-t", "expint=1",
		"-n", listener.LocalAddr().String(), "-c", "/tmp/softflowd.ctl",
		"icmp and src host "+probeSource.String()+" and dst host "+loopback.String()+" and icmp[0] = 8")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	runCmd(t, "", nil, "docker", "start", name)
	waitFor(t, "owned quiet-interface exporter", 20*time.Second, func() bool {
		_, err := releasePacketControl(t, name, "statistics")
		return err == nil
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "docker", "exec", name, "ping", "-q", "-c", "4", "-i", "1",
		"-s", "32", "-I", probeSource.String(), "-W", "1", loopback.String())
	var probeOutput bytes.Buffer
	probe.Stdout, probe.Stderr = &probeOutput, &probeOutput
	launch := time.Now()
	if err := listener.SetReadDeadline(launch.Add(deadline)); err != nil {
		t.Fatal(err)
	}
	if err := probe.Start(); err != nil {
		t.Fatal(err)
	}
	probeDone := make(chan error, 1)
	go func() { probeDone <- probe.Wait() }()
	observed, readErr := firstReleaseProbeExport(listener, probeSource, loopback)
	if err := <-probeDone; err != nil || !bytes.Contains(probeOutput.Bytes(), []byte("4 packets transmitted, 4 packets received")) {
		t.Fatalf("four ordinary loopback probes: %v: %.1024s", err, probeOutput.Bytes())
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	logReleasePacketStatistics(t, name)
	if observed.IsZero() {
		if _, err := releasePacketControl(t, name, "statistics"); err != nil {
			t.Fatalf("exporter unavailable at the observation deadline: %v", err)
		}
		t.Logf("stock softflowd 1.1.0: no selected IPFIX record within %s of launching four one-per-second loopback probes", deadline)
		return
	}
	t.Logf("stock softflowd 1.1.0: first selected IPFIX record %s after probe launch", observed.Sub(launch))
}

func firstReleaseProbeExport(listener *net.UDPConn, source, destination netip.Addr) (time.Time, error) {
	decoder := flow.NewDecoder(time.Minute, 32)
	var packet [65535]byte
	for {
		n, exporter, err := listener.ReadFromUDPAddrPort(packet[:])
		observed := time.Now()
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return time.Time{}, nil
		}
		if err != nil {
			return time.Time{}, err
		}
		if exporter.Addr() != destination {
			continue
		}
		records, _, err := decoder.Decode(packet[:n], exporter.Addr().String(), observed)
		if err != nil {
			return time.Time{}, err
		}
		for _, record := range records {
			if record.Protocol == "ipfix" && record.SrcAddr == source && record.DstAddr == destination &&
				record.Transport == 1 && record.Packets > 0 {
				return observed, nil
			}
		}
	}
}

// Pinned softflowd 1.1.0 reports canonical endpoint order and directional
// counters. Presence alone does not prove the capture drained before expiry.
func completeReleasePacketCapture(output []byte, source string) bool {
	if len(output) > 64<<10 {
		return false
	}
	matched := 0
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		src, dst := bytes.Index(line, []byte("["+source+"]:")), bytes.Index(line, []byte("[127.0.0.1]:"))
		if src < 0 || dst < 0 || !bytes.Contains(line, []byte(" proto:1 ")) {
			continue
		}
		matched++
		counters := map[string]uint64{}
		for _, field := range strings.Fields(string(line)) {
			key, raw, _ := strings.Cut(field, ":")
			switch key {
			case "octets>", "packets>", "octets<", "packets<":
				if _, duplicate := counters[key]; duplicate {
					return false
				}
				value, err := strconv.ParseUint(raw, 10, 32)
				if err != nil {
					return false
				}
				counters[key] = value
			}
		}
		forward, reverse := ">", "<"
		if src > dst {
			forward, reverse = reverse, forward
		}
		if len(counters) != 4 || counters["packets"+forward] != releasePacketCount ||
			counters["octets"+forward] != releasePacketCount*(releasePacketPayload+20+8) ||
			counters["packets"+reverse] != 0 || counters["octets"+reverse] != 0 {
			return false
		}
	}
	return matched == 1
}

func releasePacketControl(t *testing.T, name, operation string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "exec", name, "softflowctl", "-c", "/tmp/softflowd.ctl", operation).Output()
}

func logReleasePacketStatistics(t *testing.T, name string) {
	t.Helper()
	output, err := releasePacketControl(t, name, "statistics")
	if err != nil || len(output) > 64<<10 {
		t.Log("owned exporter capture statistics unavailable")
		return
	}
	for _, line := range strings.Split(string(output), "\n") {
		label, raw, _ := strings.Cut(strings.TrimSpace(line), ":")
		switch label {
		case "Packets processed", "Packets received by libpcap", "Packets dropped by libpcap", "Packets dropped by interface":
			value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
			if err == nil {
				t.Logf("owned exporter %s: %d", label, value)
			}
		}
	}
}

func TestReleasePacketCaptureRequiresExactIndependentCounters(t *testing.T) {
	const reverse = "seq:1 [127.0.0.1]:0 <> [127.0.0.2]:8 proto:1 octets>:0 packets>:0 octets<:5029888 packets<:4096 start:fixture"
	const forward = "seq:1 [127.0.0.2]:8 <> [127.0.0.1]:0 proto:1 octets>:5029888 packets>:4096 octets<:0 packets<:0 start:fixture"
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"reverse", reverse, true},
		{"forward", forward, true},
		{"unrelated", strings.ReplaceAll(reverse, "127.0.0.2", "127.0.0.100") + "\n" + reverse, true},
		{"empty", "", false},
		{"partial", strings.NewReplacer("4096", "4089", "5029888", "5021292").Replace(reverse), false},
		{"wrong-bytes", strings.ReplaceAll(reverse, "5029888", "5029887"), false},
		{"wrong-direction", strings.NewReplacer("octets>:0", "octets>:5029888", "packets>:0", "packets>:4096", "octets<:5029888", "octets<:0", "packets<:4096", "packets<:0").Replace(reverse), false},
		{"foreign-prefix", strings.ReplaceAll(reverse, "127.0.0.2", "127.0.0.20"), false},
		{"protocol", strings.ReplaceAll(reverse, "proto:1 ", "proto:17 "), false},
		{"duplicate-flow", reverse + "\n" + reverse, false},
		{"duplicate-counter", reverse + " packets<:4096", false},
		{"missing-counter", strings.ReplaceAll(reverse, "octets<:5029888 ", ""), false},
		{"malformed-counter", strings.ReplaceAll(reverse, "packets<:4096", "packets<:4096x"), false},
		{"overflow-counter", strings.ReplaceAll(reverse, "packets<:4096", "packets<:4294967296"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := completeReleasePacketCapture([]byte(tc.output), "127.0.0.2"); got != tc.want {
				t.Fatalf("selected capture completeness = %v, want %v", got, tc.want)
			}
		})
	}
}
