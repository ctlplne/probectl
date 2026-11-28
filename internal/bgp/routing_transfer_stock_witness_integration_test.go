// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package bgp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type transferStockPoll struct {
	started   time.Time
	completed time.Time
	capture   string
	octets    [2]uint64
}

var transferStockSQLIdentity = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func awaitTransferStockPolls(t *testing.T, lanes [2]transferStockLane, links [2]roleRouterLink, from time.Time, earliest bool, phase string) [2]transferStockPoll {
	t.Helper()
	var polls [2]transferStockPoll
	var readErrors [2]error
	waitTransferStock(t, time.Minute, func() bool {
		now := time.Now().UTC()
		ready := true
		for i, lane := range lanes {
			if readErrors[i] == nil {
				polls[i], readErrors[i] = readTransferStockPoll(lane, links, from, now, earliest)
			}
			ready = ready && (readErrors[i] != nil || !polls[i].started.IsZero())
		}
		return ready
	})
	for i, err := range readErrors {
		if err != nil {
			t.Errorf("lane %d %s counter poll: %v", i, phase, err)
		}
	}
	return polls
}

func readTransferStockPoll(lane transferStockLane, links [2]roleRouterLink,
	from, to time.Time, earliest bool) (transferStockPoll, error) {
	// Fixture identifiers come from registration. Fail closed if their
	// representation cannot be used as an unambiguous SQL literal.
	for _, value := range []string{lane.reg.tenantID, lane.reg.contextID, lane.reg.deviceID, lane.counters} {
		if !transferStockSQLIdentity.MatchString(value) {
			return transferStockPoll{}, errors.New("counter fixture identity is not canonical")
		}
	}
	order := "DESC"
	if earliest {
		order = "ASC"
	}
	statement := fmt.Sprintf(`SELECT capture_key,
 toString(poll_started_unix_nanos) AS started,
 toString(poll_completed_unix_nanos) AS completed,
 toString(if_index) AS interface_text,
 toString(counter_value) AS counter_text
 FROM probectl_device_counters FINAL
 WHERE tenant_id='%s' AND context_id='%s' AND device_id='%s' AND agent_id='%s'
 AND name='%s' AND (if_index=%d OR if_index=%d)
 AND counter_width=64 AND uptime_known=1 AND discontinuity_known=1
 AND poll_started_unix_nanos>=%d AND poll_completed_unix_nanos<=%d
 ORDER BY poll_started_unix_nanos %s, capture_key, if_index LIMIT 128 FORMAT JSONEachRow`,
		lane.reg.tenantID, lane.reg.contextID, lane.reg.deviceID, lane.counters, device.MetricIfOutOctets,
		links[0].index, links[1].index, from.UnixNano(), to.UnixNano(), order)

	body, err := shipped.CHQuery(shipped.CHURL(), statement)
	if err != nil {
		return transferStockPoll{}, fmt.Errorf("read original counter history: %w", err)
	}
	type combined struct {
		poll transferStockPoll
		seen [2]bool
	}
	polls := map[string]*combined{}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" {
			continue
		}
		var row struct {
			Capture   string `json:"capture_key"`
			Started   string `json:"started"`
			Completed string `json:"completed"`
			Interface string `json:"interface_text"`
			Counter   string `json:"counter_text"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return transferStockPoll{}, fmt.Errorf("decode exact counter row: %w", err)
		}
		started, e1 := strconv.ParseInt(row.Started, 10, 64)
		completed, e2 := strconv.ParseInt(row.Completed, 10, 64)
		idx, e3 := strconv.ParseUint(row.Interface, 10, 32)
		value, e4 := strconv.ParseUint(row.Counter, 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || completed < started || len(row.Capture) != 64 {
			return transferStockPoll{}, errors.New("invalid exact counter value or clock in owned fixture")
		}
		member := 0
		if idx == uint64(links[1].index) {
			member = 1
		} else if idx != uint64(links[0].index) {
			return transferStockPoll{}, errors.New("counter read included a different interface")
		}
		key := polls[row.Capture]
		if key == nil {
			key = &combined{poll: transferStockPoll{started: time.Unix(0, started).UTC(),
				completed: time.Unix(0, completed).UTC(), capture: row.Capture}}
			polls[row.Capture] = key
		}
		if key.seen[member] || key.poll.started.UnixNano() != started || key.poll.completed.UnixNano() != completed {
			return transferStockPoll{}, errors.New("an exact capture contained competing counter samples")
		}
		key.seen[member], key.poll.octets[member] = true, value
		if key.seen[0] && key.seen[1] {
			return key.poll, nil
		}
	}
	return transferStockPoll{}, nil
}

// Report the owned fixture's clocks and terminal capture state only when the
// API refuses its evidence. Receipt counts alone include unavailable captures.
func logTransferStockFlowCaptures(t *testing.T, st *shipped.Stack, lane transferStockLane, ifIndex uint32) {
	t.Helper()
	readTransferStockFlowCaptures(t, st, lane, ifIndex, lane.before.started, transferArtifacts{}, 0)
}

func readTransferStockFlowCaptures(t *testing.T, st *shipped.Stack, lane transferStockLane, ifIndex uint32, started time.Time, artifacts transferArtifacts, index int) {
	t.Helper()
	if !transferStockSQLIdentity.MatchString(lane.reg.tenantID) || !transferStockSQLIdentity.MatchString(lane.reg.agentID) {
		t.Log("invalid stock flow fixture identity")
		return
	}
	from, end := lane.before.started, lane.after.started
	if from.IsZero() {
		// Only the diagnostic query uses the fixture clock. A missing
		// signed bracket is still a failure for the estimate.
		from = started
	}
	if end.IsZero() {
		end = time.Now()
	}
	if from.IsZero() || from.After(end) {
		t.Log("stock flow diagnostics have no bounded owned time window")
		return
	}
	query := fmt.Sprintf(`SELECT routing_capture_key,clock_basis,exporter,obs_domain,src_addr,dst_addr,dst_port,
 toString(bytes) AS bytes,
 toString(toUnixTimestamp64Nano(start_ts)) AS started,toString(toUnixTimestamp64Nano(ts)) AS ended,
 toString(routing_captured_unix_nanos) AS retained,toString(packets) AS packets
 FROM probectl_flows FINAL WHERE tenant_id='%s' AND agent_id='%s' AND out_if=%d
 AND toUnixTimestamp64Nano(ts)>=%d AND toUnixTimestamp64Nano(ts)<=%d
 ORDER BY ts,routing_capture_key LIMIT 64 FORMAT JSONEachRow`, lane.reg.tenantID, lane.reg.agentID, ifIndex,
		from.UnixNano(), end.UnixNano())
	body, err := shipped.CHQuery(shipped.CHURL(), query)
	if err != nil {
		t.Logf("read owned stock flow clocks: %v", err)
		return
	}
	artifacts.write(t, fmt.Sprintf("lane-%d-ipfix.jsonl", index), []byte(body))
	var ownership strings.Builder
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.reg.tenantID))
	err = tenancy.InTenantReadSnapshot(ctx, st.ApplicationReadPool(t), func(ctx context.Context, sc tenancy.Scope) error {
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			if line == "" {
				continue
			}
			var row struct {
				Key      string `json:"routing_capture_key"`
				Basis    uint8  `json:"clock_basis"`
				Started  string
				Ended    string
				Retained string
				Packets  string
				Bytes    string
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				return err
			}
			outcome := "missing"
			if key, err := hex.DecodeString(row.Key); err == nil && len(key) == 32 {
				if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT outcome FROM bgp_flow_capture_receipts
 WHERE tenant_id=$1 AND flow_key=$2),'pending')`, lane.reg.tenantID, key).Scan(&outcome); err != nil {
					return err
				}
			}
			t.Logf("stock egress row packets=%s bytes=%s clock_basis=%d start_ns=%s end_ns=%s receipt_ns=%s outcome=%s",
				row.Packets, row.Bytes, row.Basis, row.Started, row.Ended, row.Retained, outcome)
			fmt.Fprintf(&ownership, "%s %s %s\n", row.Key, row.Retained, outcome)
		}
		return nil
	})
	if err != nil {
		t.Logf("read owned stock flow receipt states: %v", err)
	}
	artifacts.write(t, fmt.Sprintf("lane-%d-ownership.txt", index), []byte(ownership.String()))
}

func verifyTransferStockPolls(t *testing.T, st *shipped.Stack, lane *transferStockLane) {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.reg.tenantID))
	err := tenancy.InTenantReadSnapshot(ctx, st.ApplicationReadPool(t), func(ctx context.Context, sc tenancy.Scope) error {
		for _, poll := range []transferStockPoll{lane.before, lane.after} {
			key, err := hex.DecodeString(poll.capture)
			if err != nil || len(key) != 32 {
				return fmt.Errorf("invalid current capture key")
			}
			var found bool
			err = sc.Q.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM device_counter_capture_sources
 WHERE tenant_id=$1 AND context_id=$2 AND device_id=$3 AND agent_id=$4 AND capture_key=$5
  AND poll_started_unix_nanos=$6 AND poll_completed_unix_nanos=$7
 )`, lane.reg.tenantID, lane.reg.contextID, lane.reg.deviceID, lane.counters, key,
				poll.started.UnixNano(), poll.completed.UnixNano()).Scan(&found)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("physical counter has no matching tenant-authenticated witness")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

const transferStockContainerWorkload = "/tmp/probectl-transfer-workload"

func installTransferStockWorkload(t *testing.T, lab *routingLab) {
	t.Helper()
	installRoutingLabWorkload(t, lab, transferStockPackets, transferStockPayload, "edge", "rtr-b")
}

func installRoutingLabWorkload(t *testing.T, lab *routingLab, packets, payload int, routers ...string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "main.go")
	body := fmt.Sprintf(transferStockWorkloadSource, transferStockAddress, packets, payload)
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "transfer-workload")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the bounded local workload: %v %s", err, out)
	}
	for _, router := range routers {
		lab.docker(t, "cp", binary, lab.container(router)+":"+transferStockContainerWorkload)
	}
}

func sendTransferStockPayload(t *testing.T, lab *routingLab, links [2]roleRouterLink, artifacts transferArtifacts) {
	t.Helper()
	sendRoutingLabPayload(t, lab, "rtr-b", links[1].peerIP, func(counts []byte) {
		artifacts.write(t, "receiver-counts.txt", counts)
	})
}

func sendRoutingLabPayload(t *testing.T, lab *routingLab, senderRouter, source string, recordReceiver func([]byte)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	receive := exec.CommandContext(ctx, "docker", "exec", lab.container("edge"), transferStockContainerWorkload, "receive", source)
	reader, err := receive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var receiverErr bytes.Buffer
	receive.Stderr = &receiverErr
	defer func() { recordReceiver(receiverErr.Bytes()) }()
	if err := receive.Start(); err != nil {
		t.Errorf("start independent receiver: %v", err)
		return
	}
	waited := false
	defer func() {
		cancel()
		if !waited {
			_ = receive.Wait()
		}
	}()
	lines := bufio.NewScanner(reader)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Errorf("owned receiver did not start: %v", lines.Err())
		return
	}
	sender := exec.CommandContext(ctx, "docker", "exec", lab.container(senderRouter),
		transferStockContainerWorkload, "send", source)
	if out, err := sender.CombinedOutput(); err != nil {
		t.Errorf("bounded owned payload did not send: %v %s", err, out)
		return
	}
	if !lines.Scan() || lines.Text() != "received all" {
		t.Errorf("the upstream did not receive every fixed-size packet: %v", lines.Err())
		return
	}
	err = receive.Wait()
	waited = true
	if err != nil {
		t.Errorf("owned receiver completed unsuccessfully: %v %s", err, receiverErr.String())
	}
}

const transferStockWorkloadSource = `package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "os"
    "time"
)

func main() {
    if len(os.Args) != 3 {
        os.Exit(2)
    }
    address := &net.UDPAddr{IP: net.ParseIP(%q), Port: 37200}
    origin := net.ParseIP(os.Args[2])
    if origin == nil || origin.To4() == nil || !origin.IsPrivate() {
        fail("the test origin requires an owned private IPv4 address")
    }
    const count, payload = %d, %d
    switch os.Args[1] {
    case "receive":
        socket, err := net.ListenUDP("udp4", address)
        check(err)
        defer socket.Close()
        check(socket.SetReadBuffer(1 << 20))
        check(socket.SetReadDeadline(time.Now().Add(18 * time.Second)))
        fmt.Println("ready")
        buf := make([]byte, payload+1)
        var received [count]bool
        packets, wireBytes := 0, 0
        report := func() {
            fmt.Fprintf(os.Stderr, "packets=%%d ipv4_udp_wire_bytes=%%d\n", packets, wireBytes)
        }
        for i := 0; i < count; i++ {
            size, sender, err := socket.ReadFromUDP(buf)
            if err != nil {
                report()
                check(err)
            }
            packets++
            wireBytes += size + 28
            if size != payload || !sender.IP.Equal(origin) {
                report()
                fail("wrong payload length or source")
            }
            sequence := binary.BigEndian.Uint32(buf)
            if sequence >= count || received[sequence] {
                report()
                fail("unexpected or duplicate payload sequence")
            }
            received[sequence] = true
        }
        report()
        fmt.Println("received all")
    case "send":
        socket, err := net.DialUDP("udp4", &net.UDPAddr{IP: origin}, address)
        check(err)
        defer socket.Close()
        check(socket.SetWriteDeadline(time.Now().Add(12 * time.Second)))
        buf := make([]byte, payload)
        for i := 0; i < count; i++ {
            binary.BigEndian.PutUint32(buf, uint32(i))
            size, err := socket.Write(buf)
            check(err)
            if size != payload {
                fail("short payload write")
            }
            time.Sleep(3 * time.Millisecond)
        }
    default:
        fail("unknown owned fixture operation")
    }
}

func check(err error) {
    if err != nil {
        fail(err.Error())
    }
}

func fail(message string) {
    fmt.Fprintln(os.Stderr, message)
    os.Exit(1)
}
`
