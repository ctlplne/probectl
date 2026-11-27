// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestDeviceSyslogAuthenticatedFlapsKeepOneScopedIncident(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	for _, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
	}

	const deviceName = "edge-overlap"
	sources := []siem.SyslogSource{
		{Name: deviceName, TenantID: f.tenants[0], TLSClientSubject: "CN=edge-a,O=probectl",
			PatternFamily: "cisco_ios", FaultDevice: deviceName},
		{Name: "edge-sender", TenantID: f.tenants[1], TLSClientSubject: "CN=edge-b,O=probectl",
			PatternFamily: "cisco_ios"},
	}
	receiver, err := siem.NewSyslogReceiver(siem.SyslogReceiverConfig{Sources: sources}, NewDeviceSyslogSink(ops))
	if err != nil {
		t.Fatal(err)
	}
	addr, clients := startScopedSyslogFixture(t, receiver)
	down := "%LINK-3-UPDOWN: Interface Ethernet7/2, changed state to down"
	up := "%LINK-3-UPDOWN: Interface Ethernet7/2, changed state to up"
	line := "<34>1 " + time.Now().UTC().Format(time.RFC3339) + " "
	for range 3 {
		sendSyslogLine(t, addr, clients[0], line+deviceName+" syslogd - - - "+down)
		sendSyslogLine(t, addr, clients[0], line+deviceName+" syslogd - - - "+up)
		sendSyslogLine(t, addr, clients[1], line+deviceName+" syslogd - - - "+down)
	}
	sendSyslogLine(t, addr, clients[0], line+"unbound-edge syslogd - - - "+down)
	sendSyslogLine(t, addr, clients[0], line+"- syslogd - - - "+down)
	for lane, tenant := range f.tenants {
		want := []int{8, 3}[lane]
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		shipped.Await(t, "all original syslog lines are visible in their source tenant", 6*time.Second, func() bool {
			rows, err := ops.ListSyslog(ctx, tenant, device.OpsFilter{Limit: 20})
			return err == nil && len(rows) == want
		})
	}

	worker := deviceSyslogFaultProcessor{pool: f.pool, window: time.Minute, log: f.server.log}
	right := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[1]))
	assertSyslogFaultCannotReferenceSibling(right, t, f, ops)
	if _, err := worker.processOne(right, f.tenants[0]); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("a tenant context could read a sibling's fault queue", err)
	}
	if progressed, err := worker.processOne(right, f.tenants[1]); err != nil || progressed {
		t.Fatal("the grouping-only source produced a fault receipt", progressed, err)
	}
	left := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0]))
	type drainResult struct {
		processed bool
		err       error
	}
	claimed := make(chan drainResult, 2)
	for range 2 {
		go func() {
			processed, err := worker.processOne(left, f.tenants[0])
			claimed <- drainResult{processed, err}
		}()
	}
	for range 2 {
		result := <-claimed
		if !result.processed || result.err != nil {
			t.Fatal("parallel publication did not claim a distinct original observation", result.err)
		}
	}
	if progressed, err := worker.processOne(left, f.tenants[0]); err != nil || !progressed {
		t.Fatal("an original interface fault was not correlated", err)
	}
	if progressed, err := worker.processOne(left, f.tenants[0]); err != nil || progressed {
		t.Fatal("the worker reprocessed a receipt or accepted an unbound host", progressed, err)
	}
	var list struct {
		Items []incident.Incident `json:"items"`
	}
	body := callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, "/v1/incidents", nil, http.StatusOK)
	if err := json.Unmarshal(body, &list); err != nil || len(list.Items) != 1 ||
		list.Items[0].Title != "Interface down" || list.Items[0].SignalCount != 3 {
		t.Fatalf("the flap burst did not result in one incident with three original observations: %+v %v", list, err)
	}
	id := list.Items[0].ID
	path := "/v1/incidents/" + id
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusNotFound)
	f.in(f.tenants[0], func(ctx context.Context, scope tenancy.Scope) error {
		var receipts int
		err := scope.Q.QueryRow(ctx, `
SELECT count(*) FROM device_syslog_fault_queue AS q
 JOIN device_syslog AS d ON d.tenant_id=q.tenant_id AND d.id=q.event_id
 WHERE q.tenant_id=$1 AND q.incident_id=$2 AND q.observed_at=d.observed_at
   AND q.subject='Ethernet7/2' AND d.message=$3`, scope.Tenant.String(), id, down).Scan(&receipts)
		if err == nil && receipts != 3 {
			t.Fatalf("expected three durable original-row receipts, found %d", receipts)
		}
		return err
	})
	t.Run("linux-original-patterns", func(t *testing.T) {
		proveLinuxSyslogPatterns(t, f, server, addr, clients)
	})
}

// Capture actual RFC 5424 bytes from the runner's logger on an owned local
// socket. The fixture plants application messages, not kernel-origin faults.
// Replay the unchanged records through the normal authenticated TLS ingress.
func proveLinuxSyslogPatterns(t *testing.T, f *roleExplanationAPIFixture, api *httptest.Server, addr string, clients [2]*tls.Config) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("stock util-linux logger requires a Linux runner")
	}
	logger, err := exec.LookPath("logger")
	if err != nil {
		t.Fatal("Linux syslog proof requires the stock logger")
	}
	dir, err := os.MkdirTemp("", "probectl-qa-beta-logger-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "log")
	socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	from := time.Now().UTC()
	var hostname string
	for lane, messages := range [][]string{
		{"gateway 192.0.2.21 observed 3 errors", "gateway 192.0.2.22 observed 9 errors"},
		{"gateway 192.0.2.21 observed 3 errors"},
	} {
		for _, message := range messages {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			cmd := exec.CommandContext(ctx, logger, "--socket", socketPath, "--socket-errors=on",
				"--rfc5424", "--tag", "probectl-link-monitor", "--", message)
			err := cmd.Run()
			cancel()
			if err != nil {
				t.Fatal("stock Linux logger failed to write its fixture record", err)
			}
			if err := socket.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			raw := make([]byte, 2048)
			n, err := socket.Read(raw)
			if err != nil || n == len(raw) {
				t.Fatal("stock Linux logger record was unavailable or truncated", err)
			}
			line := string(raw[:n])
			header := strings.Fields(line)
			if len(header) < 7 || !strings.HasSuffix(header[0], ">1") || header[2] == "-" ||
				header[3] != "probectl-link-monitor" || !strings.HasSuffix(line, message) {
				t.Fatal("stock Linux logger did not emit the expected RFC 5424 record")
			}
			if hostname != "" && hostname != header[2] {
				t.Fatal("stock Linux logger changed the source host between fixture records")
			}
			hostname = header[2]
			sendSyslogLine(t, addr, clients[lane], line)
		}
	}
	params := url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {time.Now().Add(10 * time.Second).Format(time.RFC3339Nano)}, "device": {hostname}}
	const route = "/v1/device/syslog/patterns?"
	var ids [2]string
	for lane, tenant := range f.tenants {
		want := int64(2 - lane)
		shipped.Await(t, "stock Linux records reached their scoped pattern view", 6*time.Second, func() bool {
			raw := callSeasonalAPI(t, api, f.tokens[tenant], http.MethodGet, route+params.Encode(), nil, http.StatusOK)
			var page deviceSyslogPatternPage
			if err := json.Unmarshal(raw, &page); err != nil {
				t.Fatal(err)
			}
			if len(page.Patterns) != 1 || page.IndexedRows != want || page.UnindexedRows != 0 {
				return false
			}
			pattern := page.Patterns[0]
			ids[lane] = pattern.ID
			return pattern.ID != "" && pattern.Count == want && pattern.Kind == device.SyslogPatternOther
		})
	}
	if ids[0] == ids[1] {
		t.Fatal("identical Linux source records shared a cross-tenant pattern identity")
	}
}

func assertSyslogFaultCannotReferenceSibling(sibling context.Context, t *testing.T, f *roleExplanationAPIFixture, ops *device.PostgresOpsStore) {
	t.Helper()
	owner := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0]))
	rows, err := ops.ListSyslog(owner, f.tenants[0], device.OpsFilter{Limit: 1})
	if err != nil || len(rows) != 1 {
		t.Fatal("could not read the original syslog record in its owning scope", err)
	}
	err = tenancy.InTenant(sibling, f.pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `
INSERT INTO device_syslog_fault_queue (tenant_id, event_id, target, subject, observed_at)
VALUES ($1,$2,$3,'Ethernet7/2',$4)`, scope.Tenant.String(), rows[0].ID,
			"device-syslog:"+strings.Repeat("a", 64), rows[0].ObservedAt)
		return err
	})
	var check *pgconn.PgError
	if !errors.As(err, &check) || check.Code != "23503" || check.ConstraintName != "device_syslog_fault_event_fk" {
		t.Fatal("the database did not reject a fault receipt referencing a sibling's original", err)
	}
}

func startScopedSyslogFixture(t *testing.T, receiver *siem.SyslogReceiver) (string, [2]*tls.Config) {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("probectl paired syslog CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writePEM(t, dir, "ca.pem", ca.CertPEM())
	cert, key, err := ca.IssueServerCert("127.0.0.1", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := crypto.ServerClientCertTLSConfig(writePEM(t, dir, "server.pem", cert), writePEM(t, dir, "server-key.pem", key), caFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsServer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = receiver.Serve(ctx, listener)
	}()
	t.Cleanup(func() { cancel(); <-done })
	var clients [2]*tls.Config
	for i, subject := range []string{"edge-a", "edge-b"} {
		cert, key, err := ca.IssueClientCert(subject, "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		clients[i], err = crypto.ClientMTLSConfig(writePEM(t, dir, subject+".pem", cert), writePEM(t, dir, subject+"-key.pem", key), caFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	return listener.Addr().String(), clients
}
