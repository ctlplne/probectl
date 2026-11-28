// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type pathChangeFRRLab struct {
	target  string
	transit [2]string
	source  [2]string
}

const pathChangeTraceExecutable = "/tmp/probectl-path-trace"

// Each tenant traces from a distinct router namespace on the same owned
// network. The two route replacements occur in opposite directions. The
// HTTPS handler receives actual path.Run output during each request and
// retains it with its normal timestamps and storage-layer tenant scope.
func TestFRRPathChangePublishesOncePerOwnedVantage(t *testing.T) {
	f := newPathChangeStorageFixture(t)
	lab := startPathChangeFRRLab(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	notifications := make(chan string, 8)
	f.server.WithPathChangeObserver(func(_ context.Context, in *incident.Incident, opened bool) {
		if opened {
			notifications <- in.TenantID
		}
	})
	var tests [2]string
	sources := make(map[tenancy.ID]string, len(f.tenants))
	for i, tenant := range f.tenants {
		sources[tenancy.ID(tenant)] = lab.source[i]
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permTestWrite, permChangeRead, permIncidentRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			owned, err := (store.Tests{}).Create(ctx, sc, store.TestInput{Name: "shared route target", Type: "icmp",
				Target: lab.target, IntervalSeconds: 60, TimeoutSeconds: 3, Enabled: true,
				Params: map[string]string{"allow_private_targets": "true"}})
			if err == nil {
				tests[i] = owned.ID
			}
			return err
		})
	}
	f.server.discover = func(ctx context.Context, cfg path.Config) (*path.Path, error) {
		tenant, ok := tenancy.FromContext(ctx)
		source := sources[tenant]
		if !ok || source == "" || cfg.Target != lab.target {
			return nil, errors.New("owned FRR trace scope mismatch")
		}
		encoded, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		out, err := exec.CommandContext(ctx, "docker", "exec", "--user", "0", source, pathChangeTraceExecutable, string(encoded)).Output()
		if err != nil {
			var exited *exec.ExitError
			if errors.As(err, &exited) {
				t.Logf("owned FRR trace failed in %s: %.400s", source, exited.Stderr)
			}
			return nil, fmt.Errorf("probe from the owned router namespace: %w", err)
		}
		var observed path.Path
		if err := json.Unmarshal(out, &observed); err != nil {
			return nil, err
		}
		return &observed, nil
	}

	timeline := func(tenant string) []change.Event {
		t.Helper()
		var result struct{ Items []change.Event }
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/changes", nil, http.StatusOK)
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result.Items
	}
	var events [2]change.Event
	for round := range 4 {
		for i, tenant := range f.tenants {
			want := lab.transit[i]
			switch round {
			case 0:
				lab.route(t, i, "", want)
			case 1:
				lab.route(t, i, want, lab.transit[1-i])
				want = lab.transit[1-i]
			default:
				want = lab.transit[1-i]
			}
			data := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/tests/"+tests[i]+"/path", nil, http.StatusOK)
			var got path.Path
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			requireFRRPathHop(t, got, lab.target, want)
			rows := timeline(tenant)
			if round < 2 {
				if len(rows) != 0 {
					t.Fatalf("lane %d published an unconfirmed route change at round %d", i, round)
				}
				continue
			}
			if len(rows) != 1 || rows[0].Ref != tests[i] || rows[0].Source != pathChangeSource ||
				rows[0].Attributes["vantage"] != path.VantageControlPlane || rows[0].Attributes["vantage_id"] == "" ||
				rows[0].Attributes["changed_hops"] != "1" || rows[0].Attributes["confirmation_rounds"] != "2" {
				t.Fatalf("lane %d lost its one confirmed route event: %+v", i, rows)
			}
			if round == 2 {
				events[i] = rows[0]
			} else if rows[0].ID != events[i].ID {
				t.Fatalf("lane %d replaced its accepted event on the next unchanged round", i)
			}
		}
	}
	if len(notifications) != 2 || <-notifications != f.tenants[0] || <-notifications != f.tenants[1] {
		t.Fatal("the event observer did not receive exactly one notification from each owning tenant")
	}
	if events[0].Attributes["vantage_id"] == events[1].Attributes["vantage_id"] {
		t.Fatal("the two tenant vantages shared an event identity")
	}
	for i, tenant := range f.tenants {
		pathFor := func(testID, roundID string) string {
			return "/v1/tests/" + testID + "/path/history?round_id=" + url.QueryEscape(roundID)
		}
		roundID := events[i].Attributes["confirmed_round_id"]
		if roundID == "" {
			t.Fatal("confirmed route event did not cite its wire observation")
		}
		var retained struct{ Items []pathstore.Snapshot }
		data := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, pathFor(tests[i], roundID), nil, http.StatusOK)
		if err := json.Unmarshal(data, &retained); err != nil || len(retained.Items) != 1 || retained.Items[0].ID != roundID {
			t.Fatalf("lane %d did not retain its exact confirmed round", i)
		}
		requireFRRPathHop(t, retained.Items[0].Path, lab.target, lab.transit[1-i])
		sibling := f.tokens[f.tenants[1-i]]
		callSeasonalAPI(t, socket, sibling, http.MethodGet, pathFor(tests[i], roundID), nil, http.StatusNotFound)
		data = callSeasonalAPI(t, socket, sibling, http.MethodGet, pathFor(tests[1-i], roundID), nil, http.StatusOK)
		if err := json.Unmarshal(data, &retained); err != nil || len(retained.Items) != 0 || bytes.Contains(data, []byte(roundID)) {
			t.Fatalf("lane %d's wire observation reached sibling history", i)
		}
	}
}

func requireFRRPathHop(t *testing.T, observed path.Path, target, transit string) {
	t.Helper()
	if observed.TargetIP != target || !observed.DestinationReached || observed.MeasurementFidelity == nil ||
		observed.MeasurementFidelity.AcquisitionMode != "raw_icmp" || observed.Vantage != path.VantageControlPlane ||
		len(observed.Hops) < 2 || observed.Hops[0].TTL != 1 || len(observed.Hops[0].Nodes) != 1 ||
		observed.Hops[0].Nodes[0].IP != transit {
		t.Fatalf("the served raw probe did not reach its target through FRR transit %s: %+v", transit, observed.Hops)
	}
}

func startPathChangeFRRLab(t *testing.T) pathChangeFRRLab {
	t.Helper()
	if err := exec.CommandContext(t.Context(), "docker", "info", "--format", "{{.ServerVersion}}").Run(); err != nil {
		testsupport.SkipOrFatal(t, "the owned FRR path lab needs Docker: %v", err)
	}
	name := "probectl-qa-beta-fx30-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var subnet string
	for offset := range 8 {
		base := (int(time.Now().UnixMicro()%252) + offset) % 252
		subnet = fmt.Sprintf("198.19.%d.", base)
		out, err := exec.CommandContext(t.Context(), "docker", "network", "create", "--internal", "--subnet", subnet+"0/24", name).CombinedOutput()
		if err == nil {
			break
		}
		if !strings.Contains(string(out), "overlap") || offset == 7 {
			t.Fatalf("create the owned FRR path network: %v %.240s", err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })
	lab := pathChangeFRRLab{target: subnet + "10", transit: [2]string{subnet + "2", subnet + "3"}}
	endpoint := func(address, redirectSetting string) string {
		return fmt.Sprintf("name=%s,ip=%s,driver-opt=com.docker.network.endpoint.sysctls=net.ipv4.conf.IFNAME.%s=0",
			name, address, redirectSetting)
	}
	for i, address := range []string{lab.target, lab.transit[0], lab.transit[1]} {
		container := fmt.Sprintf("%s-transit-%d", name, i)
		pathLabDocker(t, "create", "--name", container, "--network", endpoint(address, "send_redirects"),
			"--entrypoint", "/bin/sleep", "--sysctl", "net.ipv4.ip_forward=1",
			"--sysctl", "net.ipv4.conf.all.send_redirects=0",
			testsupport.FRRoutingImage, "3600")
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
		pathLabDocker(t, "start", container)
	}
	temp := t.TempDir()
	tracer := filepath.Join(temp, "frr-trace")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", tracer, "./internal/path/testdata/frrtrace")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the production tracer fixture: %v %.500s", err, out)
	}
	for file, body := range map[string]string{
		"daemons":    "zebra=yes\nstaticd=yes\nvtysh_enable=yes\n",
		"vtysh.conf": "service integrated-vtysh-config\n",
		"frr.conf":   "frr defaults traditional\n",
	} {
		if err := os.WriteFile(filepath.Join(temp, file), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i := range lab.source {
		container := fmt.Sprintf("%s-source-%d", name, i)
		lab.source[i] = container
		pathLabDocker(t, "create", "--name", container, "--network", endpoint(subnet+strconv.Itoa(11+i), "accept_redirects"),
			"--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN", "--ulimit", "nofile=4096:4096",
			"--sysctl", "net.ipv4.conf.all.accept_redirects=0",
			testsupport.FRRoutingImage)
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
		for _, file := range []string{"daemons", "vtysh.conf", "frr.conf"} {
			pathLabDocker(t, "cp", filepath.Join(temp, file), container+":/etc/frr/"+file)
		}
		pathLabDocker(t, "cp", tracer, container+":"+pathChangeTraceExecutable)
		pathLabDocker(t, "start", container)
		shipped.Await(t, "owned FRR routing socket", 15*time.Second, func() bool {
			return exec.CommandContext(t.Context(), "docker", "exec", "--user", "0", container,
				"vtysh", "-c", "show ip route").Run() == nil
		})
	}
	return lab
}

func (lab pathChangeFRRLab) route(t *testing.T, lane int, previous, next string) {
	t.Helper()
	container := lab.source[lane]
	args := []string{"exec", "--user", "0", container, "vtysh", "-c", "configure terminal"}
	if previous != "" {
		args = append(args, "-c", "no ip route "+lab.target+"/32 "+previous)
	}
	args = append(args, "-c", "ip route "+lab.target+"/32 "+next)
	pathLabDocker(t, args...)
	shipped.Await(t, "the owned FRR route is active in the kernel", 10*time.Second, func() bool {
		out, err := exec.CommandContext(t.Context(), "docker", "exec", container, "ip", "route", "get", lab.target).Output()
		return err == nil && strings.Contains(string(out), "via "+next+" ")
	})
}

func pathLabDocker(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("owned FRR path lab command %v: %v %.400s", args, err, out)
	}
}
