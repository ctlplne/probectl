// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const (
	verdictFRRLocalASN       = 64500
	verdictFRRCarrierASN     = 64496
	verdictFRRExternalASN    = 64497
	verdictFRRLocalIP        = "10.42.0.2"
	verdictFRRCarrierIP      = "10.42.0.1"
	verdictFRRExternalIP     = "198.19.0.1"
	verdictFRRExternalPeerIP = "198.19.0.2"
	verdictFRRExternalPrefix = "198.19.0.0/24"
)

func startVerdictCarrierFRR(t *testing.T, healthy bool) verdictCarrierLab {
	t.Helper()
	router := startVerdictFRRPath(t, false)
	network := router.network
	vantages := [2]string{network.source, network.other}
	return verdictCarrierLab{
		discover: routedCarrierDiscoverer(t, network.source),
		verdictHandoffLab: verdictHandoffLab{
			peerASN: verdictFRRCarrierASN,
			states:  func() [2]entity.SNMPInterfaceState { return verdictFRRLinkStates(t, network) },
			probes: func(t *testing.T, healthy bool, senders []string, definitions []testspec.ExecutableDefinition) [2]entity.Observation {
				return collectVerdictCarrierProbes(t, vantages, healthy, senders, definitions)
			},
		},
		capture: func(definitions []testspec.ExecutableDefinition) *entity.BMPPeerSession {
			routeVerdictICMPTargets(t, network, network.child, definitions)
			checkVerdictICMPBaseline(t, vantages, definitions)
			router.awaitEstablished(t)
			socket := openVerdictFRRBMP(t, network.router)
			up := readVerdictFRRPeer(t, socket, "up")
			if healthy {
				return up
			}
			// Drop IPv4 at the provider's ingress. Its hold timer can expire
			// and return a real notification while link and ARP stay up.
			dependencyLabCommand(t, "ip", "netns", "exec", network.child, "tc", "qdisc", "add", "dev", "to-router", "clsact")
			dependencyLabCommand(t, "ip", "netns", "exec", network.child, "tc", "filter", "add", "dev", "to-router", "ingress", "protocol", "ip", "matchall", "action", "drop")
			down := readVerdictFRRPeer(t, socket, "down")
			if down.DownReason == nil || down.NotificationCode == nil || down.NotificationSubcode == nil {
				t.Fatal("stock FRR Peer Down omitted its original notification")
			}
			if *down.DownReason != 3 || *down.NotificationCode != 4 || *down.NotificationSubcode != 0 {
				t.Fatalf("stock FRR reported reason %d and notification %d/%d for the planted hold timer expiry",
					*down.DownReason, *down.NotificationCode, *down.NotificationSubcode)
			}
			return down
		},
	}
}

func verdictFRRLinkStates(t *testing.T, network dependencyPhysicalNetwork) [2]entity.SNMPInterfaceState {
	t.Helper()
	// The fixture's small IF-MIB adapter exposes kernel link state under
	// the configured logical handoff and backbone ifIndexes.
	_, handoff := readVerdictLinuxLink(t, network.router, "to-child")
	_, backbone := readVerdictLinuxLink(t, network.router, "to-source")
	if *handoff.OperStatus != 1 || *handoff.AdminStatus != 1 || *backbone.OperStatus != 1 || *backbone.AdminStatus != 1 {
		t.Fatal("the stock router's handoff and local backbone must remain up")
	}
	return [2]entity.SNMPInterfaceState{handoff, backbone}
}

type verdictFRRPath struct {
	network  dependencyPhysicalNetwork
	external string
	local    verdictFRRContainer
	carrier  verdictFRRContainer
}

func startVerdictFRRPath(t *testing.T, externalOrigin bool) verdictFRRPath {
	t.Helper()
	local := verdictFRRConfig{asn: verdictFRRLocalASN, address: verdictFRRLocalIP,
		peers: []verdictFRRNeighbor{{verdictFRRCarrierASN, verdictFRRCarrierIP, verdictFRRLocalIP}}, monitor: true, selectedRIB: externalOrigin}
	carrier := verdictFRRConfig{asn: verdictFRRCarrierASN, address: verdictFRRCarrierIP,
		peers: []verdictFRRNeighbor{{verdictFRRLocalASN, verdictFRRLocalIP, verdictFRRCarrierIP}}}
	var externalPID int
	if externalOrigin {
		carrier.peers = append(carrier.peers, verdictFRRNeighbor{verdictFRRExternalASN, verdictFRRExternalIP, verdictFRRExternalPeerIP})
		external := verdictFRRConfig{asn: verdictFRRExternalASN, address: verdictFRRExternalIP,
			peers: []verdictFRRNeighbor{{verdictFRRCarrierASN, verdictFRRExternalPeerIP, verdictFRRExternalIP}}, origin: verdictFRRExternalPrefix}
		externalPID = startVerdictFRR(t, external).pid
	}
	localContainer, carrierContainer := startVerdictFRR(t, local), startVerdictFRR(t, carrier)
	network := newDependencyPhysicalNetworkWithRouters(t, localContainer.pid, carrierContainer.pid)
	dependencyLabCommand(t, "ip", "-n", network.router, "addr", "add", verdictFRRLocalIP+"/24", "dev", "to-child")
	dependencyLabCommand(t, "ip", "-n", network.child, "addr", "add", verdictFRRCarrierIP+"/24", "dev", "to-router")
	enableDependencySecondVantage(t, network)
	path := verdictFRRPath{network: network, local: localContainer, carrier: carrierContainer}
	if externalOrigin {
		path.external = network.child + "-external"
		nameDependencyRouterNamespace(t, path.external, externalPID)
		addDependencyLabLink(t, network.child, "to-external", verdictFRRExternalPeerIP+"/30", path.external, "to-handoff", verdictFRRExternalIP+"/30")
	}
	return path
}

type verdictFRRNeighbor struct {
	asn     int
	address string
	source  string
}

type verdictFRRConfig struct {
	asn         int
	address     string
	peers       []verdictFRRNeighbor
	origin      string
	monitor     bool
	selectedRIB bool
}

type verdictFRRContainer struct {
	id  string
	pid int
}

func startVerdictFRR(t *testing.T, config verdictFRRConfig) verdictFRRContainer {
	t.Helper()
	name := "probectl-qa-beta-verdict-frr-" + gouuid.NewString()[:8]
	id := verdictFRRDocker(t, "create", "--pull=never", "--name", name, "--network", "none",
		"--label", "probectl.workspace=beta-verdict", "--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN",
		"--ulimit", "nofile=4096:4096", testsupport.FRRoutingImage)
	if id == "" {
		t.Fatal("the owned FRR container has no identity")
	}
	t.Cleanup(func() {
		if t.Failed() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "20", id).CombinedOutput()
			t.Logf("owned FRR router %s: %s", name, out)
			out, err := exec.CommandContext(ctx, "docker", "exec", id, "vtysh", "-c", "show bgp ipv4 unicast summary json", "-c", "show bgp ipv4 unicast json").CombinedOutput()
			t.Logf("owned FRR router %s IPv4 sessions and route table: %s (error %v)", name, out, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", id).CombinedOutput(); err != nil {
			t.Errorf("remove owned FRR router %s: %v: %s", name, err, out)
		}
	})
	frr := fmt.Sprintf(`frr defaults traditional
hostname %s
!
router bgp %d
 bgp router-id %s
 no bgp ebgp-requires-policy
`, name, config.asn, config.address)
	if config.origin != "" {
		frr += " no bgp network import-check\n"
	}
	for _, peer := range config.peers {
		frr += fmt.Sprintf(" neighbor %s remote-as %d\n neighbor %s update-source %s\n neighbor %s timers 1 3\n neighbor %s timers connect 1\n",
			peer.address, peer.asn, peer.address, peer.source, peer.address, peer.address)
	}
	frr += " address-family ipv4 unicast\n"
	for _, peer := range config.peers {
		frr += "  neighbor " + peer.address + " activate\n"
	}
	if config.origin != "" {
		frr += "  network " + config.origin + "\n"
	}
	frr += " exit-address-family\n"
	module := ""
	if config.monitor {
		module = " -M bmp"
		frr += " bmp targets probectl\n  bmp listener 127.0.0.1 port 5000\n  bmp monitor ipv4 unicast post-policy\n"
		if config.selectedRIB {
			frr += "  bmp monitor ipv4 unicast loc-rib\n"
		}
		frr += " exit\n"
	}
	files := map[string]string{
		"daemons":    "zebra=yes\nbgpd=yes\nvtysh_enable=yes\nzebra_options=\"-A 127.0.0.1 -s 90000000\"\nbgpd_options=\"-A 127.0.0.1" + module + "\"\n",
		"vtysh.conf": "service integrated-vtysh-config\n",
		"frr.conf":   frr + "exit\n",
	}
	dir := t.TempDir()
	for file, data := range files {
		path := filepath.Join(dir, file)
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		verdictFRRDocker(t, "cp", path, id+":/etc/frr/"+file)
	}
	verdictFRRDocker(t, "start", id)
	pid, err := strconv.Atoi(verdictFRRDocker(t, "inspect", "--format", "{{.State.Pid}}", id))
	if err != nil || pid <= 1 {
		t.Fatal("the owned FRR router has no live network namespace", err)
	}
	return verdictFRRContainer{id: id, pid: pid}
}

func (router verdictFRRContainer) requireEstablished(t *testing.T, neighbor string) {
	t.Helper()
	if state := router.neighborState(t, neighbor); state != "Established" {
		t.Fatalf("the stock session to %s did not stay established during the outside routing fault: %q", neighbor, state)
	}
}

func (lab verdictFRRPath) awaitEstablished(t *testing.T) {
	t.Helper()
	shipped.Await(t, "stock FRR established the two ends of the physical carrier handoff", 25*time.Second, func() bool {
		return lab.local.neighborState(t, verdictFRRCarrierIP) == "Established" &&
			lab.carrier.neighborState(t, verdictFRRLocalIP) == "Established"
	})
}

func (router verdictFRRContainer) neighborState(t *testing.T, neighbor string) string {
	t.Helper()
	raw := verdictFRRDocker(t, "exec", router.id, "vtysh", "-c", "show bgp ipv4 unicast summary json")
	var summary struct {
		Peers map[string]struct {
			State string `json:"state"`
		} `json:"peers"`
	}
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		t.Fatal("could not read the stock router's BGP neighbor state", err)
	}
	return summary.Peers[neighbor].State
}

func verdictFRRDocker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("owned FRR lab docker %s: %v: %s", args[0], err, out)
	}
	return strings.TrimSpace(string(out))
}

func openVerdictFRRBMP(t *testing.T, namespace string) net.Conn {
	t.Helper()
	var conn net.Conn
	shipped.Await(t, "stock FRR is listening inside its isolated namespace", 25*time.Second, func() bool {
		var err error
		conn, err = openVerdictLabSocket(namespace, func() (net.Conn, error) {
			return net.DialTimeout("tcp4", "127.0.0.1:5000", time.Second)
		})
		return err == nil
	})
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readVerdictFRRPeer(t *testing.T, conn net.Conn, state string) *entity.BMPPeerSession {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		raw, err := readVerdictFRRFrame(conn)
		if err != nil {
			t.Fatalf("stock FRR did not send the original peer %s frame: %v", state, err)
		}
		if raw[5] != 2 && raw[5] != 3 {
			continue
		}
		if len(raw) < 48 {
			t.Fatal("stock FRR omitted the peer header")
		}
		header, err := bgp.ParseBMPRouteViewHeader(raw[6:48])
		if err != nil {
			t.Fatal("stock FRR reported an invalid session header", err)
		}
		if header.View == bgp.BMPLocRIB {
			continue // The advertised local table is a different BMP source.
		}
		fact, err := bgp.DecodePhysicalPeerSession(t.Context(), raw, bgp.PeerMessageBudget{MemoryBytes: verdictMaxBMPFrame, WorkUnits: verdictMaxBMPFrame})
		if err != nil {
			t.Fatalf("stock FRR emitted an unadmitted physical peer frame: type=%d peer=%s bytes=%d: %v", raw[5], header.PeerAddress, len(raw), err)
		}
		if fact.PeerAddress != verdictFRRCarrierIP || fact.PeerASN != verdictFRRCarrierASN {
			t.Fatal("stock FRR reported a different peer than the configured lab handoff", fact.PeerAddress, fact.PeerASN)
		}
		if fact.State == state {
			return fact
		}
	}
}

const verdictMaxBMPFrame = 1 << 20

func readVerdictFRRFrame(conn net.Conn) ([]byte, error) {
	var common [6]byte
	if _, err := io.ReadFull(conn, common[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(common[1:5])
	if common[0] != 3 || size < uint32(len(common)) || size > verdictMaxBMPFrame {
		return nil, fmt.Errorf("invalid BMP version %d or length %d from the isolated FRR router", common[0], size)
	}
	raw := make([]byte, int(size))
	copy(raw, common[:])
	_, err := io.ReadFull(conn, raw[len(common):])
	return raw, err
}
