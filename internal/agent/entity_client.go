// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// EvidenceClient has only the D-179 RPC. It cannot register, heartbeat or
// submit raw results with the evidence-only certificate. The transport uses
// the existing agent listener and pins renewals to the exact original SVID.
type EvidenceClient struct {
	mu                                          sync.RWMutex
	reconnectMu                                 sync.Mutex
	conn                                        *grpc.ClientConn
	svc                                         agentv1.AgentServiceClient
	closed                                      bool
	needsReconnect                              bool
	tenantID                                    string
	agentID                                     string
	addr, certFile, keyFile, caFile, serverName string
}

// DialEntityEvidence refuses a missing or wrong-plane SVID before any network
// call. A rotated certificate may change serial, but never tenant/agent/plane.
func DialEntityEvidence(addr, certFile, keyFile, caFile, serverName string) (*EvidenceClient, error) {
	id, err := crypto.EntitySPIFFEIDFromCertFile(certFile)
	if err != nil {
		return nil, err
	}
	conn, err := dialEntityEvidenceConn(addr, certFile, keyFile, caFile, serverName, id.String())
	if err != nil {
		return nil, err
	}
	return &EvidenceClient{conn: conn, svc: agentv1.NewAgentServiceClient(conn),
		tenantID: id.TenantID, agentID: id.AgentID,
		addr: addr, certFile: certFile, keyFile: keyFile, caFile: caFile,
		serverName: serverName}, nil
}

func dialEntityEvidenceConn(addr, certFile, keyFile, caFile, serverName, spiffeID string) (*grpc.ClientConn, error) {
	cfg, _, err := crypto.ClientMTLSConfigRotating(certFile, keyFile, caFile, spiffeID)
	if err != nil {
		return nil, err
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ReconnectAfterRotation replaces the HTTP/2 TLS connection after an atomic
// certificate swap. A long-lived gRPC connection would otherwise keep
// presenting the old serial even though the files contain a renewed SVID.
func (c *EvidenceClient) ReconnectAfterRotation() error {
	if c == nil || c.addr == "" {
		return ErrEvidenceBatchInvalid
	}
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrEvidenceBatchInvalid
	}
	c.needsReconnect = true
	c.mu.Unlock()
	id, err := crypto.EntitySPIFFEIDFromCertFile(c.certFile)
	if err != nil || id.TenantID != c.tenantID || id.AgentID != c.agentID {
		return ErrEvidenceBatchInvalid
	}
	conn, err := dialEntityEvidenceConn(c.addr, c.certFile, c.keyFile, c.caFile,
		c.serverName, id.String())
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return ErrEvidenceBatchInvalid
	}
	old := c.conn
	c.conn, c.svc = conn, agentv1.NewAgentServiceClient(conn)
	c.needsReconnect = false
	c.mu.Unlock()
	if old != nil {
		_ = old.Close() // an in-flight optional evidence RPC may retry
	}
	return nil
}

func (c *EvidenceClient) Identity() (tenantID, agentID string) {
	return c.tenantID, c.agentID
}

var ErrEvidenceBatchInvalid = errors.New("agent: invalid entity evidence batch")

func (c *EvidenceClient) encodeEvidence(now time.Time, observations []entity.Observation) (*agentv1.SubmitEntityEvidenceRequest, error) {
	if c == nil || len(observations) == 0 || len(observations) > 64 {
		return nil, ErrEvidenceBatchInvalid
	}
	c.mu.RLock()
	ready := c.svc != nil
	c.mu.RUnlock()
	if !ready {
		return nil, ErrEvidenceBatchInvalid
	}
	request := &agentv1.SubmitEntityEvidenceRequest{
		Observations: make([]*agentv1.EntityEvidenceObservation, 0, len(observations))}
	for _, raw := range observations {
		item, err := raw.Normalize(now)
		if err != nil || item.Source.AgentID != c.agentID {
			return nil, ErrEvidenceBatchInvalid
		}
		var addresses *agentv1.AgentAddressSnapshot
		if item.AgentAddresses != nil {
			addresses = &agentv1.AgentAddressSnapshot{Addresses: make([]string, len(item.AgentAddresses))}
			for i, address := range item.AgentAddresses {
				addresses.Addresses[i] = address.String()
			}
		}
		var prefixes *agentv1.SnmpInterfacePrefixSnapshot
		if item.SNMPInterfacePrefixes != nil {
			prefixes = &agentv1.SnmpInterfacePrefixSnapshot{}
			for _, row := range item.SNMPInterfacePrefixes {
				prefixes.Prefixes = append(prefixes.Prefixes, &agentv1.SnmpInterfacePrefix{
					IfIndex: row.IfIndex, Prefix: row.Prefix.String(), OnLink: row.OnLink})
			}
		}
		request.Observations = append(request.Observations,
			&agentv1.EntityEvidenceObservation{
				ObservationId: item.ID, SourceKind: string(item.Source.Kind),
				ConfiguredRef: item.Source.SourceRef,
				AliasKind:     string(item.Alias.Kind), AliasValue: item.Alias.Value,
				SourceRef: item.SourceRef, ObservedUnixNanos: item.ObservedAt.UnixNano(),
				OriginSerial:              item.OriginSerial,
				InterfaceName:             item.InterfaceName,
				InterfaceDescription:      item.InterfaceDescription,
				SystemDescription:         item.SystemDescription,
				SystemName:                item.SystemName,
				AgentAddresses:            addresses,
				SnmpInterfacePrefixes:     prefixes,
				Icmp:                      encodeICMPMeasurement(item.ICMP),
				ProbeOutcome:              encodeProbeOutcome(item.Outcome),
				NeighborProtocol:          item.NeighborProtocol,
				NeighborLocalIfIndex:      item.NeighborLocalIfIndex,
				NeighborLocalPortId:       item.NeighborLocalPortID,
				NeighborRemotePortId:      item.NeighborRemotePortID,
				NeighborChassisId:         item.NeighborChassisID,
				NeighborDeviceName:        item.NeighborDeviceName,
				NeighborManagementAddress: item.NeighborAddress,
			})
		if proto.Size(request) > 1<<20 {
			return nil, ErrEvidenceBatchInvalid
		}
	}
	return request, nil
}

// Submit sends only source observations; tenant, context and canonical entity
// are absent from the wire request. A failed call leaves raw bus telemetry
// untouched and creates no canonical join. The caller may retry the same
// observation UUID under the same SVID serial without duplicating evidence;
// after a rotation it must make a new observation with a new UUID/time.
func (c *EvidenceClient) Submit(ctx context.Context, observations []entity.Observation) (accepted, unresolved int, err error) {
	if c == nil {
		return 0, 0, ErrEvidenceBatchInvalid
	}
	c.mu.RLock()
	needsReconnect := c.needsReconnect
	c.mu.RUnlock()
	if needsReconnect {
		if err := c.ReconnectAfterRotation(); err != nil {
			return 0, 0, err
		}
	}
	request, err := c.encodeEvidence(time.Now(), observations)
	if err != nil {
		return 0, 0, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.RLock()
	svc := c.svc
	c.mu.RUnlock()
	if svc == nil {
		return 0, 0, ErrEvidenceBatchInvalid
	}
	response, err := svc.SubmitEntityEvidence(callCtx, request,
		grpc.MaxCallSendMsgSize(1<<20), grpc.MaxCallRecvMsgSize(1<<20))
	if err != nil {
		return 0, 0, err
	}
	if hasPublicRoutingReceipt(response) || response.GetDeviceCounter() != nil || response.GetFlowRouting() != nil || !validICMPEvidenceReceipt(request, response) {
		return 0, 0, ErrEvidenceBatchInvalid
	}
	return int(response.GetAccepted()), int(response.GetUnresolved()), nil
}

// SubmitFault uses the same evidence-only mTLS connection as canonical source
// observations. A fault is optional signal input; the server derives sender
// and tenant from the live certificate, never from this request.
func (c *EvidenceClient) SubmitFault(ctx context.Context, raw entity.FaultObservation) error {
	accepted, err := c.SubmitFaults(ctx, []entity.FaultObservation{raw})
	if err != nil {
		return err
	}
	if accepted != 1 {
		return ErrEvidenceBatchInvalid
	}
	return nil
}

// SubmitFaults batches up to 64 independent collector faults on the existing
// evidence-only RPC. The server receipts each UUID under its authenticated
// tenant and agent, so retrying a timed-out batch is safe.
func (c *EvidenceClient) SubmitFaults(ctx context.Context, raw []entity.FaultObservation) (int, error) {
	if c == nil || len(raw) == 0 || len(raw) > 64 {
		return 0, ErrEvidenceBatchInvalid
	}
	c.mu.RLock()
	needsReconnect := c.needsReconnect
	c.mu.RUnlock()
	if needsReconnect {
		if err := c.ReconnectAfterRotation(); err != nil {
			return 0, err
		}
	}
	request := &agentv1.SubmitEntityEvidenceRequest{
		Faults: make([]*agentv1.EntityFaultObservation, 0, len(raw))}
	now := time.Now()
	for _, item := range raw {
		fault, err := item.Normalize(now)
		if err != nil || fault.Source.AgentID != c.agentID {
			return 0, ErrEvidenceBatchInvalid
		}
		request.Faults = append(request.Faults, &agentv1.EntityFaultObservation{
			ObservationId: fault.ID, SourceKind: string(fault.Source.Kind),
			ConfiguredRef: fault.Source.SourceRef, TargetAddress: fault.Target,
			Kind: string(fault.Kind), ObservedUnixNanos: fault.ObservedAt.UnixNano(),
		})
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.RLock()
	svc := c.svc
	c.mu.RUnlock()
	if svc == nil {
		return 0, ErrEvidenceBatchInvalid
	}
	response, err := svc.SubmitEntityEvidence(callCtx, request,
		grpc.MaxCallSendMsgSize(1<<20), grpc.MaxCallRecvMsgSize(1<<20))
	if err != nil {
		return 0, err
	}
	if hasPublicRoutingReceipt(response) || response.GetDeviceCounter() != nil || response.GetFlowRouting() != nil || (response.GetIcmpMeasurementsPersisted() != 0 || response.GetProbeOutcomesPersisted() != 0) || int(response.GetFaultsPersisted()) != len(raw) {
		return 0, ErrEvidenceBatchInvalid
	}
	return len(raw), nil
}

func (c *EvidenceClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.closed = true
	old := c.conn
	c.conn, c.svc = nil, nil
	c.mu.Unlock()
	if old == nil {
		return nil
	}
	return old.Close()
}
