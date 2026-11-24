// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

const (
	MeshResultKeyBytes = 32
	MaxMeshResultBytes = 64 << 10
	meshClockSkew      = 5 * time.Second
)

var ErrInvalidMeshReport = errors.New("a2a mesh: invalid or expired report")

// VerifiedMeshReport binds one admitted wire result to server-side assignment metadata.
type VerifiedMeshReport struct {
	MeshResult
	WireResult   *resultv1.Result
	Digest       [32]byte
	RegisteredAt time.Time
	ExpiresAt    time.Time
}

// VerifyReport selects the key using the TLS tenant and agent. Do not use
// payload identity, role or metadata to select the assignment or key.
func (m *MeshScheduler) VerifyReport(tenant, agent, sessionID string, payload, mac []byte) (VerifiedMeshReport, error) {
	key := sessionKey{tenant, sessionID}
	m.mu.Lock()
	session, assigned := m.sessions[key]
	assignment := m.assignments[key]
	m.mu.Unlock()
	now := m.now()
	expires := session.CreatedAt.Add(meshSessionTTL)
	if !assigned || assignment == nil || !now.Before(expires) {
		return VerifiedMeshReport{}, ErrInvalidMeshReport
	}
	var reporter *meshReporter
	var role, peer string
	switch agent {
	case session.InitiatorAgent:
		reporter, role, peer = &assignment.initiator, "initiator", session.ResponderAgent
	case session.ResponderAgent:
		reporter, role, peer = &assignment.responder, "responder", session.InitiatorAgent
	default:
		return VerifiedMeshReport{}, ErrInvalidMeshReport
	}
	issued := reporter.issued.Load()
	if issued == nil || !VerifyMeshResult(reporter.key[:], sessionID, payload, mac) {
		return VerifiedMeshReport{}, ErrInvalidMeshReport
	}
	var r resultv1.Result
	if err := proto.Unmarshal(payload, &r); err != nil {
		return VerifiedMeshReport{}, ErrInvalidMeshReport
	}
	start := time.Unix(0, r.StartTimeUnixNano).UTC()
	duration := time.Duration(r.DurationNano)
	resultID, err := uuid.Parse(r.ResultId)
	if err != nil || resultID.Version() != 4 || resultID.Variant() != uuid.RFC4122 || resultID.String() != r.ResultId ||
		r.CanaryType != "a2a" || r.TenantId != tenant || r.AgentId != agent ||
		r.Attributes["a2a.role"] != role || r.Attributes["a2a.peer_agent_id"] != peer ||
		r.Attributes["a2a.mode"] != session.Mode || r.Attributes["network.transport"] != session.Mode ||
		start.Before(issued.at.Add(-meshClockSkew)) || duration <= 0 || duration > meshSessionTTL ||
		start.Add(duration).After(now.Add(meshClockSkew)) || !start.Add(duration).Before(expires) ||
		!boundedMeshText(r.ServerAddress, 320) || !boundedMeshText(r.ErrorMessage, 512) || !boundedMeshText(r.AgentVersion, 64) {
		return VerifiedMeshReport{}, ErrInvalidMeshReport
	}
	if r.ServerAddress != issued.target || !validMeshMetrics(r.Metrics, session.Count, role, r.Success) {
		return VerifiedMeshReport{}, ErrInvalidMeshReport
	}
	// Rebuild the ordinary telemetry projection from admitted fields. Arbitrary
	// signed attributes, protocol fields and unknown wire data have no authority.
	wire := &resultv1.Result{TenantId: tenant, AgentId: agent, ResultId: r.ResultId, AgentVersion: r.AgentVersion,
		CanaryType: "a2a", ServerAddress: r.ServerAddress, Success: r.Success, ErrorMessage: r.ErrorMessage,
		StartTimeUnixNano: r.StartTimeUnixNano, DurationNano: r.DurationNano, Metrics: r.Metrics,
		Attributes: map[string]string{"a2a.role": role, "a2a.mode": session.Mode, "network.transport": session.Mode, "a2a.peer_agent_id": peer}}
	return VerifiedMeshReport{
		MeshResult: MeshResult{TenantID: tenant, SessionID: sessionID, AgentID: agent, Role: role,
			FromSite: session.FromSite, ToSite: session.ToSite, InitiatorAgent: session.InitiatorAgent, ResponderAgent: session.ResponderAgent,
			RecordedAt: start, Metrics: r.Metrics, Success: r.Success, LossRatio: r.Metrics["loss.ratio"]},
		WireResult: wire, Digest: [32]byte(crypto.Hash(payload)), RegisteredAt: reporter.registeredAt, ExpiresAt: expires,
	}, nil
}

func boundedMeshText(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

func validMeshMetrics(metrics map[string]float64, count uint32, role string, success bool) bool {
	sent, sentOK := metrics["packets.sent"]
	received, receivedOK := metrics["packets.received"]
	loss, lossOK := metrics["loss.ratio"]
	if !sentOK || !receivedOK || !lossOK || count == 0 || sent != float64(count) ||
		received != math.Trunc(received) || received < 0 || received > sent || success != (received > 0) ||
		loss != math.Round((sent-received)/sent*10000)/10000 {
		return false
	}
	for name, value := range metrics {
		switch name {
		case "packets.sent", "packets.received", "loss.ratio":
			continue
		case "rtt.min.ms", "rtt.avg.ms", "rtt.max.ms", "rtt.stddev.ms", "jitter.ms", "forward.avg.ms", "forward.max.ms", "reverse.avg.ms", "reverse.max.ms":
			if role != "initiator" || !success || math.IsNaN(value) || value < 0 || value > float64(meshSessionTTL.Milliseconds()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// SignMeshResult authenticates the exact wire bytes in the context of one
// mesh assignment. A nil signature means the signing input was invalid.
func SignMeshResult(key []byte, sessionID string, payload []byte) []byte {
	input := meshResultSignInput(key, sessionID, payload)
	if input == nil {
		return nil
	}
	return crypto.Sign(key, input)
}

// VerifyMeshResult checks a report using the assigned reporter's own key.
func VerifyMeshResult(key []byte, sessionID string, payload, mac []byte) bool {
	if len(mac) != 32 {
		return false
	}
	input := meshResultSignInput(key, sessionID, payload)
	return input != nil && crypto.Verify(key, input, mac)
}

// IsMeshSessionID checks the canonical wire form without a scheduler lookup.
func IsMeshSessionID(id string) bool { return decodeMeshSessionID(id) != nil }

// MeshSessionHandle derives the public mesh identifier from the private probe
// credential. Results and operator APIs use the handle. Probes use the secret
// distributed in the coordination task, including on older agents.
func MeshSessionHandle(probeSession string) string {
	credential := decodeMeshSessionID(probeSession)
	if credential == nil {
		return ""
	}
	digest := crypto.Hash(append([]byte("probectl/a2a/mesh-handle/v1\x00"), credential...))
	return hex.EncodeToString(digest[:16])
}

func decodeMeshSessionID(id string) []byte {
	if len(id) != 32 {
		return nil
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || hex.EncodeToString(decoded) != id {
		return nil
	}
	return decoded
}

func meshResultSignInput(key []byte, sessionID string, payload []byte) []byte {
	const domain = "probectl/a2a/mesh-result/v1\x00"
	if len(key) != MeshResultKeyBytes || len(payload) == 0 || len(payload) > MaxMeshResultBytes {
		return nil
	}
	id := decodeMeshSessionID(sessionID)
	if id == nil {
		return nil
	}
	input := make([]byte, 0, len(domain)+len(id)+len(payload))
	input = append(input, domain...)
	input = append(input, id...)
	return append(input, payload...)
}
