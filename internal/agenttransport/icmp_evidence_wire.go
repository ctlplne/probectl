// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"encoding/hex"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func parseICMPMeasurement(m *agentv1.IcmpMeasurement) (*entity.ICMPMeasurement, error) {
	if m == nil {
		return nil, nil
	}
	if len(m.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "unsupported ICMP evidence fields")
	}
	out := &entity.ICMPMeasurement{Version: int(m.Version), DefinitionHash: m.DefinitionHash,
		StartedAt: time.Unix(0, m.StartedUnixNanos), CompletedAt: time.Unix(0, m.CompletedUnixNanos),
		Requested: m.Requested, Attempted: m.Attempted, Transmitted: m.Transmitted,
		Replies: m.Replies, SendErrors: m.SendErrors, ReadComplete: m.ReadComplete,
		Canceled: m.Canceled, IOFailed: m.IoFailed, Responders: append([]string{}, m.Responders...)}
	for _, item := range m.NetworkErrors {
		if item == nil || len(item.ProtoReflect().GetUnknown()) != 0 {
			return nil, status.Error(codes.InvalidArgument, "unsupported ICMP network error fields")
		}
		out.NetworkErrors = append(out.NetworkErrors, entity.ICMPNetworkError{Sequence: item.Sequence,
			Responder: item.Responder, Type: item.Type, Code: item.Code, ReceivedAt: time.Unix(0, item.ReceivedUnixNanos),
			PacketDigest: hex.EncodeToString(item.PacketDigest), Conflicting: item.Conflicting})
	}
	return out, nil
}

func parseProbeOutcome(m *agentv1.ProbeOutcome) (*entity.ProbeOutcome, error) {
	if m == nil {
		return nil, nil
	}
	if len(m.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "unsupported configured outcome fields")
	}
	out := &entity.ProbeOutcome{Version: int(m.Version), DefinitionHash: m.DefinitionHash, CanaryType: m.CanaryType, StartedAt: time.Unix(0, m.StartedUnixNanos), CompletedAt: time.Unix(0, m.CompletedUnixNanos), Success: m.Success, Canceled: m.Canceled}
	if response := m.GetHttpResponse(); response != nil {
		if len(response.ProtoReflect().GetUnknown()) != 0 || response.GetStatusCode() < 100 || response.GetStatusCode() > 999 {
			return nil, status.Error(codes.InvalidArgument, "unsupported primary HTTP response fields")
		}
		out.HTTPResponse = &entity.ProbeHTTPResponse{StatusCode: int(response.GetStatusCode()), TLSVerified: response.GetTlsVerified(), SameOrigin: response.GetSameOrigin()}
	}
	return out, nil
}
