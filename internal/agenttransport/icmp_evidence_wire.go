// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
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
	return &entity.ICMPMeasurement{Version: int(m.Version), DefinitionHash: m.DefinitionHash,
		StartedAt: time.Unix(0, m.StartedUnixNanos), CompletedAt: time.Unix(0, m.CompletedUnixNanos),
		Requested: m.Requested, Attempted: m.Attempted, Transmitted: m.Transmitted,
		Replies: m.Replies, SendErrors: m.SendErrors, ReadComplete: m.ReadComplete,
		Canceled: m.Canceled, IOFailed: m.IoFailed, Responders: append([]string{}, m.Responders...)}, nil
}
