// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func parseBMPPeerSession(ctx context.Context, session *agentv1.BmpPeerSession) (*entity.BMPPeerSession, error) {
	if session == nil {
		return nil, nil
	}
	if len(session.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "unsupported BMP peer session fields")
	}
	fact, err := bgp.DecodePhysicalPeerSession(ctx, session.Frame, bgp.PeerMessageBudget{MemoryBytes: int64(len(session.Frame)) * 128, WorkUnits: int64(len(session.Frame)) * 4})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid whole physical BMP peer session")
	}
	return fact, nil
}
