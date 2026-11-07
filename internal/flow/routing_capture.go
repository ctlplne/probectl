// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"net/netip"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

var ErrRoutingCaptureAdmission = errors.New("complete raw flow exceeds routing capture admission")

// RoutingCaptureWitness identifies the original record before enrichment or
// exporter-clock clamping. Deterministic protobuf includes every known and
// retained unknown field. The returned tuple carries no canonical identity;
// only the verified evidence peer can bind it to a positive routing capture.
// Memory/work are finite byte-based budgets, never field/value truncation.
func RoutingCaptureWitness(ctx context.Context, record *flowv1.FlowRecord, memoryBytes, workUnits int64) ([32]byte, entity.FlowCaptureInput, error) {
	fail := func(err error) ([32]byte, entity.FlowCaptureInput, error) {
		return [32]byte{}, entity.FlowCaptureInput{}, err
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if record == nil {
		return fail(entity.ErrInvalidClaim)
	}
	size := int64(proto.Size(record))
	if memoryBytes <= 0 || workUnits <= 0 || size <= 0 || size > memoryBytes/4 || size > workUnits/8 {
		return fail(ErrRoutingCaptureAdmission)
	}
	exporter, err := netip.ParseAddr(record.GetExporterAddress())
	if err != nil {
		return fail(entity.ErrInvalidClaim)
	}
	source, err := netip.ParseAddr(record.GetSourceAddress())
	if err != nil {
		return fail(entity.ErrInvalidClaim)
	}
	destination, err := netip.ParseAddr(record.GetDestinationAddress())
	if err != nil {
		return fail(entity.ErrInvalidClaim)
	}
	input := entity.FlowCaptureInput{Exporter: exporter.Unmap(), Source: source.Unmap(), Destination: destination.Unmap(), Protocol: record.GetFlowProtocol(), Domain: record.GetObservationDomain()}
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(record)
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	hashed := crypto.Hash(body)
	if len(hashed) != 32 {
		return fail(entity.ErrInvalidClaim)
	}
	var digest [32]byte
	copy(digest[:], hashed)
	// Validation here prevents producer/consumer disagreement about malformed
	// tuples. These payload IDs are lookup selectors, never evidence authority.
	if _, err := entity.FlowCaptureKey(record.GetTenantId(), record.GetAgentId(), digest, input); err != nil {
		return fail(err)
	}
	return digest, input, nil
}
