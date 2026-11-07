// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// This compact representation stays inside the existing encrypted snapshot
// header. Digests use canonical hex, and nanoseconds stay quoted int64 values;
// no portable row JSON or float conversion can detach original selectors.
type flowRoutingCaptureSelector struct {
	Sender      string `json:"sender"`
	Raw         string `json:"raw"`
	Key         string `json:"key"`
	Clock       int64  `json:"at,string"`
	Exporter    string `json:"exporter"`
	Source      string `json:"src"`
	Destination string `json:"dst"`
	Protocol    string `json:"protocol"`
	Domain      uint32 `json:"domain"`
}

type flowRoutingSnapshotValidity struct {
	Digest      string                       `json:"digest"`
	InputDigest string                       `json:"authority"`
	Captures    []flowRoutingCaptureSelector `json:"captures"`
}

func encodeFlowRoutingValidity(proof *flowstore.RoutingQueryProof) (*flowRoutingSnapshotValidity, error) {
	if proof == nil || !canonicalFlowRoutingDigest(proof.Digest) || !canonicalFlowRoutingDigest(proof.InputDigest) {
		return nil, flowstore.ErrSnapshotInputs
	}
	out := &flowRoutingSnapshotValidity{Digest: proof.Digest, InputDigest: proof.InputDigest, Captures: make([]flowRoutingCaptureSelector, len(proof.Captures))}
	for i, read := range proof.Captures {
		input := read.Witness.Input
		out.Captures[i] = flowRoutingCaptureSelector{Sender: read.Sender, Raw: hex.EncodeToString(read.Witness.RawDigest[:]), Key: hex.EncodeToString(read.Ref.Key[:]), Clock: read.Ref.CapturedAt.UnixNano(), Exporter: input.Exporter.String(), Source: input.Source.String(), Destination: input.Destination.String(), Protocol: input.Protocol, Domain: input.Domain}
	}
	return out, nil
}

func decodeFlowRoutingValidity(ctx context.Context, tenant string, proof *flowRoutingSnapshotValidity, memory int64) ([]flowstore.RoutingCaptureRead, error) {
	if bound, present := tenancy.FromContext(ctx); !present || bound.String() != tenant {
		return nil, flowstore.ErrSnapshotInputs
	}
	if proof == nil || !canonicalFlowRoutingDigest(proof.Digest) || !canonicalFlowRoutingDigest(proof.InputDigest) || memory <= 0 || int64(len(proof.Captures)) > memory/4096 {
		return nil, flowstore.ErrSnapshotInputs
	}
	out := make([]flowstore.RoutingCaptureRead, len(proof.Captures))
	for i, value := range proof.Captures {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !canonicalFlowRoutingDigest(value.Raw) || !canonicalFlowRoutingDigest(value.Key) || value.Clock <= 0 {
			return nil, flowstore.ErrSnapshotInputs
		}
		raw, _ := hex.DecodeString(value.Raw)
		key, _ := hex.DecodeString(value.Key)
		input, err := flowRoutingSelectorInput(value)
		if err != nil {
			return nil, err
		}
		read := flowstore.RoutingCaptureRead{Sender: value.Sender, Witness: entity.FlowCaptureWitness{Input: input}, Ref: entity.FlowCaptureReference{CapturedAt: time.Unix(0, value.Clock).UTC()}}
		copy(read.Witness.RawDigest[:], raw)
		copy(read.Ref.Key[:], key)
		original, err := entity.FlowCaptureKey(tenant, read.Sender, read.Witness.RawDigest, input)
		if err != nil || original != read.Ref.Key {
			return nil, flowstore.ErrSnapshotInputs
		}
		out[i] = read
	}
	return out, nil
}

func canonicalFlowRoutingDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	body, err := hex.DecodeString(value)
	return err == nil && len(body) == 32 && hex.EncodeToString(body) == value
}

func flowRoutingSelectorInput(value flowRoutingCaptureSelector) (entity.FlowCaptureInput, error) {
	exporter, err := netip.ParseAddr(value.Exporter)
	if err != nil || exporter.String() != value.Exporter {
		return entity.FlowCaptureInput{}, flowstore.ErrSnapshotInputs
	}
	source, err := netip.ParseAddr(value.Source)
	if err != nil || source.String() != value.Source {
		return entity.FlowCaptureInput{}, flowstore.ErrSnapshotInputs
	}
	destination, err := netip.ParseAddr(value.Destination)
	if err != nil || destination.String() != value.Destination {
		return entity.FlowCaptureInput{}, flowstore.ErrSnapshotInputs
	}
	return entity.FlowCaptureInput{Exporter: exporter, Source: source, Destination: destination, Protocol: value.Protocol, Domain: value.Domain}, nil
}

func (source *flowSnapshotSource) validateRoutingAuthorization(ctx context.Context, scope flowsnapshot.Scope, receipt flowSnapshotValidity) error {
	routing := false
	for _, input := range receipt.Inputs {
		routing = routing || flowSnapshotInputUsesRouting(input)
	}
	if !routing && len(receipt.Routing) == 0 {
		return nil
	}
	actor := auth.PrincipalFrom(ctx)
	if !routing || len(receipt.Routing) != len(receipt.Inputs) || actor == nil || actor.TenantID != scope.TenantID || actor.UserID != scope.Owner || source.server == nil {
		return apierror.Forbidden("current routing authority is required; run a fresh query")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, source.server.flowStore)
	for i, input := range receipt.Inputs {
		proof := receipt.Routing[i]
		if !flowSnapshotInputUsesRouting(input) {
			if proof != nil {
				return apierror.Forbidden("routing receipt does not match its source fields")
			}
			continue
		}
		reads, err := decodeFlowRoutingValidity(ctx, scope.TenantID, proof, budget.MemoryBytes/4)
		if err != nil {
			return flowExplorerStoreError(err)
		}
		current, err := source.server.recheckFlowRoutingSnapshot(ctx, actor, reads, budget)
		if err != nil {
			return err
		}
		if current.digest != proof.Digest || current.inputDigest != proof.InputDigest {
			return apierror.Forbidden("routing source authority changed; run a fresh query")
		}
	}
	return nil
}

func flowSnapshotInputUsesRouting(input flowstore.SnapshotInputs) bool {
	for _, name := range input.Fields {
		if _, routing := flow.RoutingQueryField(name); routing {
			return true
		}
	}
	return false
}
