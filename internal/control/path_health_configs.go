// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"reflect"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
)

type pathConfigCheck struct {
	binding    device.ConfigArchiveBinding
	references []device.ConfigArchiveReference
	bytes      int64
}

func (s *Server) readPathConfigReferences(query *pathHealthOperation, target store.DeviceCounterInterface, result *pathInterfaceHealth) error {
	reader, ok := s.deviceOps.(device.ConfigArchiveReferenceReader)
	if !ok {
		return nil
	}
	source := target.Source
	binding := device.ConfigArchiveBinding{Kind: "operator_bound_archive", ContextID: source.ContextID, DeviceEntityID: source.DeviceID, AgentID: source.AgentID, SourceRef: source.SourceRef, SourceAssignedAt: source.SourceAssignedAt, AgentAssignedAt: source.AgentAssignedAt}
	refs, used, err := reader.ReadConfigArchiveReferences(query.op.request.Context(), query.op.actor.TenantID, binding, query.options.from, query.options.to, query.remaining/2)
	if errors.Is(err, device.ErrConfigReferenceBudget) {
		return apierror.TooLarge("complete path configuration references exceed resource admission")
	}
	if err != nil {
		return err
	}
	query.remaining -= used * 2
	query.configChecks = append(query.configChecks, pathConfigCheck{binding: binding, references: refs, bytes: max(used, 4096)})
	result.ConfigChanges = refs
	result.ConfigCoverage = "no_bound_archive_in_window"
	if len(refs) > 0 {
		result.ConfigCoverage = "operator_bound_archives"
	}
	return nil
}

func (s *Server) revalidatePathConfigReferences(query *pathHealthOperation) error {
	reader, ok := s.deviceOps.(device.ConfigArchiveReferenceReader)
	if !ok && len(query.configChecks) > 0 {
		return apierror.Unavailable("configuration archive reader changed during path read")
	}
	for _, check := range query.configChecks {
		current, _, err := reader.ReadConfigArchiveReferences(query.op.request.Context(), query.op.actor.TenantID, check.binding, query.options.from, query.options.to, check.bytes)
		if err != nil || !reflect.DeepEqual(current, check.references) {
			return apierror.Unavailable("original configuration references changed during path read; retry")
		}
	}
	return query.op.request.Context().Err()
}
