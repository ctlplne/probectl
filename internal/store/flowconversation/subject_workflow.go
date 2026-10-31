// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// SubjectErasureState discovers only source-free exact operation metadata under
// current privacy authority. The caller must then validate the immutable plan's
// original selector/application before resuming. A different purpose refuses.
func (j *Journal) SubjectErasureState(ctx context.Context, authorize AuthorizeMaintenance) (installed bool, operation string, err error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return false, "", err
	}
	installed, err = j.historyFamilyInstalled(ctx)
	if err != nil || !installed {
		return installed, "", err
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return true, "", err
	}
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		state, err := readConversationEpoch(ctx, sc, epochRead)
		if err != nil || !state.invalidating {
			return err
		}
		if state.kind == nil || *state.kind != string(MaintenanceSubjectErase) || state.operation == nil {
			return ErrJournalConflict
		}
		operation = *state.operation
		return nil
	})
	if err == nil {
		err = authorizeMaintenance(ctx, tenant, authorize)
	}
	if err != nil {
		return true, "", journalError(ctx, err)
	}
	return true, operation, nil
}

// PurgeSubjectHistory composes current-authorized pending source, complete
// typed classification and bounded physical deletion. It reloads durable
// counters after progress, never adds process-local batch counts. It leaves
// the marker/plan intact for the engine's separately proven all-plane work.
func (j *Journal) PurgeSubjectHistory(ctx context.Context, codec *Codec, pending Invalidation, source HistoryBudget, mutation CancellationBudget, authorize AuthorizeMaintenance, factory SubjectMatchFactory) (SubjectHistoryProgress, error) {
	if source.Rows <= 0 || source.Bytes <= 0 || mutation.Rows <= 0 || mutation.TimeLimit <= 0 {
		return SubjectHistoryProgress{}, ErrMessageBudget
	}
	if factory == nil {
		return SubjectHistoryProgress{}, ErrMessageDenied
	}
	progress, err := j.ReadSubjectProgress(ctx, pending, authorize)
	if err != nil || progress.SourceEmpty {
		return progress, err
	}
	for {
		batch, err := j.CancelInvalidated(ctx, pending, mutation, authorize)
		if err != nil {
			return SubjectHistoryProgress{}, err
		}
		if batch.ActiveRemaining == 0 {
			break
		}
		if batch.Canceled == 0 {
			return SubjectHistoryProgress{}, ErrJournalUnavailable
		}
	}
	for {
		retried, err := j.RetryDrainedOperations(ctx, ActivityBudget(mutation), authorize)
		if err != nil {
			return SubjectHistoryProgress{}, err
		}
		if retried.Pending == 0 {
			break
		}
		if retried.Acknowledged == 0 {
			return SubjectHistoryProgress{}, ErrJournalUnavailable
		}
	}
	for {
		selection, err := j.selectSubjectLeaves(ctx, codec, pending, source, authorize, factory)
		if err != nil {
			return SubjectHistoryProgress{}, err
		}
		if len(selection.leaves) == 0 {
			if err := j.recordSubjectSourceEmpty(ctx, selection, authorize); err != nil {
				return SubjectHistoryProgress{}, err
			}
			return j.ReadSubjectProgress(ctx, pending, authorize)
		}
		for index := range selection.leaves {
			for {
				batch, err := j.purgeSubjectLeaf(ctx, selection, index, mutation, authorize)
				if err != nil {
					return SubjectHistoryProgress{}, err
				}
				if batch.messagesDeleted > 0 {
					break
				}
			}
		}
	}
}
