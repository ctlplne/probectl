// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// A source ID selects only its existing exact provenance. During an explicitly
// reviewed update, the operator may bind an exact existing canonical prefix
// in the same context. A changed network always needs a different review row.
func validateProtectedPrefixDestination(ctx context.Context, sc tenancy.Scope, contextID, bound string, choice ReviewChoice, label, network string) error {
	target := choice.TargetEntityID
	if choice.Action == "create" {
		target = bound
	}
	if target == "" {
		return nil
	}
	currentLabel, currentNetwork, err := readProtectedPrefixDestination(ctx, sc, contextID, target)
	if err != nil {
		return err
	}
	if currentNetwork != network || choice.Action == "create" && currentLabel != label {
		return ErrInvalidReview
	}
	return nil
}

func readProtectedPrefixDestination(ctx context.Context, sc tenancy.Scope, contextID, target string) (label, network string, err error) {
	err = sc.Q.QueryRow(ctx, `SELECT label,coalesce(network_prefix::text,'') FROM entities
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind='prefix' FOR SHARE`,
		sc.Tenant.String(), contextID, target).Scan(&label, &network)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrInvalidReview
	}
	return label, network, err
}

func boundProtectedPrefixDestination(ctx context.Context, sc tenancy.Scope, contextID, sourceID, externalID string) (string, error) {
	var target string
	err := sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND object_kind='prefix' AND external_id=$4`,
		sc.Tenant.String(), contextID, sourceID, externalID).Scan(&target)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return target, err
}

// reviewProtectedPrefixDiff checks the same destination used by apply and
// returns an empty change list for an exact sourced re-import.
func reviewProtectedPrefixDiff(ctx context.Context, sc tenancy.Scope, contextID, sourceID string, row reviewDiffRow) (ReviewDiffItem, error) {
	item := row.item
	item.ProposedLabel, item.ProposedNetworkPrefix = row.label, row.address
	bound, err := boundProtectedPrefixDestination(ctx, sc, contextID, sourceID, item.ExternalID)
	if err != nil {
		return ReviewDiffItem{}, err
	}
	target := item.TargetID
	if item.Action == "create" {
		target = bound
	} else if bound != "" && bound != target {
		return ReviewDiffItem{}, ErrReviewStale
	}
	if target == "" {
		item.ChangedFields = []string{"label", "network_prefix"}
		return item, nil
	}
	item.CurrentLabel, item.CurrentNetworkPrefix, err = readProtectedPrefixDestination(ctx, sc, contextID, target)
	switch {
	case errors.Is(err, ErrInvalidReview):
		return ReviewDiffItem{}, ErrReviewStale
	case err != nil:
		return ReviewDiffItem{}, err
	case item.CurrentNetworkPrefix != item.ProposedNetworkPrefix:
		return ReviewDiffItem{}, ErrReviewStale
	case item.Action == "create":
		if item.CurrentLabel != item.ProposedLabel {
			return ReviewDiffItem{}, ErrReviewStale
		}
	default:
		current, err := fingerprintReviewTarget(ctx, sc, contextID, target, "prefix")
		if err != nil || current != row.fingerprint {
			if err != nil && !errors.Is(err, ErrInvalidReview) {
				return ReviewDiffItem{}, err
			}
			return ReviewDiffItem{}, ErrReviewStale
		}
		if item.CurrentLabel != item.ProposedLabel {
			item.ChangedFields = []string{"label"}
		}
	}
	return item, nil
}
