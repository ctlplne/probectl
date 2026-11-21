// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"net/netip"
	"time"
)

type IRRRouteReceipt struct {
	Origin     uint32     `json:"origin_asn"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
	Review     string     `json:"review"`
}

type IRRPosture struct {
	Source       string            `json:"source"`
	Status       string            `json:"status"`
	ObservedAt   *time.Time        `json:"observed_at,omitempty"`
	ValidUntil   *time.Time        `json:"valid_until,omitempty"`
	SHA256       string            `json:"sha256,omitempty"`
	Terms        string            `json:"terms,omitempty"`
	RPKIFiltered bool              `json:"rpki_filtered"`
	Objects      []IRRRouteReceipt `json:"objects"`
}

func (s irrLocalSnapshot) posture(ctx context.Context, prefix netip.Prefix, origin *uint32, at time.Time,
	reviewAfter time.Duration, budget int64) (IRRPosture, error) {
	out := IRRPosture{Source: s.receipt.Source, Status: "unavailable", Objects: []IRRRouteReceipt{}}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !prefix.IsValid() || prefix != prefix.Masked() || at.IsZero() || reviewAfter <= 0 {
		return out, errIRRInput
	}
	if s.objects == nil {
		return out, nil
	}
	out.ObservedAt, out.ValidUntil = &s.receipt.GeneratedAt, &s.validUntil
	out.SHA256, out.Terms, out.RPKIFiltered = s.receipt.SHA256, s.receipt.Terms, s.receipt.RPKIFiltered
	if at.Before(s.receipt.GeneratedAt) || !at.Before(s.validUntil) {
		return out, nil
	}
	if origin == nil || *origin == 0 || *origin == 23456 {
		out.Status = "unknown_origin"
		return out, nil
	}
	objects := s.objects[prefix]
	if len(objects) == 0 {
		out.Status = "not_found"
		return out, nil
	}
	if budget < 4096 || int64(len(objects)) > (budget-4096)/256 {
		return out, errIRRBudget
	}
	out.Status = "origin_mismatch"
	out.Objects = make([]IRRRouteReceipt, 0, len(objects))
	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return IRRPosture{}, err
		}
		if object.Origin == *origin {
			out.Status = "match"
		}
		receipt := IRRRouteReceipt{Origin: object.Origin, Review: "clock_unavailable"}
		if !object.ModifiedAt.IsZero() {
			receipt.ModifiedAt, receipt.Review = &object.ModifiedAt, "current"
			if !at.Before(object.ModifiedAt.Add(reviewAfter)) {
				receipt.Review = "past_review_age"
			}
		}
		out.Objects = append(out.Objects, receipt)
	}
	return out, ctx.Err()
}
