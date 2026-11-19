// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"time"
)

type PrefixImpactInput struct {
	RuleID             string `json:"rule_id"`
	ReceiptFingerprint string `json:"receipt_fingerprint"`
	ContextID          string `json:"context_id"`
	ProtectedEntityID  string `json:"protected_entity_id"`
	BenignEntityID     string `json:"benign_entity_id"`
	WholeViewID        string `json:"whole_view_id"`
	WholeViewVersion   string `json:"whole_view_version"`
}

type PrefixTraffic struct {
	Bytes   string `json:"bytes"`
	Packets string `json:"packets"`
}

// PrefixImpact records the scoped observations used to size a proposed change.
type PrefixImpact struct {
	Prefix            string        `json:"prefix"`
	From              time.Time     `json:"from"`
	To                time.Time     `json:"to"`
	Sampled           bool          `json:"sampled"`
	ObservedRecords   int           `json:"observed_records"`
	ObservedAddresses int           `json:"observed_addresses"`
	Matched           PrefixTraffic `json:"matched"`
	KnownBenign       PrefixTraffic `json:"known_benign"`
	Unclassified      PrefixTraffic `json:"unclassified"`
}

type RTBHPreviewInput struct {
	PrefixImpactInput
	Community           string `json:"community"`
	RoutingPolicyAgreed bool   `json:"routing_policy_agreed"`
}

type RTBHAnnouncement struct {
	Family    string `json:"family"`
	Prefix    string `json:"prefix"`
	Community string `json:"community"`
}

type RTBHPreview struct {
	Announcement RTBHAnnouncement `json:"announcement"`
	Impact       PrefixImpact     `json:"impact"`
	Fingerprint  string           `json:"preview_fingerprint,omitempty"`
}

type PrefixImpactSource interface {
	ObservePrefixImpact(context.Context, string, PrefixImpactInput, func(context.Context) error) (PrefixImpact, error)
}

type RTBHPreviewer interface {
	PreviewRTBH(context.Context, string, RTBHPreviewInput, func(context.Context) error) (RTBHPreview, error)
}
