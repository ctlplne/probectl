// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"time"

	"github.com/ctlplne/probectl/internal/version"
)

// Test mirrors the /v1/tests resource.
type Test struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params"`
	Enabled         bool              `json:"enabled"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// testRequest is the create/update body.
type testRequest struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params,omitempty"`
	Enabled         bool              `json:"enabled"`
}

// Agent mirrors the /v1/agents resource.
type Agent struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Hostname     string     `json:"hostname"`
	AgentVersion string     `json:"agent_version"`
	Status       string     `json:"status"`
	Capabilities []string   `json:"capabilities"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	// DPR-176: the credential the agent runs on. An agent keeps working on the
	// identity it holds and then stops for good, so an operator reading a fleet
	// from a terminal needs the lifetime next to the status, not only in the UI.
	IdentityState     string     `json:"identity_state,omitempty"`
	IdentityExpiresAt *time.Time `json:"identity_expires_at,omitempty"`
	IdentityReason    string     `json:"identity_reason,omitempty"`
}

// list is the standard list envelope.
type list[T any] struct {
	Items []T `json:"items"`
}

func buildInfo() version.Info { return version.Get() }

func buildVersion() string { return buildInfo().Version }
