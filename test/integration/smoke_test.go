// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

// Package integration holds probectl's black-box integration tests. They exercise
// the running services over their public interfaces against the real dev stack
// (Postgres + Kafka + ClickHouse + Prometheus) defined in deploy/compose/dev.yml,
// rather than importing internal packages.
//
// S0 scaffold: a single placeholder so the harness and the `make test-integration`
// target exist. Real integration tests arrive with the result pipeline (S6+).
package integration

import "testing"

func TestDevStackHarnessPlaceholder(t *testing.T) {
	t.Log("integration harness placeholder — real integration tests land in S6+")
}
