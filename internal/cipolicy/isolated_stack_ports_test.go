// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cipolicy

import (
	"regexp"
	"strings"
	"testing"
)

// TestTheDisposableStackDoesNotFightTheDevStackForPorts (DPR-094): the
// "isolated" integration runner isolated only the Compose project and network
// name, while dev.yml published fixed host ports — so the isolated upgrade
// rollback drill could not run on a machine with the documented dev stack up.
// It died on "Bind for 0.0.0.0:8123 failed: port is already allocated", which
// reads like a broken drill rather than a port clash.
func TestTheDisposableStackDoesNotFightTheDevStackForPorts(t *testing.T) {
	dev := readRepoFile(t, "deploy/compose/dev.yml")
	fixed := regexp.MustCompile(`(?m)^\s+- "(\d+):\d+"`)
	if m := fixed.FindAllStringSubmatch(dev, -1); len(m) > 0 {
		var ports []string
		for _, p := range m {
			ports = append(ports, p[1])
		}
		t.Errorf("dev.yml publishes fixed host ports %s: a disposable copy of the stack cannot run beside it", strings.Join(ports, ", "))
	}
	for _, want := range []string{
		`"${PROBECTL_DEV_POSTGRES_PORT:-5432}:5432"`,
		`"${PROBECTL_DEV_KAFKA_PORT:-9092}:9092"`,
		`"${PROBECTL_DEV_CLICKHOUSE_HTTP_PORT:-8123}:8123"`,
		`"${PROBECTL_DEV_PROMETHEUS_PORT:-9090}:9090"`,
		// A client that connects on the published port must not be redirected
		// to a port nobody is listening on.
		`PLAINTEXT://localhost:${PROBECTL_DEV_KAFKA_PORT:-9092}`,
	} {
		if !strings.Contains(dev, want) {
			t.Errorf("dev.yml must publish through a variable with the usual default: missing %q", want)
		}
	}

	runner := readRepoFile(t, "scripts/run_isolated_integration.sh")
	for _, want := range []string{
		"free_port()",
		"export PROBECTL_DEV_POSTGRES_PORT",
		"PROBECTL_DATABASE_URL:-postgres://probectl:probectl@localhost:${PROBECTL_DEV_POSTGRES_PORT}",
		"PROBECTL_TEST_KAFKA:-localhost:${PROBECTL_DEV_KAFKA_PORT}",
	} {
		if !strings.Contains(runner, want) {
			t.Errorf("the isolated runner must pick free ports and point the wrapped command at them: missing %q", want)
		}
	}
}
