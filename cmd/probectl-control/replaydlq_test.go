// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
)

func TestReplayDeadLetterRejectsUnknownTopic(t *testing.T) {
	const unknownTopic = "probectl.deadletter.unwired"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := runReplayDeadLetter(&config.Config{}, log, []string{"--topic", unknownTopic})
	if err == nil {
		t.Fatalf("replay-deadletter accepted unknown topic %q", unknownTopic)
	}
	if !strings.Contains(err.Error(), unknownTopic) || !strings.Contains(err.Error(), "not a known dead-letter topic") {
		t.Fatalf("replay-deadletter error = %q, want fail-closed unknown-topic rejection", err)
	}
}
