// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
