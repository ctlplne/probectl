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

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
)

func TestReplayDeadLetterRejectsBGPTopicWithoutProducer(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := runReplayDeadLetter(&config.Config{}, log, []string{"--topic", bus.DeadLetterBGPTopic})
	if err == nil {
		t.Fatalf("replay-deadletter accepted %q, but BGP has no DLQ producer", bus.DeadLetterBGPTopic)
	}
	if !strings.Contains(err.Error(), bus.DeadLetterBGPTopic) || !strings.Contains(err.Error(), "not a known dead-letter topic") {
		t.Fatalf("replay-deadletter error = %q, want fail-closed unknown-topic rejection", err)
	}
}
