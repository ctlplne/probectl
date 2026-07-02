// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
