// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestFlowSpecTemplateReachesPinnedFRRAndWithdraws(t *testing.T) {
	for _, tool := range []string{"docker", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			testsupport.SkipOrFatal(t, "the isolated FlowSpec receiver proof requires %s", tool)
		}
	}
	const image = "quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2"
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "docker", "image", "inspect", image).CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the pinned local FRRouting fixture is unavailable: %v %s", err, output)
	}
	port := uint16(18443)
	review := rem.FlowSpecReview{
		Fingerprint: strings.Repeat("c", 64),
		Proposal: rem.FlowSpecPreview{Candidate: rem.FlowSpecCandidate{
			Family: "ipv4", Destination: "192.0.2.0/24", Action: "discard",
			Transport: rem.FlowSpecTransport{Protocol: "tcp", DestinationPort: &port},
		}},
	}
	qualification, err := qualifyFlowSpec(review, rem.FlowSpecQualificationInput{
		Profile: rem.FlowSpecFRR1071, RoutingTable: "default",
	})
	if err != nil || !qualification.SyntaxCompatible || qualification.Template == nil {
		t.Fatalf("the owned rule did not qualify: %+v %v", qualification, err)
	}
	t.Run("operator withdrawal", func(t *testing.T) {
		runFlowSpecReceiver(ctx, t, qualification.Template, nil)
	})
	t.Run("authorized expiry", func(t *testing.T) {
		at := time.Now().UTC()
		review.ExpiresAt = at.Add(time.Minute)
		available := uint32(1)
		input := rem.FlowSpecQualificationInput{Profile: rem.FlowSpecFRR1071, RoutingTable: "default", AvailableEntries: &available}
		qualified, err := qualifyFlowSpec(review, input)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := digestFlowSpecQualification(qualified)
		if err != nil {
			t.Fatal(err)
		}
		const id = "00000000-0000-4000-8000-000000000001"
		encoded, err := prepareFlowSpecHandoff(id, review, &rem.FlowSpecHandoffInput{
			Qualification: input, QualificationFingerprint: fingerprint, DurationSeconds: 30,
		}, at)
		if err != nil {
			t.Fatal(err)
		}
		handoff, err := decodeFlowSpecHandoff(id, encoded)
		if err != nil || handoff.State(at) != rem.FlowSpecAuthorized {
			t.Fatalf("the fixture lacks its exact authorized handoff: %+v %v", handoff, err)
		}
		runFlowSpecReceiver(ctx, t, handoff.Qualification.Template, &handoff.ExpiresAt)
		if handoff.State(time.Now()) != rem.FlowSpecExpired {
			t.Fatal("the recorded handoff remained authorized after removal")
		}
	})
}

func runFlowSpecReceiver(ctx context.Context, t *testing.T, route *rem.FlowSpecRuleTemplate, expires *time.Time) {
	t.Helper()
	template, err := json.Marshal(struct {
		Template  *rem.FlowSpecRuleTemplate `json:"template"`
		ExpiresAt *time.Time                `json:"expires_at,omitempty"`
	}{route, expires})
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join("..", "..", "test", "flowspec", "receiver.py")
	command := exec.CommandContext(ctx, "python3", script)
	command.Stdin = bytes.NewReader(template)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 10 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the pinned receiver did not complete the exact rule proof: %v\n%s", err, output)
	}
	t.Logf("isolated FRRouting RIB receipt:\n%s", output)
}
