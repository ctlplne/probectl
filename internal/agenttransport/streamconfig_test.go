package agenttransport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
)

// deniedStream fails the test if the server ever SENDS on the config stream —
// the Sprint 13 deny must refuse before any frame.
type deniedStream struct {
	t *testing.T
	agentv1.AgentService_StreamConfigServer
}

func (d deniedStream) Send(*agentv1.StreamConfigResponse) error {
	d.t.Fatal("StreamConfig sent a frame — the deny must refuse BEFORE sending")
	return nil
}
func (deniedStream) Context() context.Context { return context.Background() }

// Sprint 13 (ARCH-003, within the U-044 ADR): the server answers StreamConfig
// with an IMMEDIATE explicit Unimplemented — no frame, no held-open stream.
func TestStreamConfigExplicitDeny(t *testing.T) {
	svc := &service{}
	err := svc.StreamConfig(&agentv1.StreamConfigRequest{}, deniedStream{t: t})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("want codes.Unimplemented, got %v", err)
	}
	if !strings.Contains(err.Error(), "docs/adr/config-push.md") {
		t.Fatalf("the deny must cite the ADR: %v", err)
	}
}

// Static assertion (Sprint 13 task 3b): no agent-side code path initiates
// StreamConfig — the agent binary contains no client invocation. Scans the
// agent runtime + binary sources (tests excluded; the generated client stub in
// internal/gen exists by design — the schema keeps the RPC).
func TestAgentHasNoStreamConfigInvocation(t *testing.T) {
	roots := []string{"../agent", "../../cmd/probectl-agent"}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(b), "StreamConfig") {
				t.Errorf("%s references StreamConfig — the agent must have NO client invocation (ARCH-003)", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
