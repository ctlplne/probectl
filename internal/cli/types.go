package cli

import (
	"time"

	"github.com/imfeelingtheagi/probectl/internal/version"
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
}

// list is the standard list envelope.
type list[T any] struct {
	Items []T `json:"items"`
}

func buildVersion() string { return version.Get().Version }
