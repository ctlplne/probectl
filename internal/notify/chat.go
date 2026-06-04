package notify

import (
	"context"
	"fmt"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// chat posts incident notifications to a Slack or Teams incoming webhook. The
// endpoint URL is the credential; there is no external object to reference, so
// idempotency is provided by the dispatcher's link row (one post per incident).
type chat struct {
	name     string // "slack" | "teams"
	endpoint string
	client   Doer
}

func newChat(name, endpoint string, client Doer) *chat {
	return &chat{name: name, endpoint: endpoint, client: clientOr(client)}
}

func (c *chat) Name() string           { return c.name }
func (c *chat) Capability() Capability { return CapabilityChat }

func (c *chat) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	text := fmt.Sprintf("🔴 probectl incident opened — %s (severity %s, target %s)",
		inc.Title, inc.Severity, displayTarget(inc))
	if err := c.post(ctx, text); err != nil {
		return Delivery{}, err
	}
	return Delivery{ExternalRef: inc.ID, Status: "open"}, nil
}

func (c *chat) Resolve(ctx context.Context, inc incident.Incident, _ string) error {
	return c.post(ctx, fmt.Sprintf("✅ probectl incident resolved — %s", inc.Title))
}

func (c *chat) post(ctx context.Context, text string) error {
	// Both Slack and Teams incoming webhooks accept a {"text": ...} card.
	_, err := doJSON(ctx, c.client, "POST", c.endpoint, nil, map[string]any{"text": text})
	return err
}

func displayTarget(inc incident.Incident) string {
	if inc.Target != "" {
		return inc.Target
	}
	if inc.Prefix != "" {
		return inc.Prefix
	}
	return "-"
}
