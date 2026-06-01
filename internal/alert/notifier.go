package alert

import (
	"context"
	"fmt"
	"log/slog"
)

// ChannelDeps are the shared dependencies a rule's channels are built from (an
// HTTP client for webhooks, a mail sender for email). They are configured once.
type ChannelDeps struct {
	HTTPClient Doer
	Mail       MailSender
}

// Notifier fans an alert out to every channel on a rule. A channel that fails to
// build or deliver is logged and skipped — one bad channel never blocks the
// others (graceful degradation).
type Notifier struct {
	deps ChannelDeps
	log  *slog.Logger
}

// NewNotifier builds a Notifier.
func NewNotifier(deps ChannelDeps, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{deps: deps, log: log}
}

// Deliver sends a to each of rule's channels. It returns the number of
// successful deliveries.
func (n *Notifier) Deliver(ctx context.Context, rule Rule, a Alert) int {
	delivered := 0
	for i, spec := range rule.Channels {
		ch, err := n.build(spec)
		if err != nil {
			n.log.Warn("alert channel unavailable; skipping",
				"rule", rule.Name, "channel_index", i, "type", spec.Type, "error", err)
			continue
		}
		if err := ch.Notify(ctx, a); err != nil {
			n.log.Warn("alert delivery failed; skipping",
				"rule", rule.Name, "type", ch.Type(), "error", err)
			continue
		}
		delivered++
	}
	return delivered
}

func (n *Notifier) build(spec ChannelSpec) (Channel, error) {
	switch spec.Type {
	case "webhook":
		return NewWebhookChannel(spec.URL, spec.Secret, n.deps.HTTPClient), nil
	case "email":
		if n.deps.Mail == nil {
			return nil, fmt.Errorf("email channel requested but no mail sender is configured")
		}
		return NewEmailChannel(spec.Recipients, n.deps.Mail), nil
	default:
		return nil, fmt.Errorf("unknown channel type %q", spec.Type)
	}
}
