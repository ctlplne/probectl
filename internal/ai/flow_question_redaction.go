// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"

	"github.com/ctlplne/probectl/internal/auth"
)

// The native planner must know both actual redaction passes before constructing
// private references. This is a private adapter seam, not a raw completion door.
type completionPromptRedactor interface {
	redactCompletionPrompt(context.Context, string) (string, error)
}

func (m *HTTPModel) redactCompletionPrompt(ctx context.Context, user string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if m.remote {
		return redactTextForTenant(user, m.redact, redactionTenantFromContext(ctx)), nil
	}
	return user, nil
}

func (m *ResilientModel) redactCompletionPrompt(ctx context.Context, user string) (string, error) {
	if !m.RemoteEgress() {
		return user, ctx.Err()
	}
	inner, ok := m.remote.(completionPromptRedactor)
	if !ok {
		return "", ErrFlowQuestionModelUnavailable
	}
	return inner.redactCompletionPrompt(ctx, user)
}

func (c *GatedCompleter) previewCompletionPrompt(ctx context.Context, user string) (string, error) {
	rm, ok := c.inner.(RemoteEgresser)
	if !ok {
		return "", ErrFlowQuestionModelUnavailable
	}
	if !rm.RemoteEgress() {
		return user, ctx.Err()
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil || p.TenantID == "" {
		return "", ErrNoTenant
	}
	inner, ok := c.inner.(completionPromptRedactor)
	if !ok {
		return "", ErrFlowQuestionModelUnavailable
	}
	return inner.redactCompletionPrompt(ctx, c.gate.RedactForTenant(user, p.TenantID))
}
