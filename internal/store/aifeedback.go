package store

import (
	"context"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// AIFeedback persists answer feedback for the AI assistant (S24, F13). It is
// tenant-scoped by RLS: the tenant_isolation policy on ai_feedback confines every
// row to its tenant (F50), so a write can never land in — and a read can never
// see — another tenant's feedback.
type AIFeedback struct{}

// AIFeedbackInput is a validated feedback row to persist (the handler maps the
// request + principal onto it).
type AIFeedbackInput struct {
	AnswerID string
	Question string
	Rating   string
	Comment  string
	UserID   string
}

// Save inserts a feedback row within the caller's tenant scope.
func (AIFeedback) Save(ctx context.Context, s tenancy.Scope, in AIFeedbackInput) error {
	if _, err := s.Q.Exec(ctx,
		`INSERT INTO ai_feedback (tenant_id, answer_id, question, rating, comment, user_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		s.Tenant.String(), in.AnswerID, in.Question, in.Rating, in.Comment, in.UserID); err != nil {
		return mapWriteErr("ai_feedback", err)
	}
	return nil
}
