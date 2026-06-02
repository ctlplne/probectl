package ai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Rating is a thumbs up/down on an answer — the answer-quality loop (S24).
type Rating string

const (
	RatingUp   Rating = "up"
	RatingDown Rating = "down"
)

func validRating(r Rating) bool { return r == RatingUp || r == RatingDown }

// Feedback is one user reaction to an RCA answer, tenant-owned. AnswerID ties it
// back to the answer the user saw; Comment is optional free text.
type Feedback struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	AnswerID  string    `json:"answer_id"`
	Question  string    `json:"question,omitempty"`
	Rating    Rating    `json:"rating"`
	Comment   string    `json:"comment,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ErrInvalidFeedback is returned when a feedback record is missing required
// fields or carries an unknown rating (fail closed on bad input).
var ErrInvalidFeedback = errors.New("ai: invalid feedback")

// Validate checks required fields and the rating enum.
func (f Feedback) Validate() error {
	if strings.TrimSpace(f.AnswerID) == "" || !validRating(f.Rating) {
		return ErrInvalidFeedback
	}
	if len(f.Comment) > 2000 {
		return ErrInvalidFeedback
	}
	return nil
}

// FeedbackStore persists answer feedback, tenant-scoped (the durable backing
// enforces RLS — F50). The control plane wires a Postgres-backed store; tests and
// dev use the in-memory one.
type FeedbackStore interface {
	Save(ctx context.Context, f Feedback) error
}

// MemoryFeedbackStore is an in-memory FeedbackStore for tests + dev. Records are
// partitioned by tenant so a reader can never see another tenant's notes.
type MemoryFeedbackStore struct {
	mu       sync.Mutex
	byTenant map[string][]Feedback
}

// NewMemoryFeedbackStore returns an empty in-memory feedback store.
func NewMemoryFeedbackStore() *MemoryFeedbackStore {
	return &MemoryFeedbackStore{byTenant: map[string][]Feedback{}}
}

// Save validates and stores a feedback record under its tenant.
func (m *MemoryFeedbackStore) Save(_ context.Context, f Feedback) error {
	if err := f.Validate(); err != nil {
		return err
	}
	if f.TenantID == "" {
		return ErrInvalidFeedback
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now()
	}
	m.byTenant[f.TenantID] = append(m.byTenant[f.TenantID], f)
	return nil
}

// ForTenant returns a copy of a tenant's feedback (test helper; never crosses
// tenants).
func (m *MemoryFeedbackStore) ForTenant(tenant string) []Feedback {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Feedback(nil), m.byTenant[tenant]...)
}
