package ai

import (
	"context"
	"strings"
	"testing"
)

func TestFeedbackValidate(t *testing.T) {
	if err := (Feedback{AnswerID: "ans_1", Rating: RatingUp}).Validate(); err != nil {
		t.Errorf("valid feedback rejected: %v", err)
	}
	bad := []Feedback{
		{Rating: RatingUp},                  // no answer id
		{AnswerID: "a", Rating: "sideways"}, // bad rating
		{AnswerID: "a", Rating: RatingDown, Comment: strings.Repeat("x", 2001)}, // too long
	}
	for i, f := range bad {
		if err := f.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestMemoryFeedbackStoreTenantScoped(t *testing.T) {
	s := NewMemoryFeedbackStore()
	if err := s.Save(context.Background(), Feedback{TenantID: "a", AnswerID: "x", Rating: RatingUp}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(context.Background(), Feedback{TenantID: "b", AnswerID: "y", Rating: RatingDown, Comment: "wrong"}); err != nil {
		t.Fatal(err)
	}
	if got := s.ForTenant("a"); len(got) != 1 || got[0].AnswerID != "x" {
		t.Errorf("tenant a feedback = %+v", got)
	}
	if got := s.ForTenant("b"); len(got) != 1 || got[0].Comment != "wrong" {
		t.Errorf("tenant b feedback = %+v", got)
	}
	if err := s.Save(context.Background(), Feedback{AnswerID: "z", Rating: RatingUp}); err == nil {
		t.Error("tenantless feedback should fail closed")
	}
	if err := s.Save(context.Background(), Feedback{TenantID: "a", Rating: RatingUp}); err == nil {
		t.Error("feedback without an answer id should fail")
	}
}
