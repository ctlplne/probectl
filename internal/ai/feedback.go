// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"errors"
	"strings"
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
