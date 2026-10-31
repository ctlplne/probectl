// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
)

var (
	ErrModelCompletionBudget     = errors.New("model completion exceeds or has invalid operator resource policy")
	ErrModelCompletionIncomplete = errors.New("model did not return a complete text response")
	ErrModelCompletionRefused    = errors.New("model provider declined this completion")
)

// CompletionBudget is operator-owned cost policy, never prompt/model input.
// Provider-specific maxima must be configured for the selected model; these
// defaults do not claim a model's capacity or limit native query grammar.
type CompletionBudget struct {
	ResponseBytes        int64
	OutputTokens         int
	OpenAITokenParameter string
}

func DefaultCompletionBudget() CompletionBudget {
	return CompletionBudget{ResponseBytes: 16 << 20, OutputTokens: 16384, OpenAITokenParameter: "max_completion_tokens"}
}

func (b CompletionBudget) Validate() error {
	if b.ResponseBytes < 1 || b.ResponseBytes > int64(^uint(0)>>1)-1 || b.OutputTokens < 1 || b.OutputTokens > int(^uint(0)>>1)-1 {
		return ErrModelCompletionBudget
	}
	if b.OpenAITokenParameter != "max_completion_tokens" && b.OpenAITokenParameter != "max_tokens" {
		return ErrModelCompletionBudget
	}
	return nil
}

type BudgetedRemoteCompleter interface {
	RemoteCompleter
	CompleteWithBudget(context.Context, string, string, CompletionBudget) (string, error)
}

func truncatedCompletion() error {
	return errors.Join(ErrModelCompletionBudget, ErrModelCompletionIncomplete)
}

func refusedCompletion() error {
	return errors.Join(ErrModelCompletionRefused, ErrModelCompletionIncomplete)
}
