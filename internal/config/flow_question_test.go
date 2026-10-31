// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

func TestFlowQuestionResourceConfig(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FlowQuestionMaxBytes != 8<<20 || cfg.FlowQuestionMaxTokens != 1<<20 || cfg.FlowQuestionMaxNesting != 32 || cfg.FlowQuestionModelResponseBytes != 16<<20 || cfg.FlowQuestionModelOutputTokens != 16384 || cfg.FlowQuestionModelTokenParameter != "max_completion_tokens" {
		t.Fatal("native planning cost defaults changed")
	}
	for _, key := range []string{"PROBECTL_FLOW_QUESTION_MAX_BYTES", "PROBECTL_FLOW_QUESTION_MAX_TOKENS", "PROBECTL_FLOW_QUESTION_MAX_NESTING", "PROBECTL_FLOW_QUESTION_MODEL_MAX_RESPONSE_BYTES", "PROBECTL_FLOW_QUESTION_MODEL_MAX_OUTPUT_TOKENS"} {
		for _, value := range []string{"0", "-1", "9223372036854775807", "invalid"} {
			if _, err := Load(envFunc(map[string]string{key: value})); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("invalid/unbounded resource policy did not refuse startup", key)
			}
		}
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_FLOW_QUESTION_MODEL_OPENAI_TOKEN_PARAMETER": "arbitrary"})); err == nil {
		t.Fatal("unrecognized wire token selector accepted")
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_FLOW_QUESTION_MAX_BYTES": "33554432", "PROBECTL_FLOW_QUESTION_MODEL_MAX_OUTPUT_TOKENS": "262144", "PROBECTL_FLOW_QUESTION_MODEL_OPENAI_TOKEN_PARAMETER": "max_tokens"}))
	if err != nil || cfg.FlowQuestionMaxBytes != 32<<20 || cfg.FlowQuestionModelOutputTokens != 262144 || cfg.FlowQuestionModelTokenParameter != "max_tokens" {
		t.Fatal("valid operator policy not retained", err)
	}
}
