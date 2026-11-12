// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDependencyGraphSDKPreservesOptionalAndCompleteGraph(t *testing.T) {
	input := AlertDependencyPolicyInput{ContextId: "context"}
	raw, err := json.Marshal(input)
	if err != nil || strings.Contains(string(raw), `"graph"`) {
		t.Fatal("absent graph became an invalid empty object", string(raw), err)
	}
	input.Graph = &AlertDependencyGraphInput{Nodes: []AlertDependencyNodeInput{{AgentId: "agent", EntityId: "root", TestId: "root-test", Parents: []string{}}, {AgentId: "agent", EntityId: "child", TestId: "child-test", Parents: []string{"root"}}}}
	raw, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var got AlertDependencyPolicyInput
	if err := json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(input, got) {
		t.Fatal("SDK lost a source, root array or parent edge", string(raw), err)
	}
}
