// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agentlabel

import (
	"fmt"
	"testing"
)

func TestNormalize(t *testing.T) {
	labels := map[string]string{"site": "dub-1"}
	labels[" Region "] = " eu-west "
	got, err := Normalize(labels)
	if err != nil {
		t.Fatal(err)
	}
	if got["region"] != "eu-west" || got["site"] != "dub-1" {
		t.Fatalf("Normalize = %#v", got)
	}

	for _, labels := range []map[string]string{
		{"bad key": "x"},
		{"region": ""},
		{string(make([]byte, MaxKeyBytes+1)): "x"},
	} {
		if _, err := Normalize(labels); err == nil {
			t.Fatalf("Normalize(%#v) succeeded, want error", labels)
		}
	}

	tooMany := map[string]string{}
	for i := 0; i <= MaxLabels; i++ {
		tooMany[fmt.Sprintf("k%d", i)] = "v"
	}
	if _, err := Normalize(tooMany); err == nil {
		t.Fatal("Normalize accepted too many labels")
	}
}
