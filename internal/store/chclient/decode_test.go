// SPDX-License-Identifier: LicenseRef-probectl-TBD

package chclient

import "testing"

func TestDecodePreservesUInt64Precision(t *testing.T) {
	rows, err := Decode([]byte(`{"n":9007199254740993,"s":"9007199254740995"}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Uint64(rows[0]["n"]); got != 9007199254740993 {
		t.Fatalf("numeric UInt64 decoded as %d, want exact 9007199254740993", got)
	}
	if got := Uint64(rows[0]["s"]); got != 9007199254740995 {
		t.Fatalf("string UInt64 decoded as %d, want exact 9007199254740995", got)
	}
	if got := Float(rows[0]["n"]); got == 0 {
		t.Fatal("Float compatibility path returned zero for json.Number")
	}
}
