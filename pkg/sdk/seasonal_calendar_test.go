// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"encoding/json"
	"testing"
)

func TestSeasonalCalendarRetainsMinuteZero(t *testing.T) {
	const input = `{"cadence":"hourly","timezone":"UTC","weekday":2,"hour":10,"minute":0,"training_days":["2026-11-17"],"training_periods":3}`
	var calendar AlertSeasonalCalendar
	if err := json.Unmarshal([]byte(input), &calendar); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(calendar)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Minute *int `json:"minute"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Minute == nil || *decoded.Minute != 0 {
		t.Fatal("the exact civil minute was lost during SDK re-encoding", err)
	}
}
