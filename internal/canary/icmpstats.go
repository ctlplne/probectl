// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package canary

import (
	"strconv"
	"strings"
	"time"
)

// dropRecord builds the continuous-mode drop-timing record: the comma-separated
// sequence numbers that were lost and each one's send offset (ms from the start
// of the probe). Both are empty when nothing was dropped.
func dropRecord(rtts []time.Duration, sendOffsets []time.Duration) (seqs, offsetsMs string) {
	var sb, ob strings.Builder
	for i, d := range rtts {
		if d >= 0 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(',')
			ob.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(i))
		ob.WriteString(strconv.FormatInt(sendOffsets[i].Milliseconds(), 10))
	}
	return sb.String(), ob.String()
}
