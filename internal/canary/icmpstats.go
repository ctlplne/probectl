// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
