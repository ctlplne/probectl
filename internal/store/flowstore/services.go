// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

// ServiceAttributionBytes accounts for the additional server-derived strings
// retained on one flow. Original flow bytes remain under existing ingestion and
// query admission; attribution never becomes part of the stable dedup identity.
func ServiceAttributionBytes(row Row) int64 {
	return int64(len(row.SrcService) + len(row.SrcServiceRegion) + len(row.SrcServiceProvider) + len(row.SrcServiceStatus) +
		len(row.DstService) + len(row.DstServiceRegion) + len(row.DstServiceProvider) + len(row.DstServiceStatus) +
		len(row.ServiceClassifiedAt) + len(row.ServiceEvidence))
}
