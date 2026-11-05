// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"io"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Export the same explicit fields used for erasure and verification. Evidence
// addresses compare as typed members; opaque report chunks match their owner
// through the tenant-composite parent. Stream one row at a time.
func (e *Engine) exportClassifiedSubjectRows(ctx context.Context, tenant, table string, policy subjectTablePolicy,
	aliases subjectAliasSet, w io.Writer) (int64, error) {
	var count int64
	err := tenancy.InTenant(ctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT row_to_json(subject_row) FROM `+pgIdent(table)+` subject_row
		 WHERE subject_row.tenant_id=$1 AND `+subjectTableMatchPredicate(policy), subjectTableMatchArgs(tenant, aliases, policy)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			raw = append(raw, '\n')
			n, err := w.Write(raw)
			if err != nil {
				return err
			}
			if n != len(raw) {
				return io.ErrShortWrite
			}
			count++
		}
		return rows.Err()
	})
	return count, err
}
