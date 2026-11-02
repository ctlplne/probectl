// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"fmt"

	"github.com/ctlplne/probectl/internal/tags"
)

// An old silo may retain the initial byte-only CHECK after public advances.
// Replace it before accepting values through that physical tenant boundary.
func tagValueConstraintPlan(schema string) []string {
	plan := []string{}
	for _, table := range []string{"tenant_tag_assignments", "tenant_tag_rules"} {
		child := quoteIdent(schema) + "." + quoteIdent(table)
		name := table + "_value_v2_check"
		plan = append(plan,
			"ALTER TABLE "+child+" DROP CONSTRAINT IF EXISTS "+quoteIdent(table+"_value_check"),
			fmt.Sprintf(`DO $tag_value_silo$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
    ALTER TABLE %s ADD CONSTRAINT %s CHECK
        (char_length(value) BETWEEN 1 AND %d AND octet_length(value) <= %d
         AND value !~ '[[:cntrl:]]') NOT VALID;
END IF;
END;
$tag_value_silo$`, quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name),
				tags.MaxValueCharacters, tags.MaxValueBytes))
	}
	return plan
}
