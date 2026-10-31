// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"fmt"
	"strings"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// resolveSubjectDirectory retains typed identity, separate from credential
// locators. Neither a resolved UUID nor its aliases grant privacy authority.
func (e *Engine) resolveSubjectDirectory(ctx context.Context, sc tenancy.Scope, subject string) (subjectAliasSet, []subjectIdentity, error) {
	aliases := newSubjectAliasSet(subject)
	normalizedSubject := strings.ToLower(strings.TrimSpace(subject))
	var identities []subjectIdentity
	matches := 0

	exists, err := e.subjectTableExists(ctx, sc, "users")
	if err != nil {
		return aliases, nil, fmt.Errorf("discover users table: %w", err)
	}
	if !exists {
		return aliases, nil, fmt.Errorf("tenantlife: users table is missing from tenant schema")
	}
	rows, err := sc.Q.Query(ctx, `
		SELECT id::text, email, COALESCE(user_name, ''), COALESCE(external_id, '')
		  FROM users
		 WHERE lower(id::text) = $1
		    OR lower(email) = $1
		    OR lower(COALESCE(user_name, '')) = $1
		    OR lower(COALESCE(external_id, '')) = $1`,
		normalizedSubject)
	if err != nil {
		return aliases, nil, fmt.Errorf("capture user subject aliases: %w", err)
	}
	for rows.Next() {
		var id, email, userName, externalID string
		if err := rows.Scan(&id, &email, &userName, &externalID); err != nil {
			rows.Close()
			return aliases, nil, err
		}
		matches++
		if matches == 1 {
			identities = append(identities, subjectIdentity{kind: "user", id: id, email: email, userName: userName, externalID: externalID})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return aliases, nil, err
	}
	rows.Close()

	exists, err = e.subjectTableExists(ctx, sc, "service_accounts")
	if err != nil {
		return aliases, nil, fmt.Errorf("discover service_accounts table: %w", err)
	}
	if !exists {
		return aliases, nil, fmt.Errorf("tenantlife: service_accounts table is missing from tenant schema")
	}
	rows, err = sc.Q.Query(ctx, `
		SELECT id::text, name
		  FROM service_accounts
		 WHERE lower(id::text) = $1 OR lower(name) = $1`,
		normalizedSubject)
	if err != nil {
		return aliases, nil, fmt.Errorf("capture service-account subject aliases: %w", err)
	}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return aliases, nil, err
		}
		matches++
		if matches == 1 {
			identities = append(identities, subjectIdentity{kind: "service_account", id: id, name: name})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return aliases, nil, err
	}
	rows.Close()

	if matches > 1 {
		return aliases, nil, fmt.Errorf(
			"tenantlife: subject identifier is ambiguous across %d directory identities; use an exact UUID",
			matches,
		)
	}
	if len(identities) == 0 && !isSafeContainsIdentifier(subject) {
		return aliases, nil, fmt.Errorf(
			"tenantlife: subject does not resolve to one exact identity and is not an unambiguous email, UUID, IP address, or URI",
		)
	}
	if len(identities) == 1 {
		identity := identities[0]
		aliases.add(identity.id)
		if identity.kind == "user" {
			aliases.add(identity.email)
			aliases.add(identity.userName)
			aliases.add(identity.externalID)
		} else {
			aliases.add(identity.name)
		}
	}

	return aliases, identities, nil
}
