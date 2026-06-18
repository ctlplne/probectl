// SPDX-License-Identifier: LicenseRef-probectl-TBD

package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// Backward-compatibility (expand/contract) checker for migrations (S34, F28).
//
// Zero-downtime upgrades require that release N's schema works with both release
// N's code and release N-1's code (so a rolling upgrade and a rollback are both
// safe). That means migrations must be ADDITIVE within a release: a destructive or
// rewriting change (drop a column, change a type, rename, add a NOT NULL column
// without a default) is split across releases — expand now, contract later, once
// no running code depends on the old shape.
//
// This checker enforces the rule statically so a destructive migration fails CI
// (the migration-gate) instead of breaking a production upgrade.

// Violation is one expand/contract rule broken by a migration.
type Violation struct {
	File      string // migration filename
	Rule      string // the rule that was broken
	Statement string // the offending statement (trimmed)
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s — %s", v.File, v.Rule, v.Statement)
}

// rule is a forbidden pattern with an explanation of the safe alternative.
type rule struct {
	name string
	re   *regexp.Regexp
}

// forbidden are the destructive/blocking patterns disallowed in a single release.
// Patterns run against an upper-cased, comment-stripped, whitespace-collapsed
// statement. Note the allowances they intentionally do NOT match: DROP POLICY
// (recreated in place for RLS), DROP INDEX, DROP NOT NULL / DROP DEFAULT
// (relaxing), and an ADD COLUMN that carries a DEFAULT.
var forbidden = []rule{
	{"drop table (destructive)", regexp.MustCompile(`\bDROP\s+TABLE\b`)},
	{"drop column (destructive — expand/contract across releases)", regexp.MustCompile(`\bDROP\s+COLUMN\b`)},
	{"alter column type (rewrites + locks — add a new column instead)", regexp.MustCompile(`\bALTER\s+COLUMN\s+\S+\s+(SET\s+DATA\s+)?TYPE\b`)},
	{"rename (breaks N-1 code — add the new name, backfill, drop later)", regexp.MustCompile(`\bRENAME\b`)},
	{"set not null (locks/fails — add a NOT VALID check + VALIDATE later)", regexp.MustCompile(`\bSET\s+NOT\s+NULL\b`)},
	{"truncate (destroys data)", regexp.MustCompile(`\bTRUNCATE\b`)},
}

var (
	lineComment  = regexp.MustCompile(`--[^\n]*`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	wsRun        = regexp.MustCompile(`\s+`)
	addColumn    = regexp.MustCompile(`\bADD\s+COLUMN\b`)
	notNull      = regexp.MustCompile(`\bNOT\s+NULL\b`)
	hasDefault   = regexp.MustCompile(`\bDEFAULT\b`)

	// Locking-DDL detection (SCHEMA-003). The gate is not just a destructive
	// gate — it also rejects DDL that takes a heavy lock under live ingestion
	// unless written in the online (non-locking) form.
	createIndex     = regexp.MustCompile(`\bCREATE\s+(UNIQUE\s+)?INDEX\b`)
	concurrently    = regexp.MustCompile(`\bCONCURRENTLY\b`)
	createTable     = regexp.MustCompile(`\bCREATE\s+TABLE\b`)
	addConstraint   = regexp.MustCompile(`\bADD\s+CONSTRAINT\b`)
	notValid        = regexp.MustCompile(`\bNOT\s+VALID\b`)
	validatingCheck = regexp.MustCompile(`\b(CHECK|FOREIGN\s+KEY)\b`)
	// createTableName captures the table a CREATE TABLE defines, and
	// indexOnTable / alterTable the table a CREATE INDEX / ALTER TABLE targets —
	// so the gate knows whether a locking statement hits a table created in the
	// SAME migration (zero rows, no concurrent ingestion ⇒ non-locking) or a
	// pre-existing one (the real hazard). Names are normalized upper-case.
	createTableName = regexp.MustCompile(`\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Z0-9_."]+)`)
	indexOnTable    = regexp.MustCompile(`\bON\s+([A-Z0-9_."]+)`)
	alterTableName  = regexp.MustCompile(`\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([A-Z0-9_."]+)`)
	// lockOK matches a per-statement reviewed exception: a comment
	// `-- lock-ok: <reason>` (or `lock-ok(<rule>): <reason>`) authorizes one
	// locking statement that has been confirmed safe (e.g. a brand-new or tiny
	// table). It must carry a reason; bare `-- lock-ok` is not honored.
	lockOK = regexp.MustCompile(`(?i)--\s*lock-ok(?:\([^)]*\))?\s*:\s*\S`)
)

// CheckSQL returns the expand/contract + locking violations in one migration's
// SQL. Locking checks read the RAW (comment-bearing) statement so a reviewed
// `-- lock-ok: <reason>` annotation can authorize a confirmed-safe exception.
func CheckSQL(file, sql string) []Violation {
	var out []Violation
	noTx := hasNoTxDirective(sql)
	// Split on the RAW SQL so each statement retains its leading/inline
	// comments; strip comments only for the body match.
	raws := splitStatements(sql)

	// First pass: tables CREATEd in THIS migration. A locking index/constraint
	// on a same-migration table is safe (no rows, no concurrent ingestion yet),
	// so it must not be flagged.
	fresh := map[string]bool{}
	for _, raw := range raws {
		norm := strings.ToUpper(wsRun.ReplaceAllString(strings.TrimSpace(stripComments(raw)), " "))
		if m := createTableName.FindStringSubmatch(norm); m != nil {
			fresh[normalizeTable(m[1])] = true
		}
	}

	for _, raw := range raws {
		stmt := stripComments(raw)
		norm := strings.ToUpper(wsRun.ReplaceAllString(strings.TrimSpace(stmt), " "))
		if norm == "" {
			continue
		}
		for _, r := range forbidden {
			if r.re.MatchString(norm) {
				out = append(out, Violation{File: file, Rule: r.name, Statement: trimStmt(stmt)})
			}
		}
		// An ADD COLUMN that is NOT NULL must carry a DEFAULT (else the table rewrite
		// fails on existing rows and breaks N-1 inserts).
		if addColumn.MatchString(norm) && notNull.MatchString(norm) && !hasDefault.MatchString(norm) {
			out = append(out, Violation{
				File: file, Rule: "add column NOT NULL without DEFAULT (add nullable or give a DEFAULT)",
				Statement: trimStmt(stmt),
			})
		}
		if createIndex.MatchString(norm) && concurrently.MatchString(norm) && !noTx {
			out = append(out, Violation{
				File:      file,
				Rule:      "CREATE INDEX CONCURRENTLY requires a leading `-- probectl:no-tx: <reason>` directive because PostgreSQL forbids it inside the migration transaction",
				Statement: trimStmt(stmt),
			})
		}
		out = append(out, lockViolations(file, raw, norm, fresh)...)
	}
	return out
}

// normalizeTable strips a schema qualifier and quotes so "public.\"Foo\"" and
// "foo" compare equal for the same-migration freshness check.
func normalizeTable(t string) string {
	t = strings.ReplaceAll(t, `"`, "")
	if i := strings.LastIndex(t, "."); i >= 0 {
		t = t[i+1:]
	}
	return t
}

// lockViolations reports locking-DDL violations for one statement. A statement
// targeting a table CREATEd in the SAME migration (in fresh) is safe; a reviewed
// `-- lock-ok: <reason>` annotation also waives it.
func lockViolations(file, raw, norm string, fresh map[string]bool) []Violation {
	var out []Violation
	// A DO $$ ... $$ block is procedural idempotency/RLS plumbing — its dynamic
	// EXECUTE'd SQL is reviewed and cannot run CONCURRENTLY inside the block
	// anyway. Lock detection targets top-level DDL, so skip DO blocks.
	if strings.HasPrefix(norm, "DO ") {
		return out
	}
	add := func(rule, target string) {
		if target != "" && fresh[normalizeTable(target)] {
			return // index/constraint on a same-migration (empty) table — safe
		}
		if lockOK.MatchString(raw) {
			return // explicit, reasoned exception (e.g. a confirmed-tiny table)
		}
		out = append(out, Violation{File: file, Rule: rule, Statement: trimStmt(raw)})
	}
	// A non-CONCURRENTLY CREATE INDEX takes a SHARE lock that stalls writes on a
	// hot, pre-existing table for the whole build.
	if createIndex.MatchString(norm) && !concurrently.MatchString(norm) {
		target := ""
		if m := indexOnTable.FindStringSubmatch(norm); m != nil {
			target = m[1]
		}
		add("create index without CONCURRENTLY on a pre-existing table (locks it under ingestion — use CREATE INDEX CONCURRENTLY, or `-- lock-ok: <reason>` for a confirmed-tiny table)", target)
	}
	// A validating ADD CONSTRAINT (CHECK / FOREIGN KEY) without NOT VALID scans
	// + locks the existing table. An inline constraint in CREATE TABLE is fine
	// (nothing to scan), so only ADD CONSTRAINT outside a CREATE TABLE counts.
	if addConstraint.MatchString(norm) && validatingCheck.MatchString(norm) &&
		!notValid.MatchString(norm) && !createTable.MatchString(norm) {
		target := ""
		if m := alterTableName.FindStringSubmatch(norm); m != nil {
			target = m[1]
		}
		add("add validating constraint without NOT VALID on a pre-existing table (scans+locks it — ADD CONSTRAINT ... NOT VALID then VALIDATE in a later release, or `-- lock-ok: <reason>`)", target)
	}
	return out
}

// CheckFS checks every *.sql migration in fsys and returns all violations, sorted
// by filename. It is the migration-gate's core (run over migrations.FS).
func CheckFS(fsys fs.FS) ([]Violation, error) {
	var files []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sql") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []Violation
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		out = append(out, CheckSQL(f, string(b))...)
	}
	return out, nil
}

// stripComments removes -- line and /* */ block comments.
func stripComments(sql string) string {
	sql = blockComment.ReplaceAllString(sql, " ")
	return lineComment.ReplaceAllString(sql, "")
}

// splitStatements splits SQL on top-level ';', respecting single-quoted strings and
// PostgreSQL dollar-quoted bodies ($$...$$, $tag$...$tag$) so a ';' inside a DO
// block or a function body doesn't split a statement.
func splitStatements(sql string) []string {
	var stmts []string
	var b strings.Builder
	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '-':
			// a -- line comment runs to end-of-line; a ';' inside it must not
			// split (and the comment text — e.g. a `-- lock-ok:` annotation —
			// stays attached to its statement).
			if i+1 < len(runes) && runes[i+1] == '-' {
				for i < len(runes) && runes[i] != '\n' {
					b.WriteRune(runes[i])
					i++
				}
				if i < len(runes) {
					b.WriteRune(runes[i]) // the newline
				}
				continue
			}
			b.WriteRune(c)
		case '/':
			// a /* ... */ block comment: skip to the closing */ verbatim.
			if i+1 < len(runes) && runes[i+1] == '*' {
				b.WriteRune(runes[i])
				i++
				for i < len(runes) {
					b.WriteRune(runes[i])
					if runes[i] == '/' && runes[i-1] == '*' {
						break
					}
					i++
				}
				continue
			}
			b.WriteRune(c)
		case '\'':
			// consume to the closing quote (doubled '' is an escaped quote)
			b.WriteRune(c)
			for i++; i < len(runes); i++ {
				b.WriteRune(runes[i])
				if runes[i] == '\'' {
					if i+1 < len(runes) && runes[i+1] == '\'' {
						i++
						b.WriteRune(runes[i])
						continue
					}
					break
				}
			}
		case '$':
			if tag, ok := dollarTag(runes, i); ok {
				// consume through the matching closing tag
				b.WriteString(tag)
				i += len([]rune(tag))
				for i < len(runes) {
					if strings.HasPrefix(string(runes[i:]), tag) {
						b.WriteString(tag)
						i += len([]rune(tag)) - 1
						break
					}
					b.WriteRune(runes[i])
					i++
				}
			} else {
				b.WriteRune(c)
			}
		case ';':
			stmts = append(stmts, b.String())
			b.Reset()
		default:
			b.WriteRune(c)
		}
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		stmts = append(stmts, b.String())
	}
	return stmts
}

// dollarTag returns the dollar-quote tag starting at runes[i] (e.g. "$$" or
// "$pol$"), if runes[i] opens one.
func dollarTag(runes []rune, i int) (string, bool) {
	if runes[i] != '$' {
		return "", false
	}
	for j := i + 1; j < len(runes); j++ {
		if runes[j] == '$' {
			return string(runes[i : j+1]), true
		}
		// tag chars are letters/digits/underscore
		if !isTagChar(runes[j]) {
			return "", false
		}
	}
	return "", false
}

func isTagChar(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func trimStmt(s string) string {
	s = strings.TrimSpace(wsRun.ReplaceAllString(s, " "))
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}
