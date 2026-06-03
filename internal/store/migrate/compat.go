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
)

// CheckSQL returns the expand/contract violations in one migration's SQL.
func CheckSQL(file, sql string) []Violation {
	var out []Violation
	for _, stmt := range splitStatements(stripComments(sql)) {
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
