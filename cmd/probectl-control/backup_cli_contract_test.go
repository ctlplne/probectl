// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// OPS-001 / RESIL-001 / OPS-003: the shipped restore Job and the documented PITR
// recipes invoke `probectl-control backup-seal` / `backup-open` as STDIN→STDOUT
// filters. backup.go defines ONLY -key-file/-key-id (flag.ContinueOnError), so a
// recipe that passes --in/--out is a hard break: the binary errors with "flag
// provided but not defined". These guards read the literal artifacts an operator
// runs and fail the build if any recipe drifts back to a flag the CLI lacks —
// the original defect that hid because no test exercised the encrypted path.

// repoRoot walks up from the test's CWD to the module root (the dir with go.mod).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate repo root (go.mod)")
	return ""
}

func readArtifact(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// backupBadFlags are the flags backup.go does NOT define. Their appearance next
// to a backup-seal/backup-open invocation is the OPS-001/003 defect.
var backupBadFlags = []string{"--in ", "--in=", "--out ", "--out=", "--in %p", "--out %p", "--in -", "--out -"}

// stripComments drops shell/YAML/markdown comment lines (a leading '#', possibly
// indented) so that an explanatory note like "it has NO --in/--out flags" does
// not trip the guard — only EXECUTED command lines are checked.
func stripComments(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func assertNoBadBackupFlags(t *testing.T, name, body string) {
	t.Helper()
	if !strings.Contains(body, "backup-seal") && !strings.Contains(body, "backup-open") {
		t.Fatalf("%s: expected a backup-seal/backup-open invocation to guard, found none (did the file move?)", name)
	}
	executable := stripComments(body)
	for _, bad := range backupBadFlags {
		if strings.Contains(executable, bad) {
			t.Errorf("%s: contains %q — backup.go defines NO such flag; it reads stdin/stdout. "+
				"Use shell redirection (< in, > out) and the KEK env/-key-file instead.", name, bad)
		}
	}
}

func TestRestoreJobInvokesBackupOpenAsRealCLI(t *testing.T) {
	body := readArtifact(t, "deploy/helm/probectl/templates/restore-job.yaml")
	assertNoBadBackupFlags(t, "restore-job.yaml", body)

	// The control-plane image installs the binary at /usr/local/bin/app
	// (deploy/docker/Dockerfile), NOT /usr/bin/probectl-control.
	if strings.Contains(body, "/usr/bin/probectl-control") {
		t.Error("restore-job.yaml stages /usr/bin/probectl-control, but the image only ships /usr/local/bin/app")
	}
	if !strings.Contains(body, "/usr/local/bin/app") {
		t.Error("restore-job.yaml must copy the binary from /usr/local/bin/app (the real Dockerfile path)")
	}
	// backup-open must read the sealed file on stdin (shell redirection), after
	// the backup path has been verified from the backups PVC.
	if !strings.Contains(body, "backup-open") || !strings.Contains(body, "backup=\"/backups/${backup_file}\"") || !strings.Contains(body, "backup-open < \"${backup}\"") {
		t.Error("restore-job.yaml must feed the verified sealed backup into backup-open via stdin redirection")
	}
}

func TestRestoreJobVerifiesChecksumBeforeMutatingPostgres(t *testing.T) {
	body := readArtifact(t, "deploy/helm/probectl/templates/restore-job.yaml")
	stripped := stripComments(body)

	idxChecksum := strings.Index(stripped, "sha256sum -c")
	idxOpen := strings.Index(stripped, "backup-open")
	idxRestore := strings.Index(stripped, "pg_restore")
	idxMigrate := strings.Index(stripped, "migrate")
	for name, idx := range map[string]int{
		"sha256sum -c": idxChecksum,
		"backup-open":  idxOpen,
		"pg_restore":   idxRestore,
		"migrate":      idxMigrate,
	} {
		if idx < 0 {
			t.Fatalf("restore-job.yaml missing %s in executable restore path", name)
		}
	}
	if idxChecksum >= idxOpen || idxOpen >= idxRestore || idxRestore >= idxMigrate {
		t.Fatalf("restore order must be checksum -> backup-open -> pg_restore -> migrate; indexes checksum=%d open=%d restore=%d migrate=%d",
			idxChecksum, idxOpen, idxRestore, idxMigrate)
	}
	for _, want := range []string{
		"test -s \"${sha}\"",
		"test -s \"${work}\"",
		"restore-work",
		"emptyDir: {}",
	} {
		if !strings.Contains(stripped, want) {
			t.Fatalf("restore-job.yaml missing %q — corrupt .pbk/.sha256 must fail before database mutation", want)
		}
	}
	if strings.Contains(stripped, "| pg_restore") {
		t.Fatal("restore-job.yaml must not pipe backup-open directly into pg_restore without pipefail")
	}
}

func TestRestoreJobCorruptChecksumStopsBeforePostgresMutation(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skipf("sha256sum not available for restore-job corrupt-checksum drill: %v", err)
	}

	tmp := t.TempDir()
	backups := filepath.Join(tmp, "backups")
	shared := filepath.Join(tmp, "shared")
	workdir := filepath.Join(tmp, "restore-work")
	bin := filepath.Join(tmp, "bin")
	for _, dir := range []string{backups, shared, workdir, bin} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	backupFile := "postgres-probectl-corrupt.dump.pbk"
	if err := os.WriteFile(filepath.Join(backups, backupFile), []byte("sealed backup bytes"), 0o600); err != nil {
		t.Fatalf("write corrupt pbk: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backups, backupFile+".sha256"), []byte(strings.Repeat("0", 64)+"  "+backupFile+"\n"), 0o600); err != nil {
		t.Fatalf("write corrupt checksum: %v", err)
	}

	openMarker := filepath.Join(tmp, "backup-open-called")
	mutationMarker := filepath.Join(tmp, "pg-restore-called")
	fakeControl := "#!/bin/sh\nprintf 'backup-open reached\\n' > \"$PROBECTL_TEST_OPEN_MARKER\"\ncat\n"
	if err := os.WriteFile(filepath.Join(shared, "probectl-control"), []byte(fakeControl), 0o755); err != nil {
		t.Fatalf("write fake probectl-control: %v", err)
	}
	fakeRestore := "#!/bin/sh\nprintf 'pg_restore reached\\n' > \"$PROBECTL_TEST_MUTATION_MARKER\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte(fakeRestore), 0o755); err != nil {
		t.Fatalf("write fake pg_restore: %v", err)
	}

	script := `
set -euo pipefail
backup_file="${BACKUP_FILE}"
backup="${BACKUPS}/${backup_file}"
sha="${backup}.sha256"
work="${WORKDIR}/postgres.dump"
trap 'rm -f "${work}"' EXIT
test -s "${backup}"
test -s "${sha}"
(cd "${BACKUPS}" && sha256sum -c "${backup_file}.sha256" >/dev/null)
"${SHARED}/probectl-control" backup-open < "${backup}" > "${work}"
test -s "${work}"
pg_restore --clean --if-exists --no-owner -h "postgres" -U "$PGUSER" -d "probectl" "${work}"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"BACKUP_FILE="+backupFile,
		"BACKUPS="+backups,
		"WORKDIR="+workdir,
		"SHARED="+shared,
		"PGUSER=probectl",
		"PROBECTL_TEST_OPEN_MARKER="+openMarker,
		"PROBECTL_TEST_MUTATION_MARKER="+mutationMarker,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("corrupt checksum restore drill unexpectedly succeeded:\n%s", out)
	}
	for _, marker := range []struct {
		path string
		name string
	}{
		{openMarker, "backup-open"},
		{mutationMarker, "pg_restore"},
	} {
		if _, statErr := os.Stat(marker.path); !os.IsNotExist(statErr) {
			t.Fatalf("corrupt checksum reached %s before failing; marker err=%v output:\n%s", marker.name, statErr, out)
		}
	}
}

func TestPITRRecipesUseRealCLI(t *testing.T) {
	body := readArtifact(t, "docs/ops/backup-restore.md")
	assertNoBadBackupFlags(t, "docs/ops/backup-restore.md", body)
	stripped := stripComments(body)
	for _, want := range []struct{ substr, why string }{
		{".dump.pbk.sha256", "operators must verify the sealed backup checksum before backup-open"},
		{"sha256sum postgres-probectl-<ts>.dump > postgres-probectl-<ts>.dump.sha256", "the decrypted temporary dump must get its own checksum sidecar before restore_postgres.sh"},
		{"Checksum sidecars are required restore inputs", "the runbook must not describe checksum verification as optional"},
	} {
		if !strings.Contains(stripped, want.substr) {
			t.Errorf("docs/ops/backup-restore.md: missing %q — %s", want.substr, want.why)
		}
	}
}

func TestRestorePostgresRequiresChecksumBeforeMutation(t *testing.T) {
	body := readArtifact(t, "scripts/restore_postgres.sh")
	stripped := stripComments(body)

	idxMissing := strings.Index(stripped, "missing checksum sidecar")
	idxChecksum := strings.Index(stripped, "sha256sum -c")
	idxDrop := strings.Index(stripped, "DROP DATABASE")
	idxRestore := strings.Index(stripped, "pg_restore")
	for name, idx := range map[string]int{
		"missing checksum sidecar": idxMissing,
		"sha256sum -c":             idxChecksum,
		"DROP DATABASE":            idxDrop,
		"pg_restore":               idxRestore,
	} {
		if idx < 0 {
			t.Fatalf("restore_postgres.sh missing %s in executable restore path", name)
		}
	}
	if idxMissing >= idxChecksum || idxChecksum >= idxDrop || idxDrop >= idxRestore {
		t.Fatalf("restore_postgres.sh order must be require sidecar -> verify checksum -> drop -> pg_restore; indexes missing=%d checksum=%d drop=%d restore=%d",
			idxMissing, idxChecksum, idxDrop, idxRestore)
	}
	if strings.Contains(stripped, "if [ -f \"${DUMP}.sha256\" ]") {
		t.Fatal("restore_postgres.sh must require the checksum sidecar, not treat it as optional")
	}
}

// OPS-005 / RESIL-003: the CI backup-drill must exercise the SEALED .pbk path
// end-to-end — the path the shipped restore Job actually carries — not the
// plaintext pg_dump. The Postgres backup script now seals at write time, so the
// drill must set an envelope KEK, receive a .dump.pbk from backup_postgres.sh,
// verify no plaintext dump was left behind, then restore through backup-open.
func TestBackupDrillExercisesSealedPBKPath(t *testing.T) {
	drill := readArtifact(t, "scripts/backup_restore_drill.sh")
	assertNoBadBackupFlags(t, "scripts/backup_restore_drill.sh", drill)

	stripped := stripComments(drill)
	for _, want := range []struct{ substr, why string }{
		{"PROBECTL_ENVELOPE_KEY", "the drill must set an envelope KEK so the sealed path is real"},
		{"PROBECTL_CONTROL_BIN", "the drill must pass the sealing binary to backup_postgres.sh"},
		{"backup_postgres.sh", "the drill must exercise the shipped Postgres backup entrypoint"},
		{".pbk", "the drill must produce/round-trip a .pbk artifact, not just a plaintext .dump"},
		{"left a plaintext .dump", "the drill must fail if backup_postgres.sh writes the raw tenant dump"},
		{"backup-open", "the drill must restore by DECRYPTING the .pbk via backup-open"},
		{"sha256sum -c \"$(basename \"${PBK}\").sha256\"", "the drill must verify the sealed .pbk sidecar before backup-open"},
		{"sha256sum \"$(basename \"${DECRYPTED}\")\" > \"$(basename \"${DECRYPTED}\").sha256\"", "the drill must create the decrypted dump sidecar before destructive restore"},
		{"tenant_id", "the ClickHouse regional-loss proof must query restored telemetry by tenant"},
		{"clickhouse regional-loss drill: PASS", "the drill must print an explicit telemetry DR receipt"},
		{"default shipped telemetry RPO <= 24h", "the drill receipt must name the numeric shipped telemetry RPO"},
	} {
		if !strings.Contains(stripped, want.substr) {
			t.Errorf("backup_restore_drill.sh: missing %q — %s (OPS-005)", want.substr, want.why)
		}
	}
	// backup-open must read the .pbk on stdin (the real CLI contract).
	if !strings.Contains(stripped, "backup-open") || !strings.Contains(stripped, "< \"${PBK}\"") {
		t.Error("backup_restore_drill.sh: backup-open must read the sealed .pbk on stdin (OPS-005)")
	}
}

// RESIL-003: standalone backup examples used to write the tenant Postgres dump
// directly to disk, then rely on later docs/drills to seal a copy. That leaves a
// raw multi-tenant database artifact on the backups volume. Pin the literal
// shipped artifacts to the safe shape: sealed .dump.pbk by default, and the old
// plaintext .dump path only behind an exact break-glass acknowledgement.
func TestStandalonePostgresBackupsAreSealedOrBreakGlass(t *testing.T) {
	for _, rel := range []string{
		"scripts/backup_postgres.sh",
		"deploy/backup/compose-backup.yml",
		"deploy/backup/k8s-cronjob-postgres.yaml",
	} {
		body := readArtifact(t, rel)
		assertNoBadBackupFlags(t, rel, body)
		stripped := stripComments(body)
		for _, want := range []struct{ substr, why string }{
			{"backup-seal", "the default Postgres backup path must stream through the envelope sealer"},
			{".dump.pbk", "the default Postgres backup artifact must be sealed, not plaintext"},
			{"PROBECTL_PLAINTEXT_BACKUP_ACK", "plaintext must require an explicit break-glass acknowledgement"},
			{"allow-plaintext-tenant-backup", "the acknowledgement value must be exact and searchable"},
		} {
			if !strings.Contains(stripped, want.substr) {
				t.Errorf("%s: missing %q — %s (RESIL-003)", rel, want.substr, want.why)
			}
		}
	}
}

// TestBackupFlagSetIsStdinStdoutOnly pins the CLI contract the recipes depend on:
// backup-seal/open accept only -key-file/-key-id and otherwise read stdin/write
// stdout. If someone ADDS --in/--out to backup.go in future, this stays green —
// but the guards above would then need updating, which is the intended coupling.
func TestBackupFlagSetIsStdinStdoutOnly(t *testing.T) {
	src := readArtifact(t, "cmd/probectl-control/backup.go")
	for _, want := range []string{`fs.String("key-file"`, `fs.String("key-id"`} {
		if !strings.Contains(src, want) {
			t.Errorf("backup.go: expected flag definition %q (CLI contract changed?)", want)
		}
	}
	for _, forbidden := range []string{`fs.String("in"`, `fs.String("out"`} {
		if strings.Contains(src, forbidden) {
			t.Errorf("backup.go: defines %q — update the restore Job / PITR recipe guards to match", forbidden)
		}
	}
}
