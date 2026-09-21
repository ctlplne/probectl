#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Non-runtime companion for governed artifact/methodology/legal/release reviews.
# It deliberately does not start Compose or populate executable receipt fields.

set -Eeuo pipefail
IFS=$'\n\t'

PHASE="${1:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../../.." && pwd -P)"
AUDIT_AUTHORITY_REL="docs/quality/delivery-audit-review-protocols.json"

log() { printf '[completeness-review] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

safe_id() {
  [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "$1 is not a safe bounded identifier"
}

safe_relative_path() {
  local value="$1"
  [[ -n "$value" && "$value" != /* && "$value" != *'\\'* && "$value" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  case "/$value/" in *'/../'*|*'//'* ) return 1 ;; esac
  [[ "$value" != "." && "$value" != ".." ]]
}

mode_of() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"
}

resolve_repo_file() {
  local supplied="$1" absolute
  [[ -f "$supplied" && ! -L "$supplied" ]] || die "review spec must be a regular non-symlink file: $supplied"
  absolute="$(CDPATH= cd -- "$(dirname -- "$supplied")" && pwd -P)/$(basename -- "$supplied")"
  [[ "$absolute" == "${REPO_ROOT}/"* ]] || die "review spec must be beneath the repository root"
  printf '%s' "${absolute#${REPO_ROOT}/}"
}

review_paths() {
  STATE_DIR="${PROBECTL_AUDIT_REVIEW_STATE_DIR:?set PROBECTL_AUDIT_REVIEW_STATE_DIR}"
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || die "review state must be a real directory"
  STATE_DIR="$(CDPATH= cd -- "$STATE_DIR" && pwd -P)"
  PRIVATE_DIR="${STATE_DIR}/private"
  ARTIFACT_DIR="${STATE_DIR}/artifacts"
  BIN_DIR="${STATE_DIR}/bin"
  STATE_FILE="${STATE_DIR}/review-state.json"
}

load_review_state() {
  review_paths
  [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" && "$(mode_of "$STATE_FILE")" == "600" ]] || die "review state JSON must be a mode-0600 regular file"
  jq -e '
    (keys|sort)==(["attestation_path","attestation_sha256","authority_anchor","authority_path","capability_id","git_sha","item","kind","methodology_path","review_id","schema","source_archive","source_archive_sha256","source_dir","spec_sha256","spec_source_path","started_at","state_dir","tree_sha"]|sort) and
    .schema=="probectl.completeness-audit-review-state/v1" and
    (.git_sha|test("^[0-9a-f]{40}$")) and (.tree_sha|test("^[0-9a-f]{40}$")) and
    (.source_archive_sha256|test("^sha256:[0-9a-f]{64}$")) and (.spec_sha256|test("^sha256:[0-9a-f]{64}$")) and (.attestation_sha256|test("^sha256:[0-9a-f]{64}$"))
  ' "$STATE_FILE" >/dev/null || die "review state JSON is malformed"
  REVIEW_GIT_SHA="$(jq -er .git_sha "$STATE_FILE")"
  REVIEW_TREE_SHA="$(jq -er .tree_sha "$STATE_FILE")"
  REVIEW_SOURCE_ARCHIVE="$(jq -er .source_archive "$STATE_FILE")"
  REVIEW_SOURCE_ARCHIVE_SHA256="$(jq -er .source_archive_sha256 "$STATE_FILE")"
  REVIEW_SOURCE_DIR="$(jq -er .source_dir "$STATE_FILE")"
  REVIEW_SPEC_SOURCE_PATH="$(jq -er .spec_source_path "$STATE_FILE")"
  REVIEW_SPEC_SHA256="$(jq -er .spec_sha256 "$STATE_FILE")"
  REVIEW_ATTESTATION_PATH="$(jq -er .attestation_path "$STATE_FILE")"
  REVIEW_ATTESTATION_SHA256="$(jq -er .attestation_sha256 "$STATE_FILE")"
  REVIEW_ITEM="$(jq -er .item "$STATE_FILE")"
  REVIEW_CAPABILITY_ID="$(jq -er .capability_id "$STATE_FILE")"
  REVIEW_ID="$(jq -er .review_id "$STATE_FILE")"
  REVIEW_KIND="$(jq -er .kind "$STATE_FILE")"
  REVIEW_METHODOLOGY_PATH="$(jq -er .methodology_path "$STATE_FILE")"
  REVIEW_AUTHORITY_PATH="$(jq -er .authority_path "$STATE_FILE")"
  REVIEW_AUTHORITY_ANCHOR="$(jq -er .authority_anchor "$STATE_FILE")"
  REVIEW_STARTED_AT="$(jq -er .started_at "$STATE_FILE")"
  [[ "$(jq -er .state_dir "$STATE_FILE")" == "$STATE_DIR" ]] || die "review state directory identity changed"
  [[ "$REVIEW_SOURCE_ARCHIVE" == "${PRIVATE_DIR}/source-${REVIEW_GIT_SHA}.tar" && -f "$REVIEW_SOURCE_ARCHIVE" && ! -L "$REVIEW_SOURCE_ARCHIVE" ]] || die "frozen review source archive is invalid"
  [[ "$REVIEW_SOURCE_DIR" == "${PRIVATE_DIR}/source-${REVIEW_GIT_SHA}" && -d "$REVIEW_SOURCE_DIR" && ! -L "$REVIEW_SOURCE_DIR" ]] || die "frozen review source tree is invalid"
  [[ "$REVIEW_ATTESTATION_PATH" == "${PRIVATE_DIR}/review-attestation.json" && -f "$REVIEW_ATTESTATION_PATH" && ! -L "$REVIEW_ATTESTATION_PATH" ]] || die "frozen review attestation is invalid"
  safe_id item "$REVIEW_ITEM"
  safe_id capability_id "$REVIEW_CAPABILITY_ID"
  safe_id review_id "$REVIEW_ID"
  safe_relative_path "$REVIEW_SPEC_SOURCE_PATH" || die "review spec source path is unsafe"
  safe_relative_path "$REVIEW_METHODOLOGY_PATH" || die "review methodology path is unsafe"
  safe_relative_path "$REVIEW_AUTHORITY_PATH" || die "review authority path is unsafe"
  [[ "$REVIEW_AUTHORITY_ANCHOR" != *$'\n'* && "$REVIEW_AUTHORITY_ANCHOR" != *$'\r'* ]] || die "review authority anchor contains a control character"
  [[ "sha256:$(sha256_file "$REVIEW_SOURCE_ARCHIVE")" == "$REVIEW_SOURCE_ARCHIVE_SHA256" ]] || die "frozen review source archive changed"
  [[ "sha256:$(sha256_file "${REVIEW_SOURCE_DIR}/${REVIEW_SPEC_SOURCE_PATH}")" == "$REVIEW_SPEC_SHA256" ]] || die "frozen review spec changed"
  [[ "sha256:$(sha256_file "$REVIEW_ATTESTATION_PATH")" == "$REVIEW_ATTESTATION_SHA256" ]] || die "frozen review attestation changed"
}

assert_exact_review_source() {
  [[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$REVIEW_GIT_SHA" ]] || die "live checkout HEAD changed after review prepare"
  [[ "$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" == "$REVIEW_TREE_SHA" ]] || die "live checkout tree changed after review prepare"
  [[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]] || die "live checkout is dirty"
  local fresh_archive fresh_source
  fresh_archive="$(mktemp "${PRIVATE_DIR}/review-source-check.XXXXXX.tar")"
  fresh_source="$(mktemp -d "${PRIVATE_DIR}/review-source-check.XXXXXX")"
  git -C "$REPO_ROOT" archive --format=tar "$REVIEW_GIT_SHA" >"$fresh_archive"
  [[ "sha256:$(sha256_file "$fresh_archive")" == "$REVIEW_SOURCE_ARCHIVE_SHA256" ]] || die "fresh Git archive does not match the prepared review source"
  tar -xf "$fresh_archive" -C "$fresh_source"
  diff -qr "$fresh_source" "$REVIEW_SOURCE_DIR" >/dev/null || die "prepared review source tree changed"
  rm -f "$fresh_archive"
  [[ "$fresh_source" == "${PRIVATE_DIR}/review-source-check."* ]] || die "refusing unsafe review-source cleanup"
  rm -rf -- "$fresh_source"
}

validate_review_inputs() {
  local spec="$1" attestation="$2" path
  jq -e '
    . as $spec |
    (keys|sort)==(["capability_id","item","kind","methodology_path","required_checks","review_id","schema","subjects","summary"]|sort) and
    .schema=="probectl.completeness-audit-review-spec/v1" and
    (.item|test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and (.capability_id|test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
    (.review_id|test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and (.kind|IN("artifact","methodology","legal","release")) and
    (.methodology_path|type)=="string" and (.subjects|type)=="array" and (.subjects|length)>0 and (.subjects|length)<=64 and
    all(.subjects[]; type=="string") and ([.subjects[]]|unique|length)==(.subjects|length) and
    (.required_checks|type)=="array" and (.required_checks|length)>0 and (.required_checks|length)<=128 and
    all(.required_checks[]; test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and ([.required_checks[]]|unique|length)==(.required_checks|length) and
    (.summary|type)=="string" and (.summary|length)>0 and (.summary|length)<=1000 and
    (.subjects|index($spec.methodology_path))!=null
  ' "$spec" >/dev/null || die "review spec does not satisfy probectl.completeness-audit-review-spec/v1"
  jq -e --slurpfile spec "$spec" '
    (keys|sort)==(["checks","conclusion","review_id","schema"]|sort) and
    .schema=="probectl.completeness-audit-review-attestation/v1" and .review_id==$spec[0].review_id and .conclusion=="passed" and
    (.checks|type)=="array" and (.checks|length)==($spec[0].required_checks|length) and
    all(.checks[]; (keys|sort)==(["detail","id","outcome"]|sort) and (.id|type)=="string" and .outcome=="passed" and (.detail|type)=="string" and (.detail|length)>0 and (.detail|length)<=2000) and
    ([.checks[].id]|sort)==($spec[0].required_checks|sort) and ([.checks[].id]|unique|length)==(.checks|length)
  ' "$attestation" >/dev/null || die "review attestation does not exactly satisfy the tracked required checks"
  while IFS= read -r path; do
    safe_relative_path "$path" || die "review source path is unsafe: $path"
    [[ -f "${REVIEW_SOURCE_DIR}/${path}" && ! -L "${REVIEW_SOURCE_DIR}/${path}" ]] || die "review source path is not a regular archived file: $path"
  done < <(jq -r '[.methodology_path] + .subjects | unique[]' "$spec")
}

load_review_authority() {
  local spec="$1" authority="${REVIEW_SOURCE_DIR}/${AUDIT_AUTHORITY_REL}"
  [[ -f "$authority" && ! -L "$authority" ]] || die "exact-tree delivery-audit authority registry is missing"
  jq -e --slurpfile spec "$spec" '
    def within($path; $roots): any($roots[]; . as $root | ($path|startswith($root)));
    .schema=="probectl.delivery-audit-authority/v1" and
    ([.review_protocols[] | select(.item==$spec[0].item and .capability_id==$spec[0].capability_id)]|length)==1 and
    ([.review_protocols[] | select(.item==$spec[0].item and .capability_id==$spec[0].capability_id)][0]) as $protocol |
    ($protocol.kinds|index($spec[0].kind))!=null and
    within($spec[0].methodology_path; $protocol.methodology_roots) and
    all($spec[0].subjects[]; within(.; $protocol.subject_roots))
  ' "$authority" >/dev/null || die "review spec is outside its exact-tree item/capability authority protocol"
  REVIEW_AUTHORITY_PATH="$AUDIT_AUTHORITY_REL"
  REVIEW_AUTHORITY_ANCHOR="$(jq -er .item "$spec")"
}

prepare_review() {
  need git; need go; need jq
  [[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]] || die "governed review requires a clean exact-SHA checkout"
  local git_sha tree_sha timestamp spec_live spec_rel attestation_live subject_ndjson path blob_sha
  git_sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  tree_sha="$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  STATE_DIR="${PROBECTL_AUDIT_REVIEW_STATE_DIR:-${REPO_ROOT}/../evidence/completeness/governed-review/${git_sha:0:12}-${timestamp}}"
  [[ ! -e "$STATE_DIR" ]] || die "refusing to reuse governed-review state"
  mkdir -p "$STATE_DIR" "$STATE_DIR/private" "$STATE_DIR/artifacts" "$STATE_DIR/bin"
  chmod 0700 "$STATE_DIR" "$STATE_DIR/private" "$STATE_DIR/bin"
  chmod 0755 "$STATE_DIR/artifacts"
  STATE_DIR="$(CDPATH= cd -- "$STATE_DIR" && pwd -P)"
  export PROBECTL_AUDIT_REVIEW_STATE_DIR="$STATE_DIR"
  PRIVATE_DIR="${STATE_DIR}/private"; ARTIFACT_DIR="${STATE_DIR}/artifacts"; BIN_DIR="${STATE_DIR}/bin"; STATE_FILE="${STATE_DIR}/review-state.json"
  spec_live="${PROBECTL_AUDIT_REVIEW_SPEC:?set a tracked governed-review spec path}"
  spec_rel="$(resolve_repo_file "$spec_live")"
  git -C "$REPO_ROOT" ls-files --error-unmatch "$spec_rel" >/dev/null 2>&1 || die "review spec is not tracked at the audited SHA"
  attestation_live="${PROBECTL_AUDIT_REVIEW_ATTESTATION:?set the completed independent review attestation JSON}"
  [[ -f "$attestation_live" && ! -L "$attestation_live" ]] || die "review attestation must be a regular non-symlink file"
  [[ "$(wc -c <"$attestation_live" | tr -d ' ')" -le 262144 ]] || die "review attestation exceeds 256 KiB"

  REVIEW_SOURCE_ARCHIVE="${PRIVATE_DIR}/source-${git_sha}.tar"
  REVIEW_SOURCE_DIR="${PRIVATE_DIR}/source-${git_sha}"
  mkdir "$REVIEW_SOURCE_DIR"
  git -C "$REPO_ROOT" archive --format=tar "$git_sha" >"$REVIEW_SOURCE_ARCHIVE"
  chmod 0400 "$REVIEW_SOURCE_ARCHIVE"
  tar -xf "$REVIEW_SOURCE_ARCHIVE" -C "$REVIEW_SOURCE_DIR"
  REVIEW_ATTESTATION_PATH="${PRIVATE_DIR}/review-attestation.json"
  install -m 0400 "$attestation_live" "$REVIEW_ATTESTATION_PATH"
  validate_review_inputs "${REVIEW_SOURCE_DIR}/${spec_rel}" "$REVIEW_ATTESTATION_PATH"
  load_review_authority "${REVIEW_SOURCE_DIR}/${spec_rel}"

  subject_ndjson="${PRIVATE_DIR}/subjects.ndjson"
  : >"$subject_ndjson"
  while IFS= read -r path; do
    blob_sha="$(git -C "$REPO_ROOT" rev-parse --verify "${git_sha}:${path}")"
    [[ "$blob_sha" =~ ^[0-9a-f]{40}$ ]] || die "review subject is not a Git blob at the audited SHA: $path"
    jq -nc --arg path "$path" --arg sha "sha256:$(sha256_file "${REVIEW_SOURCE_DIR}/${path}")" --arg blob "$blob_sha" \
      '{path:$path,sha256:$sha,git_blob_sha:$blob}' >>"$subject_ndjson"
  done < <(
    {
      jq -r '[.methodology_path] + .subjects | unique[]' "${REVIEW_SOURCE_DIR}/${spec_rel}"
      printf '%s\n' "$REVIEW_AUTHORITY_PATH"
    } | LC_ALL=C sort -u
  )
  jq -n --arg git_sha "$git_sha" --arg tree_sha "$tree_sha" \
    --slurpfile spec "${REVIEW_SOURCE_DIR}/${spec_rel}" --slurpfile attestation "$REVIEW_ATTESTATION_PATH" --slurpfile subjects "$subject_ndjson" \
    --arg authority_path "$REVIEW_AUTHORITY_PATH" --arg authority_anchor "$REVIEW_AUTHORITY_ANCHOR" \
    '{schema:"probectl.delivery-audit-governed-review/v1",source_git_sha:$git_sha,source_tree_sha:$tree_sha,item:$spec[0].item,capability_id:$spec[0].capability_id,review_id:$spec[0].review_id,kind:$spec[0].kind,authority_path:$authority_path,authority_anchor:$authority_anchor,methodology_path:$spec[0].methodology_path,subjects:$subjects,checks:$attestation[0].checks,conclusion:$attestation[0].conclusion}' \
    >"${ARTIFACT_DIR}/governed-review.json"
  install -m 0644 "${REVIEW_SOURCE_DIR}/${spec_rel}" "${ARTIFACT_DIR}/review-spec.json"
  install -m 0644 "$REVIEW_ATTESTATION_PATH" "${ARTIFACT_DIR}/review-attestation.json"

  (cd "$REVIEW_SOURCE_DIR" && CGO_ENABLED=0 go build -trimpath -o "${BIN_DIR}/probectl-delivery-audit" ./cmd/probectl-delivery-audit)
  chmod 0500 "${BIN_DIR}/probectl-delivery-audit"
  jq -n \
    --arg state_dir "$STATE_DIR" --arg git_sha "$git_sha" --arg tree_sha "$tree_sha" \
    --arg source_archive "$REVIEW_SOURCE_ARCHIVE" --arg archive_sha "sha256:$(sha256_file "$REVIEW_SOURCE_ARCHIVE")" --arg source_dir "$REVIEW_SOURCE_DIR" \
    --arg spec_path "$spec_rel" --arg spec_sha "sha256:$(sha256_file "${REVIEW_SOURCE_DIR}/${spec_rel}")" \
    --arg attestation_path "$REVIEW_ATTESTATION_PATH" --arg attestation_sha "sha256:$(sha256_file "$REVIEW_ATTESTATION_PATH")" \
    --arg started "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --slurpfile spec "${REVIEW_SOURCE_DIR}/${spec_rel}" \
    --arg authority_path "$REVIEW_AUTHORITY_PATH" --arg authority_anchor "$REVIEW_AUTHORITY_ANCHOR" \
    '{schema:"probectl.completeness-audit-review-state/v1",state_dir:$state_dir,git_sha:$git_sha,tree_sha:$tree_sha,source_archive:$source_archive,source_archive_sha256:$archive_sha,source_dir:$source_dir,spec_source_path:$spec_path,spec_sha256:$spec_sha,attestation_path:$attestation_path,attestation_sha256:$attestation_sha,item:$spec[0].item,capability_id:$spec[0].capability_id,review_id:$spec[0].review_id,kind:$spec[0].kind,authority_path:$authority_path,authority_anchor:$authority_anchor,methodology_path:$spec[0].methodology_path,started_at:$started}' \
    >"$STATE_FILE"
  chmod 0600 "$STATE_FILE"
  log "prepared governed review state: $STATE_DIR"
  printf '%s\n' "$STATE_DIR"
}

review_declarations() {
  local output="$1" ndjson="${PRIVATE_DIR}/review-artifacts.ndjson" file name kind
  find "$ARTIFACT_DIR" -type l -print -quit | grep -q . && die "review artifacts contain a symlink"
  : >"$ndjson"
  while IFS= read -r file; do
    name="${file#${ARTIFACT_DIR}/}"
    [[ "$name" != "$file" && "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "review artifact path is not controlled"
    case "$name" in
      governed-review.json) kind=governed_review ;;
      linter-output.json) kind=linter_output ;;
      negative-receipt.json) kind=negative_receipt ;;
      planted-control.json) kind=negative_fixture ;;
      *) kind=other ;;
    esac
    jq -nc --arg path "$name" --arg kind "$kind" '{path:$path,kind:$kind,bytes:0,sha256:""}' >>"$ndjson"
  done < <(find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 -type f -print | LC_ALL=C sort)
  jq -s . "$ndjson" >"$output"
}

review_draft() {
  local declarations="$1" output="$2" auditor owner completed receipt_id
  auditor="${PROBECTL_AUDIT_AUDITOR:?set an explicit independent auditor identity before seal}"
  owner="${PROBECTL_AUDIT_IMPLEMENTATION_OWNER:?set the explicit implementation-owner identity before seal}"
  safe_id auditor "$auditor"; safe_id implementation_owner "$owner"
  [[ "$auditor" != "$owner" ]] || die "auditor and implementation owner must differ"
  completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  receipt_id="${REVIEW_ITEM}-${REVIEW_CAPABILITY_ID}-${REVIEW_ID}-${REVIEW_GIT_SHA:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
  jq -n --arg receipt_id "$receipt_id" --arg item "$REVIEW_ITEM" --arg capability "$REVIEW_CAPABILITY_ID" \
    --arg started "$REVIEW_STARTED_AT" --arg completed "$completed" --arg auditor "$auditor" --arg owner "$owner" \
    --slurpfile spec "${REVIEW_SOURCE_DIR}/${REVIEW_SPEC_SOURCE_PATH}" --slurpfile review "${ARTIFACT_DIR}/governed-review.json" --slurpfile artifacts "$declarations" '
    {schema:"probectl.delivery-audit-receipt/v1",receipt_id:$receipt_id,item:$item,capability_id:$capability,status:"VERIFIED",started_at:$started,completed_at:$completed,
     source:{git_sha:$review[0].source_git_sha,tree_sha:$review[0].source_tree_sha,dirty:false},build:{},
     auditor:{agent:$auditor,implementation_owner:$owner,independent_from_implementation:true},
     harness_scope:{mode:"governed_review",browser_auth_mode:"not_applicable",cli_auth_mode:"not_applicable",provider_compatibility_validated:false,capability_driver:{kind:"not_applicable",runtime_path:""},browser_driver:{kind:"not_applicable",runtime_path:""}},
     human_path:{id:$review[0].review_id,path_class:"governed_artifact_review",coverage:"one_governed_artifact_review",reproduced_as_human_path:true,summary:$spec[0].summary},
     cli:{},ui:{},browser_network:{},reachability:{},activation:{},stores:{},tls:{},evidence_sources:{fixture:false,mock:false,testdata:false},
     governed_review:{artifact:"governed-review.json",kind:$review[0].kind,authority_path:$review[0].authority_path,authority_anchor:$review[0].authority_anchor,methodology_path:$review[0].methodology_path,subjects:$review[0].subjects,checks:$review[0].checks,conclusion:$review[0].conclusion},
     artifacts:$artifacts[0]}
  ' >"$output"
}

seal_review() {
  need git; need jq
  load_review_state
  assert_exact_review_source
  local tool="${BIN_DIR}/probectl-delivery-audit" key declarations base failed_root failed_draft failed_receipt lint_raw lint_status final_draft verified
  [[ -x "$tool" && ! -L "$tool" ]] || die "frozen review audit binary is missing"
  key="${PROBECTL_AUDIT_SIGNING_KEY:-${PRIVATE_DIR}/receipt-signing.pem}"
  if [[ -n "${PROBECTL_AUDIT_SIGNING_KEY:-}" ]]; then
    [[ -f "$key" && ! -L "$key" ]] || die "external signing key must be a regular non-symlink file"
  fi
  declarations="${PRIVATE_DIR}/review-declarations.json"
  base="${PRIVATE_DIR}/review-base.json"
  review_declarations "$declarations"
  review_draft "$declarations" "$base"

  failed_root="${PRIVATE_DIR}/failed-artifacts"
  [[ ! -e "$failed_root" ]] || die "refusing to reuse review negative-control directory"
  mkdir -m 0700 "$failed_root"
  printf '%s\n' '{"schema":"probectl.delivery-audit-negative-control/v1","fixture-only":"planted negative control"}' >"${failed_root}/planted-control.json"
  chmod 0600 "${failed_root}/planted-control.json"
  failed_draft="${PRIVATE_DIR}/review-failed-draft.json"
  jq '.receipt_id += "-failed" | .status="FAILED" | .evidence_sources.fixture=true | .failure_reasons=["planted control must never promote"] | .artifacts=[{path:"planted-control.json",kind:"negative_fixture",bytes:0,sha256:""}]' "$base" >"$failed_draft"
  failed_receipt="${STATE_DIR}/receipt-failed.json"
  "$tool" seal --draft "$failed_draft" --artifacts "$failed_root" --key "$key" --out "$failed_receipt" >"${STATE_DIR}/seal-failed.json"
  lint_raw="${PRIVATE_DIR}/review-failed-lint.json"
  set +e
  "$tool" lint --receipt "$failed_receipt" --artifacts "$failed_root" >"$lint_raw"
  lint_status=$?
  set -e
  (( lint_status != 0 )) || die "review planted control unexpectedly passed lint"
  jq -e '([.diagnostics[].code]|index("fixture-only"))!=null and ([.diagnostics[].code]|index("status-failed"))!=null' "$lint_raw" >/dev/null || die "review negative control lacked required diagnostics"
  install -m 0644 "$failed_receipt" "${ARTIFACT_DIR}/negative-receipt.json"
  install -m 0644 "${failed_root}/planted-control.json" "${ARTIFACT_DIR}/planted-control.json"
  jq -n --arg envelope 'negative-receipt.json' --arg envelope_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/negative-receipt.json")" \
    --arg planted 'planted-control.json' --arg planted_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/planted-control.json")" --slurpfile lint "$lint_raw" \
    '{schema:"probectl.delivery-audit-linter-output/v1",rejected:true,failed_envelope_path:$envelope,failed_envelope_sha256:$envelope_sha,planted_artifact_path:$planted,planted_artifact_sha256:$planted_sha,diagnostics:([$lint[0].diagnostics[]|select(.code=="fixture-only" or .code=="status-failed")]|unique_by(.code))}' \
    >"${ARTIFACT_DIR}/linter-output.json"
  jq -e '(.diagnostics|length)==2 and ([.diagnostics[].code]|sort)==["fixture-only","status-failed"]' "${ARTIFACT_DIR}/linter-output.json" >/dev/null || die "review negative-control report is not exact"

  review_declarations "$declarations"
  final_draft="${PRIVATE_DIR}/review-verified-draft.json"
  review_draft "$declarations" "$final_draft"
  verified="${STATE_DIR}/receipt-verified.json"
  "$tool" seal --draft "$final_draft" --artifacts "$ARTIFACT_DIR" --source-root "$REVIEW_SOURCE_DIR" --key "$key" --out "$verified" >"${STATE_DIR}/seal-verified.json"
  jq -er .signer_fingerprint "${STATE_DIR}/seal-verified.json" >"${STATE_DIR}/signer-fingerprint.txt"
  chmod 0644 "$failed_receipt" "$verified" "${STATE_DIR}/signer-fingerprint.txt"
  log "sealed governed-review VERIFIED + planted FAILED receipts; signer remains untrusted until supplied out of band"
}

verify_review() {
  need git; need jq
  load_review_state
  assert_exact_review_source
  local tool="${BIN_DIR}/probectl-delivery-audit" verified="${STATE_DIR}/receipt-verified.json" failed="${STATE_DIR}/receipt-failed.json"
  local trusted_key="${PROBECTL_AUDIT_TRUSTED_PUBLIC_KEY:-}" trusted_fingerprint="${PROBECTL_AUDIT_TRUSTED_FINGERPRINT:-}"
  "$tool" verify --receipt "$verified" --artifacts "$ARTIFACT_DIR" >"${STATE_DIR}/verify-signature.json"
  "$tool" verify --receipt "$failed" --artifacts "${PRIVATE_DIR}/failed-artifacts" >"${STATE_DIR}/verify-failed-signature.json"
  "$tool" lint --receipt "$verified" --artifacts "$ARTIFACT_DIR" --source-root "$REVIEW_SOURCE_DIR" >"${STATE_DIR}/lint-verified.json"
  jq -e '(.diagnostics|length)==0' "${STATE_DIR}/lint-verified.json" >/dev/null || die "governed-review semantic lint failed"
  if [[ -n "$trusted_key" || -n "$trusted_fingerprint" ]]; then
    local trust_args=()
    [[ -z "$trusted_key" || ( -f "$trusted_key" && ! -L "$trusted_key" ) ]] || die "trusted public key is invalid"
    [[ -z "$trusted_key" ]] || trust_args+=(--trusted-public-key "$trusted_key")
    if [[ -n "$trusted_fingerprint" ]]; then
      [[ "$trusted_fingerprint" =~ ^sha256:[0-9a-f]{64}$ ]] || die "trusted fingerprint must be an out-of-band sha256 digest"
      trust_args+=(--trusted-fingerprint "$trusted_fingerprint")
    fi
    "$tool" verify --receipt "$verified" --artifacts "$ARTIFACT_DIR" --require-current --repo "$REPO_ROOT" "${trust_args[@]}" >"${STATE_DIR}/verify-current-trusted.json"
    jq -e '.promotion_status=="VERIFIED_CURRENT" and .cryptographic_status=="SIGNATURE_VALID_TRUSTED"' "${STATE_DIR}/verify-current-trusted.json" >/dev/null || die "trusted governed-review promotion failed"
  else
    log "review signature is valid but non-promotable until an out-of-band key/fingerprint is supplied"
  fi
  [[ -n "${PROBECTL_AUDIT_SIGNING_KEY:-}" ]] || rm -f "${PRIVATE_DIR}/receipt-signing.pem"
  log "governed review verified; state-local signing key removed and public evidence retained"
}

cleanup_review() {
  load_review_state
  [[ "$PRIVATE_DIR" == "${STATE_DIR}/private" ]] || die "refusing unsafe review cleanup"
  rm -f "${PRIVATE_DIR}/receipt-signing.pem"
  log "state-local review signing key removed; public review evidence retained"
}

case "$PHASE" in
  prepare) prepare_review ;;
  seal) seal_review ;;
  verify) verify_review ;;
  cleanup) cleanup_review ;;
  all)
    prepare_review
    seal_review
    verify_review
    ;;
  *) die "usage: review.sh [prepare|seal|verify|cleanup|all]" ;;
esac
