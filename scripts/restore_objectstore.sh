#!/usr/bin/env bash
#
# restore_objectstore.sh <backup> [target]
#
# Restores an object-store backup made by backup_objectstore.sh. This is a
# replacement operation and always requires:
#   PROBECTL_OBJECTSTORE_RESTORE_ACK=replace-objectstore
#
# Filesystem restore verifies the sealed artifact checksum before decrypting
# directly into a sibling staging directory (no plaintext tar at rest), then
# swaps directories while preserving the previous target as *.pre-restore-*.
# S3/MinIO restore syncs a backup prefix to the target and verifies no dry-run
# drift remains. Custom endpoints must use verified HTTPS.
set -euo pipefail

MODE="${PROBECTL_OBJECTSTORE_MODE:-filesystem}"
BACKUP="${1:?usage: restore_objectstore.sh <backup> [target]}"
TARGET_ARG="${2:-}"
ACK="${PROBECTL_OBJECTSTORE_RESTORE_ACK:-}"

fail() { echo "restore_objectstore: $*" >&2; exit 1; }
[ "${ACK}" = "replace-objectstore" ] || fail "set PROBECTL_OBJECTSTORE_RESTORE_ACK=replace-objectstore"

case "${MODE}" in
  filesystem)
    TARGET="${TARGET_ARG:-${PROBECTL_OBJECTSTORE_DIR:-}}"
    PCTL_BIN="${PROBECTL_CONTROL_BIN:-probectl-control}"
    KEY_FILE="${PROBECTL_BACKUP_KEY_FILE:-${PROBECTL_ENVELOPE_KEY_FILE:-}}"
    [ -n "${TARGET}" ] || fail "target or PROBECTL_OBJECTSTORE_DIR is required"
    [ "${TARGET}" != "/" ] || fail "refusing filesystem root target"
    [ -s "${BACKUP}" ] || fail "backup does not exist or is empty: ${BACKUP}"
    [ -s "${BACKUP}.sha256" ] || fail "missing checksum sidecar: ${BACKUP}.sha256"
    command -v tar >/dev/null 2>&1 || fail "tar is required"
    command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
    command -v "${PCTL_BIN}" >/dev/null 2>&1 || fail "${PCTL_BIN} not found; set PROBECTL_CONTROL_BIN"
    if [ -z "${PROBECTL_ENVELOPE_KEY:-}" ] && [ -z "${KEY_FILE}" ]; then
      fail "restore requires PROBECTL_ENVELOPE_KEY or PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE"
    fi
    (cd "$(dirname "${BACKUP}")" && sha256sum -c "$(basename "${BACKUP}").sha256" >/dev/null)
    echo "restore_objectstore: checksum verified"

    parent="$(dirname "${TARGET}")"
    mkdir -p "${parent}"
    parent_abs="$(cd "${parent}" && pwd -P)"
    target_abs="${parent_abs}/$(basename "${TARGET}")"
    [ "${target_abs}" != "/" ] || fail "refusing filesystem root target"
    staging="$(mktemp -d "${parent_abs}/.probectl-objectstore-restore.XXXXXX")"
    trap 'rm -rf "${staging:-}"' EXIT
    open_cmd=("${PCTL_BIN}" backup-open)
    if [ -n "${KEY_FILE}" ]; then
      open_cmd+=(--key-file "${KEY_FILE}")
    fi
    "${open_cmd[@]}" < "${BACKUP}" | tar -C "${staging}" -xf - --no-same-owner

    old=""
    if [ -e "${target_abs}" ]; then
      old="${target_abs}.pre-restore-$(date -u +%Y%m%dT%H%M%SZ)"
      [ ! -e "${old}" ] || fail "pre-restore path already exists: ${old}"
      mv "${target_abs}" "${old}"
    fi
    if ! mv "${staging}" "${target_abs}"; then
      [ -z "${old}" ] || mv "${old}" "${target_abs}"
      fail "could not publish restored object store"
    fi
    trap - EXIT
    echo "restore_objectstore: restored ${target_abs} from ${BACKUP}"
    [ -z "${old}" ] || echo "restore_objectstore: previous target preserved at ${old}"
    ;;

  s3)
    TARGET="${TARGET_ARG:-${PROBECTL_OBJECTSTORE_S3_URI:-}}"
    ENDPOINT="${PROBECTL_OBJECTSTORE_S3_ENDPOINT:-}"
    SSE="${PROBECTL_OBJECTSTORE_S3_SSE:-AES256}"
    KMS_KEY="${PROBECTL_OBJECTSTORE_S3_KMS_KEY_ID:-}"
    case "${BACKUP}" in s3://*) ;; *) fail "backup must be an s3:// URI" ;; esac
    case "${TARGET}" in s3://*) ;; *) fail "target must be an s3:// URI" ;; esac
    [ "${BACKUP%/}" != "${TARGET%/}" ] || fail "backup and target must differ"
    case "${TARGET%/}/" in
      "${BACKUP%/}/"*) fail "target must not be inside the backup prefix" ;;
    esac
    case "${BACKUP%/}/" in
      "${TARGET%/}/"*) fail "backup must not be inside the replacement target prefix" ;;
    esac
    if [ -n "${ENDPOINT}" ]; then
      case "${ENDPOINT}" in https://*) ;; *) fail "custom S3/MinIO endpoint must use verified https://" ;; esac
    fi
    command -v aws >/dev/null 2>&1 || fail "aws CLI is required for S3/MinIO mode"
    aws_args=(aws)
    [ -z "${ENDPOINT}" ] || aws_args+=(--endpoint-url "${ENDPOINT}")
    target_bucket="${TARGET#s3://}"
    target_bucket="${target_bucket%%/*}"
    lock_mode="$("${aws_args[@]}" s3api get-object-lock-configuration \
      --bucket "${target_bucket}" \
      --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text 2>/dev/null || true)"
    [ "${lock_mode}" = "COMPLIANCE" ] ||
      fail "target bucket ${target_bucket} must have default S3 Object Lock COMPLIANCE retention"
    sse_args=()
    case "${SSE}" in
      AES256) sse_args+=(--sse AES256) ;;
      aws:kms)
        [ -n "${KMS_KEY}" ] || fail "PROBECTL_OBJECTSTORE_S3_KMS_KEY_ID is required for aws:kms"
        sse_args+=(--sse aws:kms --sse-kms-key-id "${KMS_KEY}")
        ;;
      none)
        [ "${PROBECTL_OBJECTSTORE_BACKUP_ENCRYPTION_ACK:-}" = "encrypted-objectstore-target" ] ||
          fail "SSE=none requires PROBECTL_OBJECTSTORE_BACKUP_ENCRYPTION_ACK=encrypted-objectstore-target"
        ;;
      *) fail "PROBECTL_OBJECTSTORE_S3_SSE must be AES256, aws:kms, or none" ;;
    esac
    aws_sync() {
      if [ "${#sse_args[@]}" -gt 0 ]; then
        "${aws_args[@]}" s3 sync "$@" "${sse_args[@]}"
      else
        "${aws_args[@]}" s3 sync "$@"
      fi
    }
    aws_sync "${BACKUP%/}/" "${TARGET%/}/" --delete --only-show-errors
    drift="$(aws_sync "${BACKUP%/}/" "${TARGET%/}/" --dryrun --delete)"
    [ -z "${drift}" ] || fail "restore verification found backup/target drift: ${drift}"
    echo "restore_objectstore: restored and verified ${BACKUP%/}/ -> ${TARGET%/}/"
    ;;

  *) fail "PROBECTL_OBJECTSTORE_MODE must be filesystem or s3" ;;
esac
