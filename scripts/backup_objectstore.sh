#!/usr/bin/env bash
#
# backup_objectstore.sh <destination>
#
# Backs up the operator-owned object store, including signed WORM audit
# segments. Modes:
#   filesystem (default): PROBECTL_OBJECTSTORE_DIR -> encrypted .tar.pbk in a
#                         local/off-box destination directory.
#   s3: PROBECTL_OBJECTSTORE_S3_URI -> a timestamped destination s3:// prefix
#       using the AWS CLI (works with AWS S3 and MinIO's S3 API).
#
# No credentials are accepted as command-line flags. S3 credentials come from
# the AWS SDK chain/workload identity, and custom endpoints must use verified
# HTTPS. The filesystem path never writes a plaintext tar archive.
set -euo pipefail

MODE="${PROBECTL_OBJECTSTORE_MODE:-filesystem}"
DESTINATION="${1:?usage: backup_objectstore.sh <destination-dir-or-s3-uri>}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

fail() { echo "backup_objectstore: $*" >&2; exit 1; }

case "${MODE}" in
  filesystem)
    SOURCE="${PROBECTL_OBJECTSTORE_DIR:-}"
    PCTL_BIN="${PROBECTL_CONTROL_BIN:-probectl-control}"
    KEY_FILE="${PROBECTL_BACKUP_KEY_FILE:-${PROBECTL_ENVELOPE_KEY_FILE:-}}"
    [ -n "${SOURCE}" ] || fail "PROBECTL_OBJECTSTORE_DIR is required in filesystem mode"
    [ -d "${SOURCE}" ] || fail "source directory does not exist: ${SOURCE}"
    command -v tar >/dev/null 2>&1 || fail "tar is required"
    command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
    if [ -z "${PROBECTL_ENVELOPE_KEY:-}" ] && [ -z "${KEY_FILE}" ]; then
      fail "filesystem backups require PROBECTL_ENVELOPE_KEY or PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE"
    fi
    command -v "${PCTL_BIN}" >/dev/null 2>&1 || fail "${PCTL_BIN} not found; set PROBECTL_CONTROL_BIN"

    mkdir -p "${DESTINATION}"
    SOURCE_ABS="$(cd "${SOURCE}" && pwd -P)"
    DEST_ABS="$(cd "${DESTINATION}" && pwd -P)"
    case "${DEST_ABS}/" in
      "${SOURCE_ABS}/"*) fail "destination must not be inside the object-store source" ;;
    esac
    bad="$(find "${SOURCE_ABS}" -mindepth 1 \( -type l -o \( ! -type d ! -type f \) \) -print -quit)"
    [ -z "${bad}" ] || fail "refusing symlink/special object-store entry: ${bad}"

    OUT="${DEST_ABS}/objectstore-${STAMP}.tar.pbk"
    TMP="${OUT}.tmp"
    trap 'rm -f "${TMP:-}"' EXIT
    seal_cmd=("${PCTL_BIN}" backup-seal)
    if [ -n "${KEY_FILE}" ]; then
      seal_cmd+=(--key-file "${KEY_FILE}")
    fi
    tar -C "${SOURCE_ABS}" -cf - . | "${seal_cmd[@]}" > "${TMP}"
    [ -s "${TMP}" ] || fail "empty sealed backup"
    mv "${TMP}" "${OUT}"
    trap - EXIT
    (cd "${DEST_ABS}" && sha256sum "$(basename "${OUT}")" > "$(basename "${OUT}").sha256")
    echo "backup_objectstore: wrote sealed ${OUT} ($(wc -c < "${OUT}") bytes)"
    ;;

  s3)
    SOURCE="${PROBECTL_OBJECTSTORE_S3_URI:-}"
    ENDPOINT="${PROBECTL_OBJECTSTORE_S3_ENDPOINT:-}"
    SSE="${PROBECTL_OBJECTSTORE_S3_SSE:-AES256}"
    KMS_KEY="${PROBECTL_OBJECTSTORE_S3_KMS_KEY_ID:-}"
    [ -n "${SOURCE}" ] || fail "PROBECTL_OBJECTSTORE_S3_URI is required in s3 mode"
    case "${SOURCE}" in s3://*) ;; *) fail "source must be an s3:// URI" ;; esac
    case "${DESTINATION}" in s3://*) ;; *) fail "destination must be an s3:// URI" ;; esac
    [ "${SOURCE%/}" != "${DESTINATION%/}" ] || fail "source and destination must differ"
    case "${DESTINATION%/}/" in
      "${SOURCE%/}/"*) fail "destination must not be inside the source prefix" ;;
    esac
    if [ -n "${ENDPOINT}" ]; then
      case "${ENDPOINT}" in https://*) ;; *) fail "custom S3/MinIO endpoint must use verified https://" ;; esac
    fi
    command -v aws >/dev/null 2>&1 || fail "aws CLI is required for S3/MinIO mode"
    snapshot="${DESTINATION%/}/${STAMP}"
    aws_args=(aws)
    [ -z "${ENDPOINT}" ] || aws_args+=(--endpoint-url "${ENDPOINT}")
    destination_bucket="${DESTINATION#s3://}"
    destination_bucket="${destination_bucket%%/*}"
    lock_mode="$("${aws_args[@]}" s3api get-object-lock-configuration \
      --bucket "${destination_bucket}" \
      --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text 2>/dev/null || true)"
    [ "${lock_mode}" = "COMPLIANCE" ] ||
      fail "destination bucket ${destination_bucket} must have default S3 Object Lock COMPLIANCE retention"
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

    aws_sync "${SOURCE%/}/" "${snapshot}/" --only-show-errors
    drift="$(aws_sync "${SOURCE%/}/" "${snapshot}/" --dryrun --delete)"
    [ -z "${drift}" ] || fail "verification found source/destination drift: ${drift}"
    echo "backup_objectstore: verified ${SOURCE%/}/ -> ${snapshot}/"
    echo "OBJECTSTORE_BACKUP_URI=${snapshot}/"
    ;;

  *) fail "PROBECTL_OBJECTSTORE_MODE must be filesystem or s3" ;;
esac
