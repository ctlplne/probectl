-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- Zabbix identifies a host by its documented host key. A poll item or alert
-- trigger must retain that exact parent key so a later reviewed mapper can
-- find only the same source's applied device provenance. Existing vendor
-- numeric parent IDs stay valid; no parent value grants destination authority.

-- lock-ok: the import row table is new and low-volume. Replace its narrow
-- parent CHECK without scanning existing rows; NOT VALID still checks writes.
DO $nms_zabbix_parent$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conrelid='nms_import_rows'::regclass
                 AND conname='nms_import_rows_parent_external_id_check') THEN
        ALTER TABLE nms_import_rows
            DROP CONSTRAINT nms_import_rows_parent_external_id_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_rows'::regclass
                     AND conname='nms_import_rows_parent_source_key_check') THEN
        ALTER TABLE nms_import_rows
            ADD CONSTRAINT nms_import_rows_parent_source_key_check CHECK (
                parent_external_id IS NULL OR
                (octet_length(parent_external_id) BETWEEN 1 AND 256
                 AND parent_external_id !~ '[[:cntrl:]]'
                 AND (parent_external_id ~ '^[0-9a-f]+$' OR
                      object_kind IN ('poll_setting','alert_rule')))
            ) NOT VALID;
    END IF;
END $nms_zabbix_parent$;
