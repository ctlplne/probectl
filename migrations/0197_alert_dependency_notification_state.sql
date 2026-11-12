-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Reuse the existing tenant-owned FORCE-RLS notification episode. A delivered
-- episode can later be held, so a zero last_notified is not its state machine.
-- The opaque transition identifies one hold period, not source authorization.
-- lock-ok: additive default/nullable metadata; existing readers remain valid.
ALTER TABLE alert_notifications
    ADD COLUMN IF NOT EXISTS dependency_held boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS dependency_transition uuid;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='alert_notifications'::regclass
          AND conname='alert_dependency_notification_shape'
    ) THEN
        ALTER TABLE alert_notifications
            ADD CONSTRAINT alert_dependency_notification_shape
            CHECK ((NOT dependency_held OR (dependency_transition IS NOT NULL AND firing_since IS NOT NULL))
                AND (dependency_transition IS NULL OR
                     dependency_transition<>'00000000-0000-0000-0000-000000000000'::uuid))
            NOT VALID;
    END IF;
END;
$migration$;
ALTER TABLE alert_notifications VALIDATE CONSTRAINT alert_dependency_notification_shape;
