# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

import hashlib
import json
import unittest

from score_ddos_replay import score


class ReplayClockTests(unittest.TestCase):
    def score_episode(self, positive, delay_ms, end="2026-01-12T12:00:10Z"):
        replay_case = {
            "id": "trial-0001",
            "modeled_start": "2026-01-12T11:59:58Z",
            "pairs": [
                {"current": {"to": "2026-01-12T12:00:05Z"}},
                {"current": {"to": end}},
            ],
        }
        inputs = json.dumps(
            {"schema": "probectl-ddos-synthetic-replay-v1", "cases": [replay_case]}
        ).encode()
        digest = hashlib.sha256(inputs).hexdigest()
        truth = {
            "inputs_sha256": digest,
            "cases": [{"id": "trial-0001", "scenario": "test", "positive": positive}],
        }
        decisions = {
            "schema": "probectl-ddos-synthetic-decisions-v1",
            "inputs_sha256": digest,
            "cases": [
                {
                    "id": "trial-0001",
                    "decision": "episode",
                    "episode_delay_ms": delay_ms,
                }
            ],
        }
        return score(inputs, json.dumps(truth).encode(), json.dumps(decisions).encode())

    def test_final_replay_clock_is_inclusive(self):
        for positive, outcome in ((True, "true_positive"), (False, "false_positive")):
            with self.subTest(positive=positive):
                self.assertEqual(
                    self.score_episode(positive, 12000)["counts"][outcome], 1
                )
                with self.assertRaisesRegex(ValueError, "exceeds its 12000 ms replay"):
                    self.score_episode(positive, 12001)

    def test_replay_clocks_need_timezone(self):
        with self.assertRaisesRegex(ValueError, "invalid replay clocks"):
            self.score_episode(True, 12000, end="2026-01-12T12:00:10")
