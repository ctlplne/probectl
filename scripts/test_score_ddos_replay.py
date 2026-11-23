# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

import hashlib
import json
import unittest

from score_ddos_replay import score


class ReplayTests(unittest.TestCase):
    def episode_documents(self, positive, delay_ms, end="2026-01-12T12:00:10Z"):
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
        return inputs, json.dumps(truth).encode(), json.dumps(decisions).encode()

    def test_final_replay_clock_is_inclusive(self):
        for positive, outcome in ((True, "true_positive"), (False, "false_positive")):
            with self.subTest(positive=positive):
                self.assertEqual(
                    score(*self.episode_documents(positive, 12000))["counts"][outcome], 1
                )
                with self.assertRaisesRegex(ValueError, "exceeds its 12000 ms replay"):
                    score(*self.episode_documents(positive, 12001))

    def test_replay_clocks_need_timezone(self):
        with self.assertRaisesRegex(ValueError, "invalid replay clocks"):
            score(*self.episode_documents(True, 12000, end="2026-01-12T12:00:10"))

    def test_reject_duplicate_json_keys_in_all_documents(self):
        for index, name, key, first_value in (
            (0, "inputs", b'"to"', b'"2026-01-12T12:00:04Z"'),
            (1, "ground truth", b'"positive"', b"false"),
            (2, "decisions", b'"decision"', b'"quiet"'),
        ):
            with self.subTest(document=name):
                documents = list(self.episode_documents(True, 10000))
                documents[index] = documents[index].replace(
                    key + b":", key + b": " + first_value + b", " + key + b":", 1
                )
                if index == 0:
                    digest = hashlib.sha256(documents[0]).hexdigest()
                    for bound in (1, 2):
                        document = json.loads(documents[bound])
                        document["inputs_sha256"] = digest
                        documents[bound] = json.dumps(document).encode()
                with self.assertRaisesRegex(ValueError, f"{name}: duplicate JSON key"):
                    score(*documents)

    def test_reject_non_json_numbers(self):
        inputs, truth, decisions = self.episode_documents(True, 10000)
        for value in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(value=value):
                invalid = b'{"extra": ' + value + b", " + decisions[1:]
                with self.assertRaisesRegex(ValueError, "decisions: invalid JSON number"):
                    score(inputs, truth, invalid)
