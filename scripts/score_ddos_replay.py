#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Score decisions against the offline probectl synthetic DDoS replay."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

RESULTS = {
    "episode": ("true_positive", "false_positive"),
    "quiet": ("false_negative", "true_negative"),
    "abstained": ("abstained_positive", "abstained_negative"),
    "unsupported": ("unsupported_positive", "unsupported_negative"),
}


def case_rows(document, name):
    rows = document.get("cases") if isinstance(document, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{name} needs a nonempty cases array")
    indexed = {}
    for row in rows:
        case_id = row.get("id") if isinstance(row, dict) else None
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"{name} has a row without a case ID")
        if case_id in indexed:
            raise ValueError(f"{name} repeats case {case_id!r}")
        indexed[case_id] = row
    return indexed


def full_counts(counts):
    return {key: counts[key] for pair in RESULTS.values() for key in pair}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def onset(delays):
    if not delays:
        return None
    ordered = sorted(delays)
    return {
        "min": ordered[0],
        "p50": ordered[(len(ordered) * 50 + 99) // 100 - 1],
        "p95": ordered[(len(ordered) * 95 + 99) // 100 - 1],
        "max": ordered[-1],
    }


def score(input_bytes, truth_bytes, decision_bytes):
    inputs = json.loads(input_bytes)
    cases = case_rows(inputs, "inputs")
    if inputs.get("schema") != "probectl-ddos-synthetic-replay-v1":
        raise ValueError("unsupported input schema")
    truth = json.loads(truth_bytes)
    decisions = json.loads(decision_bytes)
    labels = case_rows(truth, "ground truth")
    guesses = case_rows(decisions, "decisions")
    if decisions.get("schema") != "probectl-ddos-synthetic-decisions-v1":
        raise ValueError("unsupported decision schema")
    digest = hashlib.sha256(input_bytes).hexdigest()
    for name, document, rows in (
        ("ground truth", truth, labels),
        ("decisions", decisions, guesses),
    ):
        if document.get("inputs_sha256") != digest:
            raise ValueError(f"{name} does not match the SHA-256 of the inputs")
        missing = len(cases.keys() - rows.keys())
        extra = len(rows.keys() - cases.keys())
        if missing or extra:
            raise ValueError(
                f"{name} must cover the same case IDs ({missing} missing, {extra} unknown)"
            )

    counts = Counter()
    families = defaultdict(Counter)
    true_positive_delays = []
    positives = 0
    for case_id, label in labels.items():
        scenario, positive = label.get("scenario"), label.get("positive")
        if (
            not isinstance(scenario, str)
            or not scenario
            or not isinstance(positive, bool)
        ):
            raise ValueError(f"ground truth has an invalid label for {case_id!r}")
        family = scenario.split("/", 1)[0]
        guess = guesses[case_id]
        status = guess.get("decision")
        if not isinstance(status, str) or status not in RESULTS:
            raise ValueError(f"unknown decision for {case_id!r}")
        if status == "episode":
            delay = guess.get("episode_delay_ms")
            if type(delay) is not int or delay < 0:
                raise ValueError(
                    f"episode for {case_id!r} needs a nonnegative integer delay"
                )
            if positive:
                true_positive_delays.append(delay)
        elif "episode_delay_ms" in guess:
            raise ValueError(f"only an episode can carry a delay ({case_id!r})")
        positive_key, negative_key = RESULTS[status]
        outcome = positive_key if positive else negative_key
        counts[outcome] += 1
        families[family][outcome] += 1
        positives += positive

    classified = sum(
        counts[key] for status in ("episode", "quiet") for key in RESULTS[status]
    )
    return {
        "inputs_sha256": digest,
        "ground_truth_sha256": hashlib.sha256(truth_bytes).hexdigest(),
        "decisions_sha256": hashlib.sha256(decision_bytes).hexdigest(),
        "cases": len(cases),
        "counts": full_counts(counts),
        "classification_coverage": ratio(classified, len(cases)),
        "recall_all_positives": ratio(counts["true_positive"], positives),
        "false_alarm_rate_all_negatives": ratio(
            counts["false_positive"], len(cases) - positives
        ),
        "true_positive_onset_ms": onset(true_positive_delays),
        "by_family": {
            family: full_counts(families[family]) for family in sorted(families)
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("ground_truth", type=Path)
    parser.add_argument("decisions", type=Path)
    args = parser.parse_args()
    try:
        report = score(
            args.inputs.read_bytes(),
            args.ground_truth.read_bytes(),
            args.decisions.read_bytes(),
        )
    except (OSError, ValueError) as ex:
        parser.error(str(ex))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
