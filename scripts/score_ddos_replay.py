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
from datetime import datetime, timedelta
from pathlib import Path

RESULTS = {
    "episode": ("true_positive", "false_positive"),
    "quiet": ("false_negative", "true_negative"),
    "abstained": ("abstained_positive", "abstained_negative"),
    "unsupported": ("unsupported_positive", "unsupported_negative"),
}
REFLECTION = "udp_reflection_suspected"
EXPECTED_VECTORS = {
    "distributed_destination_pressure",
    "mixed_network_vector_pressure",
    "tcp_syn_pressure",
    "volumetric_pressure",
    *(
        f"{REFLECTION}/{service}"
        for service in ("cldap", "dns", "memcached", "ntp", "ssdp")
    ),
}
OBSERVED_VECTORS = EXPECTED_VECTORS | {REFLECTION, "other"}
VECTOR_OUTCOMES = ("exact_match", "different_vector", "episode_without_vector", "no_episode")


def unique_json_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON key {name!r}")
        result[name] = value
    return result


def reject_json_constant(value):
    raise ValueError(f"invalid JSON number {value}")


def replay_document(data, name):
    try:
        return json.loads(
            data,
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except ValueError as ex:
        raise ValueError(f"{name}: {ex}") from ex


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


def metrics(counts, true_positive_delays):
    positives = sum(counts[positive] for positive, _ in RESULTS.values())
    negatives = sum(counts[negative] for _, negative in RESULTS.values())
    classified = sum(
        counts[key] for status in ("episode", "quiet") for key in RESULTS[status]
    )
    return {
        "classification_coverage": ratio(classified, positives + negatives),
        "recall_all_positives": ratio(counts["true_positive"], positives),
        "false_alarm_rate_all_negatives": ratio(counts["false_positive"], negatives),
        "true_positive_onset_ms": onset(true_positive_delays),
    }


def replay_horizon_ms(case_id, case):
    try:
        start = datetime.fromisoformat(case["modeled_start"])
        ends = [datetime.fromisoformat(pair["current"]["to"]) for pair in case["pairs"]]
        if (
            start.tzinfo is None
            or len(ends) != 2
            or any(end.tzinfo is None for end in ends)
            or not start < ends[0] < ends[1]
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as ex:
        raise ValueError(f"inputs have invalid replay clocks for {case_id!r}") from ex
    return (ends[1] - start) // timedelta(milliseconds=1)


def vector_outcome(case_id, label, guess, status):
    expected = label.get("expected_vector")
    observed = guess.get("vector")
    if "expected_vector" in label and (
        not label["positive"]
        or not isinstance(expected, str)
        or expected not in EXPECTED_VECTORS
    ):
        raise ValueError(f"ground truth has an invalid expected vector for {case_id!r}")
    if "vector" in guess and (
        status != "episode"
        or not isinstance(observed, str)
        or observed not in OBSERVED_VECTORS
    ):
        raise ValueError(f"decision has an invalid episode vector for {case_id!r}")
    if expected is None:
        return None
    if status != "episode":
        return "no_episode"
    if observed is None:
        return "episode_without_vector"
    return "exact_match" if observed == expected else "different_vector"


def vector_metrics(counts):
    total = sum(counts.values())
    return {
        "labeled_positives": total,
        **{key: counts[key] for key in VECTOR_OUTCOMES},
        "exact_match_rate_all_labeled_positives": ratio(counts["exact_match"], total),
    }


def score(input_bytes, truth_bytes, decision_bytes):
    inputs = replay_document(input_bytes, "inputs")
    cases = case_rows(inputs, "inputs")
    if inputs.get("schema") != "probectl-ddos-synthetic-replay-v1":
        raise ValueError("unsupported input schema")
    truth = replay_document(truth_bytes, "ground truth")
    decisions = replay_document(decision_bytes, "decisions")
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
    vector_counts = Counter()
    by_vector = defaultdict(Counter)
    true_positive_delays = []
    family_delays = defaultdict(list)
    for case_id, label in labels.items():
        horizon = replay_horizon_ms(case_id, cases[case_id])
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
            if delay > horizon:
                raise ValueError(
                    f"episode for {case_id!r} exceeds its {horizon} ms replay"
                )
            if positive:
                true_positive_delays.append(delay)
                family_delays[family].append(delay)
        elif "episode_delay_ms" in guess:
            raise ValueError(f"only an episode can carry a delay ({case_id!r})")
        positive_key, negative_key = RESULTS[status]
        outcome = positive_key if positive else negative_key
        counts[outcome] += 1
        families[family][outcome] += 1
        result = vector_outcome(case_id, label, guess, status)
        if result is not None:
            vector_counts[result] += 1
            by_vector[label["expected_vector"]][result] += 1

    report = {
        "inputs_sha256": digest,
        "ground_truth_sha256": hashlib.sha256(truth_bytes).hexdigest(),
        "decisions_sha256": hashlib.sha256(decision_bytes).hexdigest(),
        "cases": len(cases),
        "counts": full_counts(counts),
        **metrics(counts, true_positive_delays),
        "by_family": {
            family: full_counts(families[family]) for family in sorted(families)
        },
        "by_family_metrics": {
            family: metrics(families[family], family_delays[family])
            for family in sorted(families)
        },
    }
    if vector_counts:
        report["vector_accuracy"] = vector_metrics(vector_counts)
        report["by_expected_vector"] = {
            vector: vector_metrics(by_vector[vector]) for vector in sorted(by_vector)
        }
    return report


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
