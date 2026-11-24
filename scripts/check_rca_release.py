#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Gate the tagged commit's builtin RCA report and emit release-note metrics."""
import argparse
import json
import math
from pathlib import Path
import re

def score(value):
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError('invalid RCA score')
    return value

def case_index(rows, count):
    if type(count) is not int or not isinstance(rows, list) or len(rows) != count:
        raise ValueError('RCA report scenario count does not match its rows')
    out = {}
    for row in rows:
        name = row['name']
        if not isinstance(name, str) or not name or name in out:
            raise ValueError('missing or duplicate RCA scenario identity')
        if any(type(row[key]) is not bool for key in ('expect_insufficient', 'answer_correct', 'insufficient')):
            raise ValueError('RCA report is missing a boolean outcome')
        precision = score(row['citation_precision'])
        if row.get('error'):
            raise ValueError(f'RCA scenario {name} did not finish cleanly')
        raw, valid = row['published_citations'], row['published_resolved_citations']
        if type(raw) is not int or type(valid) is not int or raw < 0 or valid != raw:
            raise ValueError(f'RCA scenario {name} contains unresolved citations')
        cited, relevant = row['cited'], row['relevant_cited']
        if type(cited) is not int or type(relevant) is not int or not 0 <= relevant <= cited <= valid:
            raise ValueError(f'RCA scenario {name} has inconsistent citation counts')
        if cited and not math.isclose(precision, relevant / cited, rel_tol=0, abs_tol=1e-12):
            raise ValueError(f'RCA scenario {name} citation precision differs from its counts')
        if not cited and not row['expect_insufficient'] and precision != 0:
            raise ValueError(f'RCA scenario {name} claimed citation credit without citations')
        if row['insufficient'] and row['answer_correct']:
            raise ValueError(f'RCA scenario {name} claimed answer credit for an abstention')
        if row['expect_insufficient'] and not row['insufficient']:
            raise ValueError(f'RCA scenario {name} should have abstained')
        out[name] = row
    return out

def quality(rows):
    positives = [row for row in rows if not row['expect_insufficient']]
    if not positives:
        raise ValueError('RCA report has no positive scenarios')
    return (sum(row['answer_correct'] for row in positives) / len(positives),
            sum(row['citation_precision'] for row in positives) / len(positives))

def check(report, baseline, expected_sha):
    if not re.fullmatch(r'[0-9a-f]{40}', expected_sha) or report.get('commit') != expected_sha:
        raise ValueError('RCA report does not name the exact tagged commit')
    if report['model'] != 'builtin' or baseline['model'] != 'builtin' or report['honesty_pass'] is not True:
        raise ValueError('the builtin RCA evaluation must pass its abstention checks')
    rows = case_index(report['results'], report['scenarios'])
    whole = quality(rows.values())
    declared = (score(report['answer_accuracy']), score(report['mean_citation_precision']))
    if not all(math.isclose(a, b, rel_tol=0, abs_tol=1e-12) for a, b in zip(whole, declared, strict=True)):
        raise ValueError('RCA report summary differs from the per-scenario scores')
    expected = set()
    controls = baseline['cases']
    lab_cases = baseline['required_lab_cases']
    if not controls or not lab_cases:
        raise ValueError('the RCA release policy requires historical and added lab cases')
    for control in [*controls, *lab_cases]:
        name = control['name']
        abstains = control['expect_insufficient']
        if (name in expected or name not in rows or type(abstains) is not bool
                or rows[name]['expect_insufficient'] != abstains):
            raise ValueError(f'RCA release case was removed, duplicated or reclassified: {name}')
        expected.add(name)
    matched = [rows[control['name']] for control in controls]
    matched_scores = quality(matched)
    margin = score(baseline['max_absolute_drop'])
    previous = (score(baseline['answer_accuracy']), score(baseline['mean_citation_precision']))
    names = ('answer accuracy', 'citation precision')
    for label, old, all_score, cohort_score in zip(names, previous, whole, matched_scores, strict=True):
        minimum = old - margin
        if min(all_score, cohort_score) + 1e-12 < minimum:
            raise ValueError(f'{label} drops beyond the release margin. Minimum {minimum:.4f}, '
                             f'full corpus {all_score:.4f}, matched baseline {cohort_score:.4f}')
    citations = sum(row['published_citations'] for row in rows.values())
    if citations == 0:
        raise ValueError('the RCA run published no citations')
    negatives = sum(row['expect_insufficient'] for row in rows.values())
    return {
        'answer_accuracy_pct': f'{100 * whole[0]:.2f}',
        'citation_precision_pct': f'{100 * whole[1]:.2f}',
        'scenario_count': str(len(rows)),
        'positive_count': str(len(rows) - negatives),
        'abstention_count': str(negatives),
        'resolved_citations': str(citations),
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--github-output', type=Path)
    args = p.parse_args()
    try:
        report = json.loads(args.report.read_text())
        baseline = json.loads(args.baseline.read_text())
        metrics = check(report, baseline, args.sha)
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise SystemExit(f'RCA release gate: {error}') from error
    print(json.dumps(metrics))
    if args.github_output:
        with args.github_output.open('a') as stream:
            for name, value in metrics.items():
                stream.write(f'{name}={value}\n')

if __name__ == '__main__':
    main()
