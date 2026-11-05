#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Offline PDF component: mandatory Go roots plus independent Poppler proofs."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from ci_report_pdf_direction import (
    RTL_TOKENS,
    assert_complete_records,
    assert_default_presentation,
    diagnose,
    original_semantics_control,
    semantics_selftest,
)

TESTS = (
    "TestReportPDFWholeUnicodeAndCompleteRows",
    "TestReportPDFRefusesIncompleteForeignAndUnrenderableSources",
    "TestReportPDFBudgetsCancellationWriterAndFontIntegrity",
    "TestReportPDFIndependentSpecimen",
    "TestReportPDFDirectionalUnicodeKeepsLogicalContent",
)
PACKAGE = "github.com/ctlplne/probectl/internal/reporting"
OMISSION_ASSERTION = "PDF omitted or duplicated complete row 0"


def assert_omission_control(log: str, returncode: int) -> None:
    events = []
    output = ""
    for line in log.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("Package") == PACKAGE and event.get("Test") == TESTS[0]:
            events.append(event.get("Action"))
            output += event.get("Output", "")
    if (
        returncode == 0
        or events.count("run") != 1
        or events.count("fail") != 1
        or "pass" in events
        or "skip" in events
        or OMISSION_ASSERTION not in output
    ):
        raise RuntimeError(
            "PDF omission control did not fail its complete-row assertion"
        )


def assert_tests(log: str, returncode: int) -> None:
    roots = {test: [] for test in TESTS}
    for line in log.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("Package") == PACKAGE and event.get("Test") in roots:
            roots[event["Test"]].append(event.get("Action"))
    if returncode or any(
        events.count("run") != 1
        or events.count("pass") != 1
        or "skip" in events
        or "fail" in events
        for events in roots.values()
    ):
        raise RuntimeError(f"mandatory PDF roots did not all execute and pass: {roots}")


def selftest() -> None:
    semantics_selftest()
    events = [
        {"Package": PACKAGE, "Test": test, "Action": action}
        for test in TESTS
        for action in ("run", "pass")
    ]

    def encode(values):
        return "\n".join(json.dumps(e) for e in values)

    assert_tests(encode(events), 0)
    for bad, code in (
        (events[2:], 0),
        (events + [events[1]], 0),
        (events, 1),
        ([{**e, "Action": "skip"} if i == 1 else e for i, e in enumerate(events)], 0),
    ):
        try:
            assert_tests(encode(bad), code)
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "PDF classifier accepted missing/duplicate/skipped/failed proof"
            )
    print("PDF classifier refuses missing, duplicate, skipped or failed roots")
    baseline = [
        {"Package": PACKAGE, "Test": TESTS[0], "Action": action}
        for action in ("run", "fail")
    ]
    baseline.insert(
        1,
        {
            "Package": PACKAGE,
            "Test": TESTS[0],
            "Action": "output",
            "Output": OMISSION_ASSERTION,
        },
    )
    assert_omission_control(encode(baseline), 1)
    for bad, code in (
        (baseline, 0),
        (baseline[1:], 1),
        (baseline[:1] + baseline[2:], 1),
        (baseline + [baseline[-1]], 1),
    ):
        try:
            assert_omission_control(encode(bad), code)
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "PDF classifier accepted a false omission-control failure"
            )


def run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PROBECTL_PDF_PROOF_DIR": str(output.resolve())}
    command = [
        "go",
        "test",
        "-race",
        "-count=1",
        "-json",
        "-timeout=10m",
        "./internal/reporting",
        "-run",
        "^(" + "|".join(TESTS) + ")$",
    ]
    source = Path("internal/reporting/pdf.go")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    original = source.read_text()
    seam = '\tfor _, table := range d.Tables {\n\t\tif err := p.table(table); err != nil {\n\t\t\treturn PDFReceipt{}, fmt.Errorf("PDF table rendering: %w", err)\n\t\t}\n\t}'
    if original.count(seam) != 1:
        raise RuntimeError("PDF complete-table omission control seam is unavailable")
    try:
        source.write_text(
            original.replace(seam, "\t// Omission control: no source tables rendered.")
        )
        baseline_command = command[:-1] + ["^" + TESTS[0] + "$"]
        baseline = subprocess.run(
            baseline_command,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        (output / "omission-control.jsonl").write_text(baseline.stdout)
    finally:
        source.write_text(original)
    assert_omission_control(baseline.stdout, baseline.returncode)
    result = subprocess.run(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (output / "go-test.jsonl").write_text(result.stdout)
    assert_tests(result.stdout, result.returncode)
    specimen = output / "specimen.pdf"
    if not specimen.is_file() or specimen.stat().st_size == 0:
        raise RuntimeError("PDF proof did not produce its complete specimen")
    text = subprocess.run(
        ["pdftotext", "-enc", "UTF-8", str(specimen), "-"],
        text=True,
        capture_output=True,
        check=True,
    )
    if text.stderr.strip():
        raise RuntimeError(f"Poppler text warnings: {text.stderr}")
    (output / "extracted.txt").write_text(text.stdout)
    raster = subprocess.run(
        ["pdftoppm", "-r", "96", "-png", str(specimen), str(output / "page")],
        text=True,
        capture_output=True,
        check=True,
    )
    if raster.stderr.strip():
        raise RuntimeError(f"Poppler raster warnings: {raster.stderr}")
    images = sorted(output.glob("page-*.png"))
    if not images or any(image.stat().st_size < 1000 for image in images):
        raise RuntimeError("PDF rasterization did not produce reviewable pages")
    diagnose(specimen, output)
    logical = original_semantics_control(specimen, output)
    assert_default_presentation(text.stdout)
    for token in (
        "LATIN-BEGIN",
        "café",
        "naïve",
        "Straße",
        "e\u0301",
        "LATIN-END",
        "ARABIC-BEGIN",
        "العربية",
        "موقع",
        "الشبكة",
        "ARABIC-END",
        "INDIC-BEGIN",
        "नमस्ते",
        "दुनिया",
        "INDIC-END",
        "HEBREW-BEGIN",
        "שָׁלוֹם",
        "HEBREW-END",
        "HEBREW-CLUSTER-BEGIN",
        "שָׁ",
        "HEBREW-CLUSTER-END",
        "THAI-BEGIN",
        "สวัสดี",
        "THAI-END",
        "CJK-BEGIN",
        "東京",
        "中文",
        "CJK-END",
        "EMOJI-BEGIN",
        "🚀",
        "🌐",
        "EMOJI-END",
        "LITERAL-BEGIN",
        "＝SUM(1,2)",
        "LITERAL-END",
        "WRAP-BEGIN",
        "WRAP-END",
    ):
        if token not in logical or (
            token not in RTL_TOKENS and token not in text.stdout
        ):
            raise RuntimeError(
                f"independent PDF extraction lost complete text: {token!r}"
            )
    assert_complete_records(text.stdout)
    assert_complete_records(logical)
    # Check every word's actual ink/text box rather than trusting renderer math.
    boxes = subprocess.run(
        ["pdftotext", "-bbox", str(specimen), "-"],
        text=True,
        capture_output=True,
        check=True,
    )
    if boxes.stderr.strip():
        raise RuntimeError(f"Poppler geometry warnings: {boxes.stderr}")
    (output / "bounds.html").write_text(boxes.stdout)
    root = ET.fromstring(boxes.stdout)
    pages = list(root.iter("{http://www.w3.org/1999/xhtml}page"))
    if len(pages) < 2:
        raise RuntimeError("PDF pagination proof did not paginate")
    words = 0
    for page in pages:
        page_text = " ".join(
            w.text or "" for w in page.iter("{http://www.w3.org/1999/xhtml}word")
        )
        if (
            "tenant-a" not in page_text
            or "Absolute time:" not in page_text
            or "Page" not in page_text
        ):
            raise RuntimeError("PDF page lost tenant, absolute interval or page footer")
        for word in page.iter("{http://www.w3.org/1999/xhtml}word"):
            words += 1
            x1, y1, x2, y2 = (
                float(word.attrib[key]) for key in ("xMin", "yMin", "xMax", "yMax")
            )
            if not (39 <= x1 <= x2 <= 573 and 28 <= y1 <= y2 <= 772):
                raise RuntimeError(
                    f"PDF content escaped printable page bounds: {word.attrib}"
                )
    if words < 300:
        raise RuntimeError("PDF geometry proof did not inspect all report content")
    if len(images) != len(pages):
        raise RuntimeError("PDF rasterization omitted a page")
    receipt = {
        "component": "offline Go PDF",
        "source": "synthetic report over production renderer; not sender or storage proof",
        "sha": os.environ.get("GITHUB_SHA"),
        "tests": TESTS,
        "table_omission_control": "failed the intended complete-row assertion; source restored",
        "pages": len(pages),
        "words_checked": words,
        "pdf_bytes": specimen.stat().st_size,
        "raster_pages": [image.name for image in images],
        "poppler": subprocess.run(
            ["pdftotext", "-v"], text=True, capture_output=True, check=True
        ).stderr.strip(),
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("dist/report-pdf"))
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        run(args.output)
