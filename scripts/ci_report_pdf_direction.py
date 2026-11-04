#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Independent logical word semantics and diagnostic RTL replacement grouping."""

import json
from pathlib import Path
import re
import subprocess
import unicodedata
import xml.etree.ElementTree as ET

OBJECT = re.compile(rb"(?m)^(\d+) 0 obj\n(.*?)\nendobj\n", re.S)
SPAN = re.compile(rb"/Span << /ActualText <([0-9A-F]+)> >> BDC\n(.*?)EMC\n", re.S)
GLYPH = re.compile(rb"BT /F(\d+) \d+ Tf [^\n]* <([0-9A-F]{2})> Tj ET\n")
RTL_VALUES = ("العربية موقع الشبكة", "שָׁלוֹם", "שָׁ")
RTL_TOKENS = ("العربية", "موقع", "الشبكة", "שָׁלוֹם", "שָׁ")
LOGICAL_ASSERTION = "independent PDF words lost original RTL Unicode"


def extract(path: Path, extra: tuple[str, ...] = ()) -> str:
    result = subprocess.run(
        ["pdftotext", *extra, "-enc", "UTF-8", str(path), "-"],
        capture_output=True,
        text=True,
        check=True,
    )
    if result.stderr.strip():
        raise RuntimeError("PDF direction diagnostic returned text warnings")
    return result.stdout


def objects_from(body: bytes) -> dict[int, bytes]:
    matches = OBJECT.findall(body)
    objects = {int(index): value for index, value in matches}
    if (
        not matches
        or len(matches) != len(objects)
        or sorted(objects) != list(range(1, len(objects) + 1))
    ):
        raise RuntimeError("PDF direction diagnostic requires complete native objects")
    return objects


def font_mappings(objects: dict[int, bytes]) -> dict[tuple[bytes, bytes], bytes]:
    resources = {}
    for obj in objects.values():
        for name, index in re.findall(rb"/F(\d+) (\d+) 0 R", obj):
            if name in resources and resources[name] != int(index):
                raise RuntimeError("PDF direction diagnostic has ambiguous fonts")
            resources[name] = int(index)
    mappings = {}
    for name, index in resources.items():
        font = objects[index]
        match = re.search(rb"/ToUnicode (\d+) 0 R", font)
        if not match:
            raise RuntimeError("PDF direction diagnostic font has no Unicode mapping")
        cmap = objects[int(match[1])]
        for block in re.findall(rb"\d+ beginbfchar\n(.*?)endbfchar", cmap, re.S):
            for code, value in re.findall(rb"<([0-9A-F]{2})> <([0-9A-F]+)>", block):
                mappings[name, code] = value
    if not mappings:
        raise RuntimeError("PDF direction diagnostic has no complete font mappings")
    return mappings


def change_spans(
    stream: bytes,
    mappings: dict[tuple[bytes, bytes], bytes],
    clusters: bool,
    reverse_semantics: bool = False,
) -> tuple[bytes, int]:
    changed = 0

    def replace(span):
        nonlocal changed
        text = bytes.fromhex(span[1].decode("ascii")).decode("utf-16")
        directions = {unicodedata.bidirectional(char) for char in text}
        if not directions.intersection({"R", "AL"}) or "L" in directions:
            return span[0]
        changed += 1
        if reverse_semantics:
            value = text[::-1].encode("utf-16-be").hex().upper().encode("ascii")
            return (
                b"/Span << /ActualText <FEFF"
                + value
                + b"> >> BDC\n"
                + span[2]
                + b"EMC\n"
            )
        if not clusters:
            return span[2]

        def wrap(glyph):
            value = mappings.get((glyph[1], glyph[2]))
            if value is None:
                return glyph[0]
            return (
                b"/Span << /ActualText <FEFF"
                + value
                + b"> >> BDC\n"
                + glyph[0]
                + b"EMC\n"
            )

        return GLYPH.sub(wrap, span[2])

    return SPAN.sub(replace, stream), changed


def variant(
    objects: dict[int, bytes],
    mappings: dict[tuple[bytes, bytes], bytes],
    clusters: bool,
    reverse_semantics: bool = False,
) -> bytes:
    result = bytearray(b"%PDF-1.4\n%\xd0\xd4\xc5\xd8\n")
    offsets = []
    changes = 0
    for index, obj in sorted(objects.items()):
        if b"/ActualText" in obj and b"\nstream\n" in obj:
            header, stream = obj.split(b"\nstream\n", 1)
            if not stream.endswith(b"endstream"):
                raise RuntimeError("PDF direction diagnostic has an unknown stream")
            stream, count = change_spans(
                stream[: -len(b"endstream")], mappings, clusters, reverse_semantics
            )
            changes += count
            header, count = re.subn(
                rb"/Length \d+", b"/Length " + str(len(stream)).encode(), header
            )
            if count != 1:
                raise RuntimeError(
                    "PDF direction diagnostic has an ambiguous stream length"
                )
            obj = header + b"\nstream\n" + stream + b"endstream"
        offsets.append(len(result))
        result.extend(str(index).encode() + b" 0 obj\n" + obj + b"\nendobj\n")
    if changes == 0:
        raise RuntimeError("PDF direction diagnostic did not reach any RTL span")
    xref = len(result)
    result.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(result)


def word_text(xml: str) -> str:
    root = ET.fromstring(xml)
    words = [
        word.text or "" for word in root.iter("{http://www.w3.org/1999/xhtml}word")
    ]
    if not words:
        raise RuntimeError("independent PDF word API returned no source words")
    return "\n".join(words)


def assert_original_rtl(words: str) -> None:
    for value, count in zip(RTL_VALUES, (1, 1, 2), strict=True):
        if words.count(value) != count:
            raise RuntimeError(f"{LOGICAL_ASSERTION}: {value!r}")


def assert_default_presentation(text: str) -> None:
    # Expectations derive from fixed source fixtures, never by normalizing the
    # actual extractor output. Word semantics independently require originals.
    for source, count in zip(RTL_VALUES, (1, 1, 2), strict=True):
        if text.count(source) + text.count(source[::-1]) != count:
            raise RuntimeError(
                "independent PDF default RTL presentation changed or duplicated text"
            )


def assert_complete_records(text: str) -> None:
    for i in range(120):
        for token in (f"proof-row-{i:03}", str(9_007_199_254_740_993 + i)):
            if text.count(token) != 1:
                raise RuntimeError(
                    f"independent PDF extraction omitted or duplicated row: {token}"
                )


def original_semantics_control(specimen: Path, output: Path) -> str:
    xml = (output / "direction-current-bbox.txt").read_text()
    original = word_text(xml)
    assert_original_rtl(original)
    assert_complete_records(original)
    objects = objects_from(specimen.read_bytes())
    bad = variant(objects, font_mappings(objects), False, reverse_semantics=True)
    changed = objects_from(bad)
    for index, obj in objects.items():
        if b"/ActualText" not in obj:
            if changed[index] != obj:
                raise RuntimeError(
                    "RTL semantic control changed an unrelated PDF object"
                )
        elif SPAN.sub(lambda match: match[2], obj) != SPAN.sub(
            lambda match: match[2], changed[index]
        ):
            raise RuntimeError("RTL semantic control changed a visible glyph command")
    poison = output / "reversed-logical-control.pdf"
    poison.write_bytes(bad)
    dumped = extract(poison)
    wrong_xml = extract(poison, ("-bbox",))
    (output / "reversed-logical-control.txt").write_text(dumped)
    (output / "reversed-logical-control-words.html").write_text(wrong_xml)
    wrong_words = word_text(wrong_xml)
    assert_complete_records(dumped)
    assert_complete_records(wrong_words)
    # Demonstrate the former presentation-only criterion rewards wrong logical
    # Unicode, then require the original-word oracle to reject that same file.
    if not all(token in dumped for token in RTL_TOKENS):
        raise RuntimeError("PDF direction oracle counterexample was not proved")
    try:
        assert_original_rtl(wrong_words)
    except RuntimeError as error:
        if not str(error).startswith(LOGICAL_ASSERTION):
            raise
    else:
        raise RuntimeError(
            "independent PDF words accepted reversed logical source Unicode"
        )
    (output / "logical-semantics-control.json").write_text(
        json.dumps(
            {
                "correct_original_words": True,
                "reversed_logical_unicode_rejected": True,
                "presentation_only_criterion_accepts_reversed_semantics": True,
                "visible_commands_unchanged": True,
                "all_120_records_preserved": True,
            },
            indent=2,
        )
        + "\n"
    )
    (output / "logical-words.txt").write_text(original)
    return original


def semantics_selftest() -> None:
    correct = RTL_VALUES[0] + "\n" + RTL_VALUES[1] + "\n" + RTL_VALUES[2]
    assert_original_rtl(correct)
    assert_default_presentation(correct)
    visual = "\n".join(value[::-1] for value in RTL_VALUES)
    assert_default_presentation(visual)
    for bad in (visual, correct + RTL_VALUES[1], correct.replace(RTL_VALUES[2], "")):
        try:
            assert_original_rtl(bad)
        except RuntimeError as error:
            if not str(error).startswith(LOGICAL_ASSERTION):
                raise
        else:
            raise RuntimeError(
                "PDF word oracle accepted reversed, duplicated or missing Unicode"
            )


def diagnose(specimen: Path, output: Path) -> None:
    observations = {}
    for mode in ("raw", "layout", "bbox"):
        text = extract(specimen, ("-" + mode,))
        (output / f"direction-current-{mode}.txt").write_text(text)
        observations["current-" + mode] = text
    objects = objects_from(specimen.read_bytes())
    mappings = font_mappings(objects)
    for mode, clusters in (("glyph-mappings", False), ("cluster-spans", True)):
        path = output / f"direction-{mode}.pdf"
        path.write_bytes(variant(objects, mappings, clusters))
        text = extract(path)
        path.with_suffix(".txt").write_text(text)
        observations[mode] = text
    tokens = ("العربية", "موقع", "الشبكة", "שָׁלוֹם", "שָׁ", "東京", "🚀")
    receipt = {
        "scope": "diagnostics only; unchanged product acceptance remains mandatory",
        "modes": {
            mode: {
                "exact_tokens": {token: token in text for token in tokens},
                "lines": [
                    line
                    for line in text.splitlines()
                    if any(
                        name in line
                        for name in ("arabic:", "hebrew:", "hebrew_cluster:")
                    )
                ],
            }
            for mode, text in observations.items()
        },
    }
    (output / "direction-diagnostics.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n"
    )
