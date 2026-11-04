#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Independent CI-only Chromium reference for the bundled fonts. The product
// renderer never launches Chromium. No server, system font or network fallback.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const { chromium } = createRequire(join(root, "browser-worker/package.json"))("playwright");
const families = ["NotoSans", "NotoSansArabic", "NotoSansDevanagari", "NotoSansSC", "NotoEmoji", "NotoSansSymbols2", "NotoSansHebrew", "NotoSansThai"];
const samples = [
  "arabic: ARABIC-BEGIN العربية موقع الشبكة ARABIC-END",
  "cjk: CJK-BEGIN 東京 中文 CJK-END",
  "emoji: EMOJI-BEGIN 🚀 🌐 EMOJI-END",
  "hebrew: HEBREW-BEGIN שָׁלוֹם HEBREW-END",
  "hebrew_cluster: HEBREW-CLUSTER-BEGIN שָׁ HEBREW-CLUSTER-END",
  "indic: INDIC-BEGIN नमस्ते दुनिया INDIC-END",
  "latin: LATIN-BEGIN café naïve Straße e\u0301 LATIN-END",
  "literal: LITERAL-BEGIN ＝SUM(1,2) (quoted) \\ left  right LITERAL-END",
  "thai: THAI-BEGIN สวัสดี THAI-END",
];
const fonts = await Promise.all(families.map(async (name, i) => ({
  name: `PDF${i}`,
  weight: name === "NotoSansSymbols2" ? "400" : "100 900",
  url: `data:font/ttf;base64,${(await readFile(join(root, "internal/reporting/fonts", `${name}.ttf`))).toString("base64")}`,
})));
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ offline: true, viewport: { width: 1000, height: 780 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  await page.setContent('<html lang="en"><meta charset="utf-8"><body></body></html>');
  await page.evaluate(async ({ fonts, samples }) => {
    for (const item of fonts) {
      const face = new FontFace(item.name, `url(${item.url})`, { weight: item.weight });
      await face.load();
      if (face.status !== "loaded") throw new Error("Reference font failed to load");
      document.fonts.add(face);
    }
    document.body.style.cssText = "margin:32px;background:white;color:black;";
    for (const size of ["10pt", "20pt"]) {
      const group = document.createElement("div");
      group.style.cssText = `font-family:${fonts.map((font) => font.name).join(",")};font-size:${size};font-weight:400;font-variation-settings:'wght' 400;line-height:1.8;margin-bottom:24px;`;
      for (const text of samples) {
        const line = document.createElement("div");
        line.className = "sample";
        line.style.whiteSpace = "pre";
        line.textContent = text;
        group.append(line);
      }
      document.body.append(group);
    }
    await document.fonts.ready;
  }, { fonts, samples });
  const output = join(root, "dist/report-pdf");
  await mkdir(output, { recursive: true });
  // Verify that the independent image actually used bundled custom fonts,
  // rather than silently substituting an installed system face.
  const session = await context.newCDPSession(page);
  await session.send("DOM.enable");
  await session.send("CSS.enable");
  const { root: documentNode } = await session.send("DOM.getDocument");
  const { nodeIds } = await session.send("DOM.querySelectorAll", { nodeId: documentNode.nodeId, selector: ".sample" });
  if (nodeIds.length !== samples.length * 2) throw new Error("Font reference omitted sample lines");
  const fontSelections = [];
  for (const nodeId of nodeIds) {
    const { fonts } = await session.send("CSS.getPlatformFontsForNode", { nodeId });
    if (!fonts.length || fonts.some((font) => font.glyphCount > 0 && !font.isCustomFont)) {
      throw new Error("Font reference used an unbundled system font");
    }
    fontSelections.push(fonts);
  }
  await page.screenshot({ path: join(output, "font-reference.png"), fullPage: true });
  await writeFile(join(output, "font-reference.json"), JSON.stringify({ source: "independent Chromium synthetic text using only the bundled font bytes; manual glyph comparison required", families, samples, fontSelections, offline: true, browser: browser.version(), sha: process.env.GITHUB_SHA }, null, 2) + "\n");
  await session.detach();
  await context.close();
} finally {
  await browser.close();
}
