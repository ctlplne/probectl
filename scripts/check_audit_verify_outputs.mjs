#!/usr/bin/env node
// check_audit_verify_outputs.mjs validates the repaired probectl-audit VERIFY
// artifacts. It is intentionally dependency-free so an audit wave can run it
// from a checked-out repo with only Node available.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const DEFAULT_EXPECTED_REPORTS = 25;
const DEFAULT_MIN_CITATION_REFERENCES = 178;

function usage() {
  console.error(`usage:
  node scripts/check_audit_verify_outputs.mjs [--repo <repo>] [--outputs <audit-outputs>] [--expected-reports <n>] [--min-citation-references <n>]

Defaults:
  --repo current working directory
  --outputs <repo>/../probectl-audit/outputs
  --expected-reports ${DEFAULT_EXPECTED_REPORTS}
  --min-citation-references ${DEFAULT_MIN_CITATION_REFERENCES}`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    }
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected positional argument: ${arg}`);
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`missing value for ${arg}`);
    }
    args[arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
    i += 1;
  }
  return args;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function parseAppendix(html, name) {
  const match = html.match(/<script[^>]*id=["']diligence-findings["'][^>]*>([\s\S]*?)<\/script>/);
  assert(match, `${name}: missing diligence-findings appendix`);
  try {
    return JSON.parse(match[1].trim());
  } catch (error) {
    throw new Error(`${name}: diligence appendix is not valid JSON: ${error.message}`);
  }
}

function reportFiles(outputsDir) {
  return readdirSync(outputsDir)
    .filter((name) => name.endsWith(".html"))
    .filter((name) => !name.startsWith("00-"))
    .filter((name) => name !== "VERIFY.html")
    .sort((a, b) => a.localeCompare(b));
}

function hasScoreKeys(doc) {
  return (
    Object.hasOwn(doc, "score") ||
    Object.hasOwn(doc, "score_raw") ||
    Object.hasOwn(doc, "score_weighted") ||
    Object.hasOwn(doc, "scores") ||
    Object.hasOwn(doc, "scoring") ||
    Object.hasOwn(doc, "score_summary")
  );
}

function hasScopeKeys(doc) {
  return (
    Object.hasOwn(doc, "scope") ||
    Object.hasOwn(doc, "baseline") ||
    Object.hasOwn(doc, "repo") ||
    Object.hasOwn(doc, "repository") ||
    Object.hasOwn(doc, "target") ||
    Object.hasOwn(doc, "target_repo")
  );
}

function hasCoverageKeys(doc) {
  return (
    Object.hasOwn(doc, "coverage") ||
    Object.hasOwn(doc, "coverage_score") ||
    Object.hasOwn(doc, "coverage_pct") ||
    Object.hasOwn(doc, "coverage_ledger") ||
    Object.hasOwn(doc, "coverage_matrix_present")
  );
}

function inspectedPath(entry) {
  if (typeof entry === "string") return entry;
  if (entry && typeof entry.path === "string") return entry.path;
  if (entry && typeof entry.file === "string") return entry.file;
  return "";
}

function validateDomainReports(outputsDir, expectedReports) {
  const files = reportFiles(outputsDir);
  assert(
    files.length === expectedReports,
    `expected ${expectedReports} repaired report appendices, found ${files.length}: ${files.join(", ")}`,
  );

  const inspectedUnion = new Set();
  const missingTopLevel = [];

  for (const name of files) {
    const html = readFileSync(path.join(outputsDir, name), "utf8");
    const doc = parseAppendix(html, name);
    const missing = [];
    if (!hasScoreKeys(doc)) missing.push("score");
    if (!hasScopeKeys(doc)) missing.push("scope");
    if (!hasCoverageKeys(doc)) missing.push("coverage");
    if (!Array.isArray(doc.findings)) missing.push("findings");
    if (!Array.isArray(doc.inspected_files)) missing.push("inspected_files");
    if (missing.length > 0) {
      missingTopLevel.push(`${name}: ${missing.join(", ")}`);
    }

    for (const entry of doc.inspected_files ?? []) {
      const filePath = inspectedPath(entry);
      if (filePath) inspectedUnion.add(filePath);
    }
  }

  assert(missingTopLevel.length === 0, `missing top-level appendix keys: ${missingTopLevel.join("; ")}`);
  return { files, inspectedUnion };
}

function validateCoverageSummary(verifyDoc, inspectedUnion) {
  assert(verifyDoc.coverage_overall_pct === 100, "VERIFY coverage_overall_pct must be exactly 100");

  const areas = Object.entries(verifyDoc.coverage_by_area ?? {});
  assert(areas.length > 0, "VERIFY coverage_by_area must be present");

  let filesTotal = 0;
  let filesInspected = 0;
  const badAreas = [];
  for (const [area, stats] of areas) {
    filesTotal += Number(stats.files_total ?? 0);
    filesInspected += Number(stats.files_inspected ?? 0);
    if (stats.coverage_pct !== 100) badAreas.push(`${area}: coverage_pct=${stats.coverage_pct}`);
    if (Number(stats.files_total ?? 0) !== Number(stats.files_inspected ?? 0)) {
      badAreas.push(`${area}: ${stats.files_inspected}/${stats.files_total}`);
    }
    if (Array.isArray(stats.unaudited_files) && stats.unaudited_files.length > 0) {
      badAreas.push(`${area}: unaudited_files=${stats.unaudited_files.slice(0, 5).join(",")}`);
    }
  }

  assert(badAreas.length === 0, `coverage_by_area is not fully covered: ${badAreas.join("; ")}`);
  assert(filesTotal > 0, "VERIFY coverage denominator must be non-zero");
  assert(filesTotal === filesInspected, `VERIFY coverage total mismatch: ${filesInspected}/${filesTotal}`);
  assert(
    inspectedUnion.size >= filesTotal,
    `domain inspected_files union (${inspectedUnion.size}) is smaller than VERIFY denominator (${filesTotal})`,
  );

  return { filesTotal, filesInspected };
}

function validateCitationSummary(verifyHTML, verifyDoc, minCitationReferences) {
  const results = verifyDoc.citation_results ?? {};
  assert(Number(results.references_checked ?? 0) >= minCitationReferences, "citation sample is smaller than required");
  assert(Number(results.fabricated ?? -1) === 0, "fabricated citation count must be zero");
  assert(Number(verifyDoc.fabrication_rate ?? -1) === 0, "fabrication_rate must be zero");
  assert(Number(results.critical_high_file_only ?? -1) === 0, "Critical/High file-only citations must be zero");
  assert(Number(results.line_level_verified ?? 0) > 0, "line-level citation verification count must be non-zero");

  const fileOnlyRows = [
    ...verifyHTML.matchAll(
      /<tr><td>([^<]+)<\/td><td>([^<]+)<\/td><td>(Critical|High)<\/td><td>([^<]+)<\/td><td><span class="warn">VERIFIED_FILE_ONLY<\/span><\/td>/g,
    ),
  ];
  assert(
    fileOnlyRows.length === 0,
    `Critical/High VERIFIED_FILE_ONLY rows remain: ${fileOnlyRows.map((row) => `${row[1]} ${row[4]}`).join(", ")}`,
  );

  return results;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const repo = path.resolve(args.repo ?? process.cwd());
  const outputsDir = path.resolve(args.outputs ?? path.join(repo, "..", "probectl-audit", "outputs"));
  const expectedReports = Number(args.expectedReports ?? DEFAULT_EXPECTED_REPORTS);
  const minCitationReferences = Number(args.minCitationReferences ?? DEFAULT_MIN_CITATION_REFERENCES);

  assert(existsSync(repo), `repo does not exist: ${repo}`);
  assert(existsSync(outputsDir), `audit outputs directory does not exist: ${outputsDir}`);

  const { files, inspectedUnion } = validateDomainReports(outputsDir, expectedReports);
  const verifyPath = path.join(outputsDir, "VERIFY.html");
  const verifyHTML = readFileSync(verifyPath, "utf8");
  const verifyDoc = parseAppendix(verifyHTML, "VERIFY.html");
  const coverage = validateCoverageSummary(verifyDoc, inspectedUnion);
  const citation = validateCitationSummary(verifyHTML, verifyDoc, minCitationReferences);

  console.log(
    `audit-verify-gate: OK (${files.length} appendices parsed, coverage ${coverage.filesInspected}/${coverage.filesTotal}, citations fabricated=${citation.fabricated})`,
  );
}

try {
  main();
} catch (error) {
  console.error(`audit-verify-gate: ${error.message}`);
  process.exit(1);
}
