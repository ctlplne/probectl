#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from "node:fs";

const severityRank = {
  info: 0,
  low: 1,
  moderate: 2,
  medium: 2,
  high: 3,
  critical: 4,
};

function usage() {
  return [
    "usage: node scripts/check_npm_audit_policy.mjs --workspace <name> --audit <npm-audit.json> --lock <package-lock.json> --policy <policy.json> [--omit-dev]",
    "       node scripts/check_npm_audit_policy.mjs --selftest",
  ].join("\n");
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--selftest") {
      args.selftest = true;
      continue;
    }
    if (arg === "--omit-dev") {
      args.omitDev = true;
      continue;
    }
    if (!arg.startsWith("--"))
      throw new Error(`${usage()}\nunexpected argument: ${arg}`);
    const key = arg.slice(2);
    const value = argv[++i];
    if (!value || value.startsWith("--"))
      throw new Error(`${usage()}\nmissing value for ${arg}`);
    args[key] = value;
  }
  return args;
}

function readJSON(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function rank(severity) {
  return severityRank[String(severity || "").toLowerCase()] ?? -1;
}

function todayUTC() {
  if (process.env.PROBECTL_NPM_AUDIT_POLICY_TODAY) {
    return process.env.PROBECTL_NPM_AUDIT_POLICY_TODAY;
  }
  return new Date().toISOString().slice(0, 10);
}

function parseDate(value, field) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || "")) {
    throw new Error(
      `${field} must be YYYY-MM-DD, got ${JSON.stringify(value)}`,
    );
  }
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  if (
    Number.isNaN(timestamp) ||
    new Date(timestamp).toISOString().slice(0, 10) !== value
  ) {
    throw new Error(
      `${field} must be a real UTC calendar date, got ${JSON.stringify(value)}`,
    );
  }
  return timestamp;
}

function isExpired(expiresAt, today) {
  return parseDate(today, "today") > parseDate(expiresAt, "expires_at");
}

function vulnerabilityNodes(vuln) {
  return Array.isArray(vuln.nodes) ? vuln.nodes : [];
}

function isDevOnly(vuln, lock) {
  const nodes = vulnerabilityNodes(vuln);
  if (nodes.length === 0) return false;
  return nodes.every((node) => {
    const pkg = lock.packages?.[node];
    return pkg && (pkg.dev === true || pkg.devOptional === true);
  });
}

function advisoryID(via) {
  if (!via || typeof via !== "object") return "";
  const text = `${via.url || ""} ${via.name || ""}`;
  const ghsa = text.match(/\bGHSA-[0-9a-z-]+\b/i);
  if (ghsa) return ghsa[0].toUpperCase();
  if (Number.isInteger(via.source)) return `npm:${via.source}`;
  return "";
}

function advisoryRecords(vuln, audit, seen = new Set()) {
  if (!vuln || typeof vuln !== "object") return [];
  const key = String(vuln.name || "");
  if (key && seen.has(key)) return [];
  const nextSeen = new Set(seen);
  if (key) nextSeen.add(key);

  const records = new Map();
  for (const via of Array.isArray(vuln.via) ? vuln.via : []) {
    if (typeof via === "string") {
      for (const record of advisoryRecords(
        audit.vulnerabilities?.[via],
        audit,
        nextSeen,
      )) {
        records.set(`${record.id}\u0000${record.range}`, record);
      }
      continue;
    }
    const id = rank(via.severity) >= rank("high") ? advisoryID(via) : "";
    if (id) {
      const range = String(via.range || "");
      records.set(`${id}\u0000${range}`, { id, range });
    }
  }
  return [...records.values()].sort(
    (left, right) =>
      left.id.localeCompare(right.id) || left.range.localeCompare(right.range),
  );
}

function advisoryIDs(vuln, audit) {
  return [...new Set(advisoryRecords(vuln, audit).map(({ id }) => id))].sort();
}

function advisoryRanges(vuln, audit) {
  const ranges = {};
  for (const { id, range } of advisoryRecords(vuln, audit)) {
    ranges[id] ||= [];
    ranges[id].push(range);
  }
  for (const id of Object.keys(ranges)) {
    ranges[id] = [...new Set(ranges[id])].sort();
  }
  return ranges;
}

function sameStrings(left, right) {
  const a = [...new Set(left || [])].sort();
  const b = [...new Set(right || [])].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function sameStringMaps(left, right) {
  const a = left && typeof left === "object" ? left : {};
  const b = right && typeof right === "object" ? right : {};
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  return keys.every(
    (key) =>
      Object.hasOwn(a, key) &&
      Object.hasOwn(b, key) &&
      sameStrings(a[key], b[key]),
  );
}

function normalizedAdvisoryRanges(value) {
  const normalized = {};
  for (const [id, ranges] of Object.entries(value || {})) {
    const key = String(id).toUpperCase();
    normalized[key] ||= [];
    normalized[key].push(...(Array.isArray(ranges) ? ranges : []));
  }
  return normalized;
}

function installedVersions(vuln, lock) {
  return [
    ...new Set(
      vulnerabilityNodes(vuln)
        .map((node) => lock.packages?.[node]?.version)
        .filter((version) => typeof version === "string" && version.length > 0),
    ),
  ].sort();
}

function matchingException({ vuln, workspace, lock, policy, audit, today }) {
  const name = vuln.name;
  const severity = String(vuln.severity || "").toLowerCase();
  const observedAdvisories = advisoryIDs(vuln, audit);
  const observedRanges = advisoryRanges(vuln, audit);
  const observedVersions = installedVersions(vuln, lock);
  const matches = (policy.exceptions || []).filter((ex) => {
    return ex.workspace === workspace && (ex.packages || []).includes(name);
  });
  const expired = [];
  for (const ex of matches) {
    if (rank(severity) > rank(ex.max_severity)) continue;
    if (
      !Array.isArray(ex.advisories) ||
      ex.advisories.length === 0 ||
      !sameStrings(
        observedAdvisories,
        ex.advisories.map((id) => String(id).toUpperCase()),
      )
    ) {
      continue;
    }
    if (
      !sameStringMaps(
        observedRanges,
        normalizedAdvisoryRanges(ex.advisory_ranges),
      )
    ) {
      continue;
    }
    if (
      !ex.versions ||
      !sameStrings(observedVersions, ex.versions[name] || [])
    ) {
      continue;
    }
    if (isExpired(ex.expires_at, today)) {
      expired.push(ex);
      continue;
    }
    if (ex.dev_only && !isDevOnly(vuln, lock)) {
      continue;
    }
    return { active: ex };
  }
  if (expired.length > 0) return { expired: expired[0] };
  return {};
}

function evaluate({
  audit,
  lock,
  policy,
  workspace,
  omitDev = false,
  today = todayUTC(),
}) {
  const failures = [];
  const accepted = [];
  const usedExceptions = new Set();
  if (!audit || typeof audit !== "object" || audit.error) {
    return {
      failures: [`${workspace}: npm audit did not return a usable report`],
      accepted,
    };
  }
  if (!audit.vulnerabilities || typeof audit.vulnerabilities !== "object") {
    return {
      failures: [
        `${workspace}: npm audit report has no vulnerabilities object`,
      ],
      accepted,
    };
  }
  for (const ex of policy.exceptions || []) {
    if (ex.workspace !== workspace) continue;
    if (omitDev && ex.dev_only === true) continue;
    if (isExpired(ex.expires_at, today) && ex.standing !== true) {
      failures.push(
        `${workspace}: policy exception ${ex.id} expired at ${ex.expires_at}`,
      );
    }
    if (!Array.isArray(ex.advisories) || ex.advisories.length === 0) {
      failures.push(
        `${workspace}: exception ${ex.id} requires exact advisories`,
      );
    }
    if (
      !sameStrings(
        Object.keys(normalizedAdvisoryRanges(ex.advisory_ranges)),
        (ex.advisories || []).map((id) => String(id).toUpperCase()),
      ) ||
      Object.values(ex.advisory_ranges || {}).some(
        (ranges) =>
          !Array.isArray(ranges) ||
          ranges.length === 0 ||
          ranges.some(
            (range) => typeof range !== "string" || range.length === 0,
          ),
      )
    ) {
      failures.push(
        `${workspace}: exception ${ex.id} requires exact ranges for every advisory`,
      );
    }
    if (
      !sameStrings(Object.keys(ex.versions || {}), ex.packages || []) ||
      Object.values(ex.versions || {}).some(
        (versions) =>
          !Array.isArray(versions) ||
          versions.length === 0 ||
          versions.some(
            (version) => typeof version !== "string" || version.length === 0,
          ),
      )
    ) {
      failures.push(
        `${workspace}: exception ${ex.id} requires exact installed versions for every package`,
      );
    }
    if (ex.standing === true && ex.dev_only !== true) {
      failures.push(
        `${workspace}: standing exception ${ex.id} must be dev-only`,
      );
    }
    if (
      ex.dev_only !== true &&
      (typeof ex.guard !== "string" || ex.guard.length === 0)
    ) {
      failures.push(
        `${workspace}: production exception ${ex.id} requires an applicability guard`,
      );
    }
  }
  for (const vuln of Object.values(audit.vulnerabilities || {})) {
    const severity = String(vuln.severity || "").toLowerCase();
    if (rank(severity) < rank("high")) continue;
    if (severity === "critical") {
      failures.push(
        `${workspace}: critical advisory ${vuln.name} is never allowlisted`,
      );
      continue;
    }
    const match = matchingException({
      vuln,
      workspace,
      lock,
      policy,
      audit,
      today,
    });
    if (match.expired) {
      if (match.expired.standing === true) {
        failures.push(
          `${workspace}: standing exception ${match.expired.id} expired at ${match.expired.expires_at}`,
        );
      }
      continue;
    }
    if (!match.active) {
      const scope = isDevOnly(vuln, lock)
        ? "dev-only"
        : "production-reachable or unknown scope";
      failures.push(
        `${workspace}: high advisory ${vuln.name} is ${scope} and has no active exception`,
      );
      continue;
    }
    usedExceptions.add(match.active.id);
    accepted.push(
      `${workspace}: accepted high advisory ${vuln.name} via ${match.active.id} until ${match.active.expires_at}`,
    );
  }
  for (const ex of policy.exceptions || []) {
    if (
      ex.workspace === workspace &&
      !(omitDev && ex.dev_only === true) &&
      Array.isArray(ex.advisories) &&
      ex.advisories.length > 0 &&
      !isExpired(ex.expires_at, today) &&
      ex.standing !== true &&
      !usedExceptions.has(ex.id)
    ) {
      failures.push(
        `${workspace}: exact advisory exception ${ex.id} matched no current advisory; remove it`,
      );
    }
  }
  return { failures, accepted };
}

function sampleAudit(
  name,
  severity,
  nodes = [`node_modules/${name}`],
  advisory = "GHSA-aaaa-bbbb-cccc",
  advisoryRange = ">=1.0.0 <2.0.0",
) {
  return {
    vulnerabilities: {
      [name]: {
        name,
        severity,
        via: [
          {
            source: 1000000,
            name,
            severity,
            url: `https://github.com/advisories/${advisory}`,
            range: advisoryRange,
          },
        ],
        nodes,
      },
    },
  };
}

function selftest() {
  const policy = {
    exceptions: [
      {
        id: "vite-dev",
        workspace: "web",
        packages: ["vite"],
        advisories: ["GHSA-aaaa-bbbb-cccc"],
        advisory_ranges: {
          "GHSA-aaaa-bbbb-cccc": [">=1.0.0 <2.0.0"],
        },
        versions: {
          vite: ["1.2.3"],
        },
        max_severity: "high",
        dev_only: true,
        expires_at: "2026-09-30",
      },
    ],
  };
  const devLock = {
    packages: { "node_modules/vite": { dev: true, version: "1.2.3" } },
  };
  const prodLock = {
    packages: { "node_modules/vite": { version: "1.2.3" } },
  };

  const pass = evaluate({
    audit: sampleAudit("vite", "high"),
    lock: devLock,
    policy,
    workspace: "web",
    today: "2026-06-19",
  });
  if (pass.failures.length !== 0 || pass.accepted.length !== 1)
    throw new Error(
      `selftest allow active dev exception failed: ${JSON.stringify(pass)}`,
    );

  const prod = evaluate({
    audit: sampleAudit("vite", "high"),
    lock: prodLock,
    policy,
    workspace: "web",
    today: "2026-06-19",
  });
  if (!prod.failures.some((f) => f.includes("no active exception")))
    throw new Error("selftest failed to reject production-scoped high");

  const expired = evaluate({
    audit: sampleAudit("vite", "high"),
    lock: devLock,
    policy,
    workspace: "web",
    today: "2026-10-01",
  });
  if (!expired.failures.some((f) => f.includes("expired")))
    throw new Error("selftest failed to reject expired exception");

  const critical = evaluate({
    audit: sampleAudit("vite", "critical"),
    lock: devLock,
    policy,
    workspace: "web",
    today: "2026-06-19",
  });
  if (!critical.failures.some((f) => f.includes("critical")))
    throw new Error("selftest failed to reject critical");

  const rscVia = {
    source: 1124282,
    name: "react-router",
    url: "https://github.com/advisories/GHSA-qwww-vcr4-c8h2",
    severity: "high",
    range: ">=7.12.0 <8.3.0",
  };
  const rscAudit = {
    vulnerabilities: {
      "react-router": {
        name: "react-router",
        severity: "high",
        via: [rscVia],
        nodes: ["node_modules/react-router"],
      },
      "react-router-dom": {
        name: "react-router-dom",
        severity: "high",
        via: ["react-router"],
        nodes: ["node_modules/react-router-dom"],
      },
    },
  };
  const rscPolicy = {
    exceptions: [
      {
        id: "react-router-rsc",
        workspace: "web",
        packages: ["react-router", "react-router-dom"],
        advisories: ["GHSA-qwww-vcr4-c8h2"],
        advisory_ranges: {
          "GHSA-qwww-vcr4-c8h2": [">=7.12.0 <8.3.0"],
        },
        versions: {
          "react-router": ["7.18.1"],
          "react-router-dom": ["7.18.1"],
        },
        max_severity: "high",
        dev_only: false,
        expires_at: "2026-08-31",
        guard: "scripts/check_web_router_mode.mjs",
      },
    ],
  };
  const rscLock = {
    packages: {
      "node_modules/react-router": { version: "7.18.1" },
      "node_modules/react-router-dom": { version: "7.18.1" },
    },
  };
  const rscPass = evaluate({
    audit: rscAudit,
    lock: rscLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (rscPass.failures.length !== 0 || rscPass.accepted.length !== 2) {
    throw new Error(
      `selftest exact transitive advisory exception failed: ${JSON.stringify(rscPass)}`,
    );
  }

  const extraAdvisoryAudit = structuredClone(rscAudit);
  extraAdvisoryAudit.vulnerabilities["react-router"].via.push({
    source: 9999999,
    name: "react-router",
    url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
    severity: "high",
    range: "<1.0.1",
  });
  const extraAdvisory = evaluate({
    audit: extraAdvisoryAudit,
    lock: rscLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (!extraAdvisory.failures.some((f) => f.includes("no active exception"))) {
    throw new Error(
      "selftest failed to reject an additional high advisory on an excepted package",
    );
  }

  const rangeDriftAudit = structuredClone(rscAudit);
  rangeDriftAudit.vulnerabilities["react-router"].via[0].range =
    ">=7.11.0 <8.3.0";
  const rangeDrift = evaluate({
    audit: rangeDriftAudit,
    lock: rscLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (!rangeDrift.failures.some((f) => f.includes("no active exception"))) {
    throw new Error(
      "selftest failed to reject affected-range drift on an excepted advisory",
    );
  }

  const versionBumpLock = structuredClone(rscLock);
  versionBumpLock.packages["node_modules/react-router"].version = "7.18.2";
  const versionBump = evaluate({
    audit: rscAudit,
    lock: versionBumpLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (!versionBump.failures.some((f) => f.includes("no active exception"))) {
    throw new Error(
      "selftest failed to reject an installed-version change on an excepted advisory",
    );
  }

  const rscExpired = evaluate({
    audit: rscAudit,
    lock: rscLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-09-01",
  });
  if (!rscExpired.failures.some((f) => f.includes("expired"))) {
    throw new Error(
      "selftest failed to reject expired exact advisory exception",
    );
  }

  const staleException = evaluate({
    audit: { vulnerabilities: {} },
    lock: rscLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (
    !staleException.failures.some((f) =>
      f.includes("matched no current advisory"),
    )
  ) {
    throw new Error(
      "selftest failed to reject an unused exact advisory exception",
    );
  }

  const standingPolicy = {
    exceptions: [
      {
        id: "brace-expansion-dev-only",
        workspace: "web",
        packages: ["brace-expansion"],
        advisories: ["GHSA-mh99-v99m-4gvg"],
        advisory_ranges: {
          "GHSA-mh99-v99m-4gvg": ["<=5.0.7"],
        },
        versions: {
          "brace-expansion": ["1.1.16"],
        },
        max_severity: "high",
        dev_only: true,
        standing: true,
        expires_at: "2026-09-30",
      },
    ],
  };
  const patchedBraceLock = {
    packages: {
      "node_modules/brace-expansion": { dev: true, version: "5.0.8" },
    },
  };
  const dormantStanding = evaluate({
    audit: { vulnerabilities: {} },
    lock: patchedBraceLock,
    policy: standingPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (dormantStanding.failures.length !== 0) {
    throw new Error(
      `selftest rejected a dormant dev-only standing exception: ${JSON.stringify(dormantStanding)}`,
    );
  }

  const affectedBraceAudit = sampleAudit(
    "brace-expansion",
    "high",
    ["node_modules/brace-expansion"],
    "GHSA-mh99-v99m-4gvg",
    "<=5.0.7",
  );
  const affectedBraceLock = {
    packages: {
      "node_modules/brace-expansion": { dev: true, version: "1.1.16" },
    },
  };
  const activeStanding = evaluate({
    audit: affectedBraceAudit,
    lock: affectedBraceLock,
    policy: standingPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (
    activeStanding.failures.length !== 0 ||
    activeStanding.accepted.length !== 1
  ) {
    throw new Error(
      `selftest rejected the exact active standing exception: ${JSON.stringify(activeStanding)}`,
    );
  }

  const changedBraceLock = structuredClone(affectedBraceLock);
  changedBraceLock.packages["node_modules/brace-expansion"].version = "1.1.17";
  const changedStanding = evaluate({
    audit: affectedBraceAudit,
    lock: changedBraceLock,
    policy: standingPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (
    !changedStanding.failures.some((failure) =>
      failure.includes("no active exception"),
    )
  ) {
    throw new Error(
      "selftest failed to reject an installed-version change on a standing exception",
    );
  }

  const malformedAudit = evaluate({
    audit: { error: { summary: "registry unavailable" } },
    lock: rscLock,
    policy: rscPolicy,
    workspace: "web",
    today: "2026-07-27",
  });
  if (!malformedAudit.failures.some((f) => f.includes("usable report"))) {
    throw new Error("selftest failed to reject an unusable npm audit report");
  }

  const renewedPolicy = {
    exceptions: [
      { ...policy.exceptions[0], id: "vite-expired", expires_at: "2026-01-01" },
      { ...policy.exceptions[0], id: "vite-renewed", expires_at: "2026-09-30" },
    ],
  };
  const renewed = evaluate({
    audit: sampleAudit("vite", "high"),
    lock: devLock,
    policy: renewedPolicy,
    workspace: "web",
    today: "2026-06-19",
  });
  if (!renewed.failures.some((line) => line.includes("vite-expired"))) {
    throw new Error("selftest failed to reject a stale expired policy entry");
  }

  const cleanRenewed = evaluate({
    audit: sampleAudit("vite", "high"),
    lock: devLock,
    policy: { exceptions: [renewedPolicy.exceptions[1]] },
    workspace: "web",
    today: "2026-06-19",
  });
  if (
    cleanRenewed.failures.length !== 0 ||
    !cleanRenewed.accepted.some((line) => line.includes("vite-renewed"))
  ) {
    throw new Error("selftest failed to accept a clean renewed exception");
  }

  const productionOnly = evaluate({
    audit: { vulnerabilities: {} },
    lock: devLock,
    policy,
    workspace: "web",
    omitDev: true,
    today: "2026-06-19",
  });
  if (productionOnly.failures.length !== 0) {
    throw new Error(
      `selftest production scope did not ignore dev-only exceptions: ${JSON.stringify(productionOnly)}`,
    );
  }

  try {
    evaluate({
      audit: sampleAudit("vite", "high"),
      lock: devLock,
      policy,
      workspace: "web",
      today: "2026-02-31",
    });
    throw new Error("selftest failed to reject impossible date");
  } catch (err) {
    if (!String(err.message || err).includes("real UTC calendar date"))
      throw err;
  }

  console.log("npm audit policy selftest: OK");
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.selftest) {
    selftest();
    return;
  }
  for (const key of ["workspace", "audit", "lock", "policy"]) {
    if (!args[key]) throw new Error(`${usage()}\nmissing --${key}`);
  }
  const result = evaluate({
    audit: readJSON(args.audit),
    lock: readJSON(args.lock),
    policy: readJSON(args.policy),
    workspace: args.workspace,
    omitDev: args.omitDev === true,
  });
  for (const line of result.accepted) {
    console.warn(`npm audit policy: ${line}`);
  }
  if (result.failures.length > 0) {
    for (const line of result.failures) {
      console.error(`npm audit policy: ${line}`);
    }
    process.exit(1);
  }
  console.log("npm audit policy: OK");
}

main();
