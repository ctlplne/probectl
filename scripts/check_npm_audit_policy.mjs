#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0

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

function advisoryIDs(vuln, audit, seen = new Set()) {
  if (!vuln || typeof vuln !== "object") return [];
  const key = String(vuln.name || "");
  if (key && seen.has(key)) return [];
  const nextSeen = new Set(seen);
  if (key) nextSeen.add(key);

  const ids = new Set();
  for (const via of Array.isArray(vuln.via) ? vuln.via : []) {
    if (typeof via === "string") {
      for (const id of advisoryIDs(
        audit.vulnerabilities?.[via],
        audit,
        nextSeen,
      )) {
        ids.add(id);
      }
      continue;
    }
    const id = rank(via.severity) >= rank("high") ? advisoryID(via) : "";
    if (id) ids.add(id);
  }
  return [...ids].sort();
}

function sameStrings(left, right) {
  const a = [...new Set(left || [])].sort();
  const b = [...new Set(right || [])].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function matchingException({ vuln, workspace, lock, policy, audit, today }) {
  const name = vuln.name;
  const severity = String(vuln.severity || "").toLowerCase();
  const observedAdvisories = advisoryIDs(vuln, audit);
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
    if (isExpired(ex.expires_at, today)) {
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
        max_severity: "high",
        dev_only: true,
        expires_at: "2026-09-30",
      },
    ],
  };
  const devLock = { packages: { "node_modules/vite": { dev: true } } };
  const prodLock = { packages: { "node_modules/vite": {} } };

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
        max_severity: "high",
        dev_only: false,
        expires_at: "2026-08-31",
        guard: "scripts/check_web_router_mode.mjs",
      },
    ],
  };
  const rscLock = {
    packages: {
      "node_modules/react-router": {},
      "node_modules/react-router-dom": {},
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
