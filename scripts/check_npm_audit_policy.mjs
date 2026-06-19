#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
    "usage: node scripts/check_npm_audit_policy.mjs --workspace <name> --audit <npm-audit.json> --lock <package-lock.json> --policy <policy.json>",
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
    if (!arg.startsWith("--")) throw new Error(`${usage()}\nunexpected argument: ${arg}`);
    const key = arg.slice(2);
    const value = argv[++i];
    if (!value || value.startsWith("--")) throw new Error(`${usage()}\nmissing value for ${arg}`);
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
    throw new Error(`${field} must be YYYY-MM-DD, got ${JSON.stringify(value)}`);
  }
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  if (Number.isNaN(timestamp) || new Date(timestamp).toISOString().slice(0, 10) !== value) {
    throw new Error(`${field} must be a real UTC calendar date, got ${JSON.stringify(value)}`);
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

function matchingException({ vuln, workspace, lock, policy, today }) {
  const name = vuln.name;
  const severity = String(vuln.severity || "").toLowerCase();
  const matches = (policy.exceptions || []).filter((ex) => {
    return ex.workspace === workspace && (ex.packages || []).includes(name);
  });
  const expired = [];
  for (const ex of matches) {
    if (rank(severity) > rank(ex.max_severity)) continue;
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

function evaluate({ audit, lock, policy, workspace, today = todayUTC() }) {
  const failures = [];
  const accepted = [];
  for (const vuln of Object.values(audit.vulnerabilities || {})) {
    const severity = String(vuln.severity || "").toLowerCase();
    if (rank(severity) < rank("high")) continue;
    if (severity === "critical") {
      failures.push(`${workspace}: critical advisory ${vuln.name} is never allowlisted`);
      continue;
    }
    const match = matchingException({ vuln, workspace, lock, policy, today });
    if (match.expired) {
      failures.push(`${workspace}: high advisory ${vuln.name} exception ${match.expired.id} expired at ${match.expired.expires_at}`);
      continue;
    }
    if (!match.active) {
      const scope = isDevOnly(vuln, lock) ? "dev-only" : "production-reachable or unknown scope";
      failures.push(`${workspace}: high advisory ${vuln.name} is ${scope} and has no active exception`);
      continue;
    }
    accepted.push(`${workspace}: accepted high advisory ${vuln.name} via ${match.active.id} until ${match.active.expires_at}`);
  }
  return { failures, accepted };
}

function sampleAudit(name, severity, nodes = [`node_modules/${name}`]) {
  return {
    vulnerabilities: {
      [name]: {
        name,
        severity,
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
        max_severity: "high",
        dev_only: true,
        expires_at: "2026-09-30",
      },
    ],
  };
  const devLock = { packages: { "node_modules/vite": { dev: true } } };
  const prodLock = { packages: { "node_modules/vite": {} } };

  const pass = evaluate({ audit: sampleAudit("vite", "high"), lock: devLock, policy, workspace: "web", today: "2026-06-19" });
  if (pass.failures.length !== 0 || pass.accepted.length !== 1) throw new Error(`selftest allow active dev exception failed: ${JSON.stringify(pass)}`);

  const prod = evaluate({ audit: sampleAudit("vite", "high"), lock: prodLock, policy, workspace: "web", today: "2026-06-19" });
  if (!prod.failures.some((f) => f.includes("no active exception"))) throw new Error("selftest failed to reject production-scoped high");

  const expired = evaluate({ audit: sampleAudit("vite", "high"), lock: devLock, policy, workspace: "web", today: "2026-10-01" });
  if (!expired.failures.some((f) => f.includes("expired"))) throw new Error("selftest failed to reject expired exception");

  const critical = evaluate({ audit: sampleAudit("vite", "critical"), lock: devLock, policy, workspace: "web", today: "2026-06-19" });
  if (!critical.failures.some((f) => f.includes("critical"))) throw new Error("selftest failed to reject critical");

  const renewedPolicy = {
    exceptions: [
      { ...policy.exceptions[0], id: "vite-expired", expires_at: "2026-01-01" },
      { ...policy.exceptions[0], id: "vite-renewed", expires_at: "2026-09-30" },
    ],
  };
  const renewed = evaluate({ audit: sampleAudit("vite", "high"), lock: devLock, policy: renewedPolicy, workspace: "web", today: "2026-06-19" });
  if (renewed.failures.length !== 0 || !renewed.accepted.some((line) => line.includes("vite-renewed"))) {
    throw new Error("selftest failed to accept renewed exception after expired entry");
  }

  try {
    evaluate({ audit: sampleAudit("vite", "high"), lock: devLock, policy, workspace: "web", today: "2026-02-31" });
    throw new Error("selftest failed to reject impossible date");
  } catch (err) {
    if (!String(err.message || err).includes("real UTC calendar date")) throw err;
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
