#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const defaultRepoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceExtensions = new Set([".js", ".jsx", ".mjs", ".ts", ".tsx"]);
const forbiddenDependencies = [
  "@react-router/dev",
  "@vitejs/plugin-rsc",
  "react-server-dom-webpack",
  "react-server-dom-parcel",
  "react-server-dom-turbopack",
];
const forbiddenSourcePatterns = [
  {
    label: "React Router unstable RSC API",
    pattern:
      /\bunstable_(?:matchRSCServerRequest|routeRSCServerRequest|RSCStaticRouter|RSCHydratedRouter|createCallServer|getRSCStream|RSC[A-Za-z0-9_]*)\b/,
  },
  {
    label: "RSC build/runtime package",
    pattern: /@vitejs\/plugin-rsc|@react-router\/dev|react-server-dom-[a-z-]+/,
  },
  {
    label: "server-action module directive",
    pattern: /(?:^|\n)\s*["']use server["']\s*;?/,
  },
  {
    label: "React Router react-server-client internal entrypoint",
    pattern: /react-router(?:-dom)?\/internal\/react-server-client/,
  },
];

function usage() {
  return [
    "usage: node scripts/check_web_router_mode.mjs [--root <repo-root>]",
    "       node scripts/check_web_router_mode.mjs --selftest",
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
    if (arg !== "--root")
      throw new Error(`${usage()}\nunexpected argument: ${arg}`);
    const value = argv[++i];
    if (!value || value.startsWith("--"))
      throw new Error(`${usage()}\nmissing value for --root`);
    args.root = value;
  }
  return args;
}

function sourceFiles(root) {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (sourceExtensions.has(extname(entry.name))) {
        files.push(path);
      }
    }
  };
  walk(join(root, "web", "src"));
  for (const path of [
    join(root, "web", "vite.config.ts"),
    join(root, "web", "vite.config.js"),
  ]) {
    if (existsSync(path)) files.push(path);
  }
  return files;
}

function inspect({ packageJSON, files }) {
  const violations = [];
  const dependencies = {
    ...(packageJSON.dependencies || {}),
    ...(packageJSON.devDependencies || {}),
    ...(packageJSON.optionalDependencies || {}),
  };
  for (const name of forbiddenDependencies) {
    if (Object.hasOwn(dependencies, name)) {
      violations.push(`forbidden RSC dependency ${name}`);
    }
  }

  let browserRouterImport = false;
  let browserRouterElement = false;
  for (const [name, contents] of files) {
    if (/(?:^|\/)entry\.rsc\.[cm]?[jt]sx?$/.test(name)) {
      violations.push(`${name}: RSC entrypoint`);
    }
    if (
      /import\s*\{[^}]*\bBrowserRouter\b[^}]*\}\s*from\s*["']react-router-dom["']/.test(
        contents,
      )
    ) {
      browserRouterImport = true;
    }
    if (/<BrowserRouter(?:\s|>)/.test(contents)) browserRouterElement = true;
    for (const { label, pattern } of forbiddenSourcePatterns) {
      if (pattern.test(contents)) violations.push(`${name}: ${label}`);
    }
  }
  if (!browserRouterImport || !browserRouterElement) {
    violations.push(
      "web/src must remain an explicit client-only BrowserRouter SPA",
    );
  }
  return violations;
}

function inspectRepo(root) {
  const packageJSON = JSON.parse(
    readFileSync(join(root, "web", "package.json"), "utf8"),
  );
  const files = sourceFiles(root).map((path) => [
    relative(root, path),
    readFileSync(path, "utf8"),
  ]);
  return inspect({ packageJSON, files });
}

function selftest() {
  const safe = {
    packageJSON: {
      dependencies: {
        react: "18.3.1",
        "react-router-dom": "7.18.1",
      },
    },
    files: [
      [
        "web/src/App.tsx",
        'import { BrowserRouter } from "react-router-dom";\nexport const App = () => <BrowserRouter />;',
      ],
    ],
  };
  if (inspect(safe).length !== 0)
    throw new Error("selftest rejected the client-only BrowserRouter fixture");

  const rscSymbol = structuredClone(safe);
  rscSymbol.files.push([
    "web/src/entry.rsc.tsx",
    'import { unstable_matchRSCServerRequest } from "react-router";',
  ]);
  if (!inspect(rscSymbol).some((line) => line.includes("unstable RSC API"))) {
    throw new Error("selftest failed to reject a planted React Router RSC API");
  }

  const serverAction = structuredClone(safe);
  serverAction.files.push([
    "web/src/action.ts",
    '"use server";\nexport function mutate() {}',
  ]);
  if (!inspect(serverAction).some((line) => line.includes("server-action"))) {
    throw new Error("selftest failed to reject a planted server action");
  }

  const rscDependency = structuredClone(safe);
  rscDependency.packageJSON.devDependencies = { "@vitejs/plugin-rsc": "0.5.1" };
  if (
    !inspect(rscDependency).some((line) =>
      line.includes("forbidden RSC dependency"),
    )
  ) {
    throw new Error("selftest failed to reject a planted RSC dependency");
  }

  console.log("web router mode selftest: OK (planted RSC paths rejected)");
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.selftest) {
    selftest();
    return;
  }
  const violations = inspectRepo(args.root || defaultRepoRoot);
  if (violations.length > 0) {
    for (const violation of violations) {
      console.error(`web router mode: ${violation}`);
    }
    process.exit(1);
  }
  console.log(
    "web router mode: OK (client-only BrowserRouter; no RSC/server-action path)",
  );
}

main();
