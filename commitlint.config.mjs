// commitlint configuration enforcing Conventional Commits (CLAUDE.md §6).
//
// Format:  type(scope): subject
// Every PR references its sprint + requirement IDs, e.g.
//   feat(canary): ICMP network test [S7, F2]
//
// Rules are inlined (no `extends`) so CI needs no extra config packages.
export default {
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "docs",
        "chore",
        "test",
        "refactor",
        "perf",
        "build",
        "ci",
        "style",
        "revert",
      ],
    ],
    "type-case": [2, "always", "lower-case"],
    "type-empty": [2, "never"],
    "subject-empty": [2, "never"],
    "subject-full-stop": [2, "never", "."],
    "header-max-length": [2, "always", 100],
  },
};
