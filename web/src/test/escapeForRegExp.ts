// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// js/incomplete-sanitization (CodeQL #1, #14, #27): an escape of only `[[\]'.]`
// misses ( ) * + ? { } | ^ $ - and backslash, so a selector containing any of
// them builds a regex that silently matches the wrong declaration block — a
// token test that passes while testing nothing. Every test that turns a CSS
// selector into a pattern uses this one helper.
export const escapeForRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')
