/* SPDX-License-Identifier: BUSL-1.1 */
import tailwindcss from '@tailwindcss/postcss'

export default {
  plugins: [
    tailwindcss(),
    {
      postcssPlugin: 'probectl-token-opacity',
      Declaration(declaration) {
        // Mixing a single token color with transparent changes only its alpha.
        // Keep that equivalent form measurable by the pinned contrast checker.
        // Arbitrary color mixes and variable percentages remain untouched.
        const match =
          /^color-mix\(\s*in\s+oklab,\s*hsl\(var\((--[a-z0-9-]+)\)\)\s+(\d+(?:\.\d+)?)%,\s*transparent\s*\)$/.exec(
            declaration.value,
          )
        if (match && Number(match[2]) <= 100) {
          declaration.value = `hsl(var(${match[1]}) / ${match[2]}%)`
        }
      },
    },
  ],
}
