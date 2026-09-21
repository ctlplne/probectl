/* SPDX-License-Identifier: BUSL-1.1 */

/*
 * Every design value resolves to a custom property from styles/tokens.css, so
 * the deployment-level operator theme stays a runtime override rather than a
 * rebuild (CLAUDE.md §2 — theming is deployment-level design tokens).
 *
 * The vocabulary is the ctlplne studio's, shared with trstctl's console and
 * probectl's website. The lane colours are probectl's OWN four nav groups, and
 * the chart/viz entries have no studio equivalent: probectl is a data product,
 * and the dash patterns exist so hue never carries unique meaning.
 */

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Every colour carries `/ <alpha-value>` so opacity utilities work —
        // e.g. bg-brand-accent/10 for the soft-tint pills and rows.
        border: 'hsl(var(--border) / <alpha-value>)',
        background: 'hsl(var(--background) / <alpha-value>)',
        foreground: 'hsl(var(--foreground) / <alpha-value>)',
        muted: {
          DEFAULT: 'hsl(var(--muted) / <alpha-value>)',
          foreground: 'hsl(var(--muted-foreground) / <alpha-value>)',
        },
        primary: {
          DEFAULT: 'hsl(var(--primary) / <alpha-value>)',
          foreground: 'hsl(var(--primary-foreground) / <alpha-value>)',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive) / <alpha-value>)',
          foreground: 'hsl(var(--destructive-foreground) / <alpha-value>)',
        },
        card: {
          DEFAULT: 'hsl(var(--card) / <alpha-value>)',
          foreground: 'hsl(var(--card-foreground) / <alpha-value>)',
        },
        brand: {
          accent: 'hsl(var(--brand-accent) / <alpha-value>)',
          foreground: 'hsl(var(--brand-accent-foreground) / <alpha-value>)',
        },
        focus: 'hsl(var(--focus) / <alpha-value>)',
        sidebar: {
          DEFAULT: 'hsl(var(--sidebar) / <alpha-value>)',
          hover: 'hsl(var(--sidebar-hover) / <alpha-value>)',
          active: 'hsl(var(--sidebar-active) / <alpha-value>)',
          foreground: 'hsl(var(--sidebar-foreground) / <alpha-value>)',
        },
        // probectl's four nav groups (nav/ia.ts), not trstctl's cert-ops lanes.
        monitor: {
          DEFAULT: 'hsl(var(--monitor) / <alpha-value>)',
          foreground: 'hsl(var(--monitor-foreground) / <alpha-value>)',
        },
        analyze: {
          DEFAULT: 'hsl(var(--analyze) / <alpha-value>)',
          foreground: 'hsl(var(--analyze-foreground) / <alpha-value>)',
        },
        secure: {
          DEFAULT: 'hsl(var(--secure) / <alpha-value>)',
          foreground: 'hsl(var(--secure-foreground) / <alpha-value>)',
        },
        operate: {
          DEFAULT: 'hsl(var(--operate) / <alpha-value>)',
          foreground: 'hsl(var(--operate-foreground) / <alpha-value>)',
        },
        risk: {
          critical: 'hsl(var(--risk-critical) / <alpha-value>)',
          high: 'hsl(var(--risk-high) / <alpha-value>)',
          medium: 'hsl(var(--risk-medium) / <alpha-value>)',
          low: 'hsl(var(--risk-low) / <alpha-value>)',
          none: 'hsl(var(--risk-none) / <alpha-value>)',
        },
        status: {
          success: 'hsl(var(--status-success) / <alpha-value>)',
          warning: 'hsl(var(--status-warning) / <alpha-value>)',
          neutral: 'hsl(var(--status-neutral) / <alpha-value>)',
          info: 'hsl(var(--status-info) / <alpha-value>)',
        },
        // Data-viz: probectl-only. Series also carry dash patterns.
        chart: {
          1: 'hsl(var(--chart-1) / <alpha-value>)',
          2: 'hsl(var(--chart-2) / <alpha-value>)',
          3: 'hsl(var(--chart-3) / <alpha-value>)',
          4: 'hsl(var(--chart-4) / <alpha-value>)',
          5: 'hsl(var(--chart-5) / <alpha-value>)',
          6: 'hsl(var(--chart-6) / <alpha-value>)',
          grid: 'hsl(var(--chart-grid) / <alpha-value>)',
          axis: 'hsl(var(--chart-axis) / <alpha-value>)',
          neutral: 'hsl(var(--chart-neutral) / <alpha-value>)',
        },
      },
      fontFamily: {
        // Sora for UI text, DM Mono only for machine data, Syne only for the
        // wordmark or a rare brand moment.
        sans: ['var(--font-sans)'],
        mono: ['var(--font-mono)'],
        display: ['var(--font-display)'],
      },
      fontSize: {
        caption: ['var(--font-size-caption)', { lineHeight: 'var(--line-height-caption)' }],
        data: ['var(--font-size-data)', { lineHeight: 'var(--line-height-data)' }],
        body: ['var(--font-size-body)', { lineHeight: 'var(--line-height-body)' }],
        title: ['var(--font-size-title)', { lineHeight: 'var(--line-height-title)' }],
        heading: ['var(--font-size-heading)', { lineHeight: 'var(--line-height-heading)' }],
        display: ['var(--font-size-display)', { lineHeight: 'var(--line-height-display)' }],
      },
      borderRadius: {
        control: 'var(--radius-control)',
        panel: 'var(--radius-panel)',
        pill: 'var(--radius-pill)',
      },
      boxShadow: {
        elevation1: 'var(--elevation-1)',
        elevation2: 'var(--elevation-2)',
        elevation3: 'var(--elevation-3)',
      },
      spacing: {
        comfortable: 'var(--density-comfortable)',
        'panel-padding': 'var(--density-panel-padding)',
        'cell-block': 'var(--density-table-cell-block)',
        'cell-inline': 'var(--density-table-cell-inline)',
      },
      minWidth: {
        // The same coarse-pointer target as minHeight.touch: a control may not
        // shrink below a hittable size on either axis (WCAG 2.5.8).
        touch: 'var(--density-touch-target)',
      },
      height: {
        control: 'var(--density-control-block)',
        'control-sm': 'var(--density-control-block-sm)',
        row: 'var(--density-row-block)',
        topbar: 'var(--layout-topbar-height)',
      },
      minHeight: {
        touch: 'var(--density-touch-target)',
      },
      width: {
        sidebar: 'var(--layout-sidebar-width)',
      },
      maxWidth: {
        content: 'var(--layout-content-max)',
      },
      zIndex: {
        sticky: 'var(--z-sticky)',
        overlay: 'var(--z-overlay)',
        modal: 'var(--z-modal)',
        toast: 'var(--z-toast)',
      },
      transitionDuration: {
        fast: 'var(--motion-fast)',
        base: 'var(--motion-base)',
        slow: 'var(--motion-slow)',
      },
      transitionTimingFunction: {
        standard: 'var(--easing-standard)',
        emphasized: 'var(--easing-emphasized)',
      },
      letterSpacing: {
        tight: 'var(--tracking-tight)',
        snug: 'var(--tracking-snug)',
        wide: 'var(--tracking-wide)',
        wider: 'var(--tracking-wider)',
      },
      keyframes: {
        'overlay-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'panel-in': {
          // Panel motion stays on opacity. A transform here replaces utility
          // transforms such as -translate-x-1/2 after animation fill, which
          // moves a centered dialog halfway off-screen in a real browser.
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        'drawer-in': {
          from: { opacity: '0', transform: 'translateX(24px)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
      },
      animation: {
        'overlay-in': 'overlay-in var(--motion-fast) ease-out both',
        'panel-in': 'panel-in var(--motion-base) var(--easing-emphasized) both',
        'drawer-in': 'drawer-in var(--motion-base) var(--easing-emphasized) both',
      },
    },
  },
  plugins: [],
}
