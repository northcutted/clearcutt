/** @type {import('tailwindcss').Config} */
//
// Colors are driven by CSS custom properties defined in src/styles/global.css.
// `:root` carries the light palette; `.dark` overrides for dark mode. This
// lets every existing utility class (`bg-ink-900`, `text-ink-100`, etc.) flip
// automatically when the `dark` class is toggled on `<html>`.
//
// RGB triples (no `rgb(...)` wrapper) are required so Tailwind's alpha
// modifiers (e.g. `bg-ink-800/60`) keep working.

export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        ink: {
          950: 'rgb(var(--ink-950) / <alpha-value>)',
          900: 'rgb(var(--ink-900) / <alpha-value>)',
          800: 'rgb(var(--ink-800) / <alpha-value>)',
          700: 'rgb(var(--ink-700) / <alpha-value>)',
          600: 'rgb(var(--ink-600) / <alpha-value>)',
          500: 'rgb(var(--ink-500) / <alpha-value>)',
          400: 'rgb(var(--ink-400) / <alpha-value>)',
          300: 'rgb(var(--ink-300) / <alpha-value>)',
          200: 'rgb(var(--ink-200) / <alpha-value>)',
          100: 'rgb(var(--ink-100) / <alpha-value>)',
          50:  'rgb(var(--ink-50)  / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--accent)      / <alpha-value>)',
          soft:    'rgb(var(--accent-soft) / <alpha-value>)',
          deep:    'rgb(var(--accent-deep) / <alpha-value>)',
          glow:    'rgb(var(--accent-glow) / <alpha-value>)',
        },
        link: {
          DEFAULT: 'rgb(var(--link)       / <alpha-value>)',
          hover:   'rgb(var(--link-hover) / <alpha-value>)',
        },
        warn:   'rgb(var(--warn)   / <alpha-value>)',
        danger: 'rgb(var(--danger) / <alpha-value>)',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'Inter', 'system-ui', 'sans-serif'],
        sans: ['"Inter Variable"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 0 1px rgb(var(--accent) / 0.18), 0 8px 36px -12px rgb(var(--accent) / 0.32)',
      },
    },
  },
  plugins: [],
};
