/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#070b0a',
          900: '#0c1413',
          800: '#111c1a',
          700: '#172622',
          600: '#1f322d',
          500: '#2a4239',
          400: '#3b5d51',
          300: '#5c8676',
          200: '#9ebaa9',
          100: '#d6e3da',
          50:  '#eef4ef',
        },
        accent: {
          DEFAULT: '#3ddc97',
          soft: '#a4f5cf',
          deep: '#0f9d6e',
          glow: '#9ff7c2',
        },
        warn: '#f6c177',
        danger: '#ef6f6c',
      },
      fontFamily: {
        sans: ['"Inter Variable"', '"Inter"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(61,220,151,0.18), 0 8px 36px -12px rgba(61,220,151,0.28)',
      },
    },
  },
  plugins: [],
};
