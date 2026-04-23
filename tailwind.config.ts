import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'monospace'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'monospace'],
      },
      colors: {
        ink: {
          50: '#edf1f4',
          100: '#d8e0e4',
          200: '#b2c0c8',
          300: '#879ba6',
          400: '#657780',
          500: '#46575f',
          600: '#344148',
          700: '#273137',
          800: '#1b2328',
          900: '#11171b',
          950: '#080b0e',
        },
        accent: {
          50: '#e8fbff',
          100: '#c9f5ff',
          200: '#96ebff',
          300: '#5ddcff',
          400: '#23c9f1',
          500: '#00acd4',
          600: '#008aa9',
          700: '#087088',
          800: '#0d596b',
          900: '#0d4858',
        },
        amber: {
          300: '#f5c76a',
          400: '#e8aa34',
          500: '#c88418',
        },
      },
      boxShadow: {
        glow: '0 0 60px -18px rgb(35 201 241 / 0.55)',
      },
      backgroundImage: {
        'hero-grad':
          'radial-gradient(ellipse at top, rgb(35 201 241 / 0.18), transparent 60%), radial-gradient(ellipse at bottom, rgb(232 170 52 / 0.08), transparent 65%)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
} satisfies Config;
