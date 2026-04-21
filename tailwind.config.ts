import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        ink: {
          50: '#f5f7fb',
          100: '#e7ecf5',
          200: '#c8d2e6',
          300: '#9aabcc',
          400: '#6a7fae',
          500: '#4a608f',
          600: '#334872',
          700: '#253456',
          800: '#182340',
          900: '#0c1430',
          950: '#060a1e',
        },
        accent: {
          50: '#eef3ff',
          100: '#dce7ff',
          200: '#bfd1ff',
          300: '#93b1ff',
          400: '#6084ff',
          500: '#3a5bff',
          600: '#233ef0',
          700: '#1a2dc4',
          800: '#16289a',
          900: '#15267a',
        },
      },
      boxShadow: {
        glow: '0 0 60px -12px rgb(58 91 255 / 0.45)',
      },
      backgroundImage: {
        'hero-grad':
          'radial-gradient(ellipse at top, rgb(35 62 240 / 0.25), transparent 60%), radial-gradient(ellipse at bottom, rgb(147 177 255 / 0.12), transparent 60%)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
} satisfies Config;
