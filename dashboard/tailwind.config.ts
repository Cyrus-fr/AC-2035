import type { Config } from 'tailwindcss';

// Every custom CSS variable (defined in src/index.css) is mapped to a
// Tailwind utility here so components use bg-base / text-cyan /
// shadow-glow-red etc. and never hardcode a hex value.
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: 'var(--bg-base)',
        surface: 'var(--bg-surface)',
        elevated: 'var(--bg-elevated)',
        overlay: 'var(--bg-overlay)',
        border: 'var(--border)',
        'border-glow': 'var(--border-glow)',
        cyan: 'var(--accent-cyan)',
        purple: 'var(--accent-purple)',
        green: 'var(--accent-green)',
        red: 'var(--accent-red)',
        amber: 'var(--accent-amber)',
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        dim: 'var(--text-dim)',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': 'var(--glow-cyan)',
        'glow-red': 'var(--glow-red)',
        'glow-green': 'var(--glow-green)',
        'glow-purple': 'var(--glow-purple)',
        'glow-amber': '0 0 20px rgba(255, 170, 0, 0.35)',
      },
    },
  },
  plugins: [],
} satisfies Config;
