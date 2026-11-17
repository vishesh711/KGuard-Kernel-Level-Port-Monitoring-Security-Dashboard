import colors from 'tailwindcss/colors'

/*
 * Dark security-console theme.
 *
 * The pages use Tailwind's usual light-theme classes (bg-gray-50, text-gray-900,
 * bg-red-100 text-red-800, ...). Instead of rewriting every class, the scales are
 * redefined for a dark background: low numbers are dark, high numbers are light.
 *   gray:   50 page, 100 raised/hover, 200 borders, 300 input borders,
 *           400-600 muted text, 700-900 body text and headings
 *   colour: 50-200 dark tints (backgrounds, borders), 300-600 the colour itself,
 *           700-950 light tints (text on a tinted background)
 */

const PAGE = '#0a0f1a'

function mix(hex, base, amount) {
  const parse = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16))
  const [a, b] = [parse(hex), parse(base)]
  return '#' + a.map((v, i) => Math.round(v * amount + b[i] * (1 - amount)).toString(16).padStart(2, '0')).join('')
}

function dark(scale) {
  return {
    50: mix(scale[500], PAGE, 0.1),
    100: mix(scale[500], PAGE, 0.18),
    200: mix(scale[500], PAGE, 0.32),
    300: scale[400],
    400: scale[400],
    500: scale[500],
    600: scale[500],
    700: scale[300],
    800: scale[200],
    900: scale[100],
    950: scale[50],
  }
}

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        page: PAGE,
        surface: '#101827',
        sunken: '#0d1422',
        gray: {
          50: '#0d1422',
          100: '#162033',
          200: '#1f2b40',
          300: '#2c3a52',
          400: '#5f6f87',
          500: '#8292a9',
          600: '#9aa8bc',
          700: '#c2cbd8',
          800: '#dbe2ec',
          900: '#eef2f7',
          950: '#ffffff',
        },
        red: dark(colors.red),
        orange: dark(colors.orange),
        amber: dark(colors.amber),
        yellow: dark(colors.amber),
        green: dark(colors.emerald),
        emerald: dark(colors.emerald),
        blue: dark(colors.sky),
        sky: dark(colors.sky),
        indigo: dark(colors.indigo),
        purple: dark(colors.violet),
        violet: dark(colors.violet),
        primary: dark(colors.sky),
        danger: dark(colors.red),
        warning: dark(colors.amber),
        success: dark(colors.emerald),
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
