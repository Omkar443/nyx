/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f5f5f5',
          100: '#e5e5e5',
          200: '#cccccc',
          300: '#999999',
          400: '#666666',
          500: '#2a2a2a',
          600: '#1c1c1c',
          700: '#141414',
          800: '#0a0a0a',
          900: '#000000',
        },
        accent: {
          50: '#fdf8ed',
          100: '#fbf1db',
          200: '#f7e3b7',
          300: '#f3d593',
          400: '#efc76f',
          500: '#ebb94b',
          600: '#d4a73a',
          700: '#b8912f',
          800: '#9c7a24',
          900: '#806319',
        },
        status: {
          live: '#00e676',
          connecting: '#ff9100',
          error: '#ff1744',
        },
        surface: {
          primary: '#141414',
          secondary: '#1c1c1c',
          tertiary: '#0a0a0a',
          glass: 'rgba(255, 255, 255, 0.03)',
          'glass-hover': 'rgba(255, 255, 255, 0.06)',
        },
        border: {
          DEFAULT: '#2a2a2a',
          card: '#2a2a2a',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      backgroundImage: {
        'gradient-military': 'linear-gradient(145deg, #000000 0%, #0a0a0a 50%, #141414 100%)',
        'gradient-card': 'linear-gradient(135deg, #1c1c1c 0%, #141414 100%)',
        'gradient-gold': 'linear-gradient(90deg, #ebb94b, #f3d593, #ebb94b)',
      },
    },
  },
  plugins: [],
};
