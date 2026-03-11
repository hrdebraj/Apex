/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        apex: {
          bg: "#0a0a0f",
          surface: "#12121a",
          panel: "#1a1a26",
          border: "#2a2a3a",
          hover: "#252535",
          accent: "#00d4aa",
          "accent-dim": "#00a88a",
          danger: "#ff4d6a",
          warning: "#ffaa00",
          text: "#e4e4ef",
          muted: "#6e6e8a",
        },
      },
      fontFamily: {
        sans: ['"Inter"', '"SF Pro Display"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Fira Code"', "monospace"],
      },
    },
  },
  plugins: [],
};
