import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter"', '"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "Menlo", "Monaco", "Consolas", "monospace"],
      },
      colors: {
        bg: "var(--bg)",
        surface: "var(--surface)",
        "surface-muted": "var(--surface-muted)",
        field: "var(--field)",
        fg: "var(--fg)",
        muted: "var(--muted)",
        faint: "var(--faint)",
        border: "var(--border)",
        accent: "var(--accent)",
      },
    },
  },
  plugins: [],
};

export default config;
