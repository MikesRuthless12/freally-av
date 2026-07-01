import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    // Restrict the spacing scale per PRD § 9. By replacing `theme.spacing`
    // (instead of extending it) we drop Tailwind's default 0.5/1.5/2.5/...
    // half-steps and the 7/9/11/13/... odd values entirely. The only
    // permitted scale is the one below.
    spacing: {
      0: "0",
      px: "1px",
      1: "4px",
      2: "8px",
      3: "12px",
      4: "16px",
      5: "20px",
      6: "24px",
      8: "32px",
      10: "40px",
      14: "56px",
      20: "80px",
    },
    borderRadius: {
      none: "0",
      sm: "var(--myth-radius-sm)",
      DEFAULT: "var(--myth-radius-md)",
      md: "var(--myth-radius-md)",
      lg: "var(--myth-radius-lg)",
    },
    fontFamily: {
      display: "var(--myth-font-display)",
      sans: "var(--myth-font-ui)",
      mono: "var(--myth-font-mono)",
    },
    extend: {
      colors: {
        myth: {
          "bg-0": "var(--myth-bg-0)",
          "bg-1": "var(--myth-bg-1)",
          "bg-2": "var(--myth-bg-2)",
          line: "var(--myth-line)",
          "text-hi": "var(--myth-text-hi)",
          "text-md": "var(--myth-text-md)",
          "text-lo": "var(--myth-text-lo)",
          accent: "var(--myth-accent)",
          "accent-hi": "var(--myth-accent-hi)",
          ok: "var(--myth-ok)",
          warn: "var(--myth-warn)",
          bad: "var(--myth-bad)",
          "mono-bg": "var(--myth-mono-bg)",
        },
      },
      boxShadow: {
        none: "var(--myth-shadow-none)",
      },
    },
  },
  plugins: [],
};

export default config;
