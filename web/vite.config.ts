/// <reference types="vitest" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:7878",
    },
  },
  build: {
    outDir: "dist",
    // Never inline assets as data: URIs - the console's CSP (default-src 'self') refuses them.
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.tsx", "src/**/*.test.ts"],
  },
});
