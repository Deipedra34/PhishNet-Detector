import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API server the dev server forwards /api requests to (see README.md).
const apiTarget = process.env.PHISHNET_API_URL || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  // Built assets are referenced from the site root, which is where `phishnet serve` hosts them.
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.js"],
    css: false,
  },
});
