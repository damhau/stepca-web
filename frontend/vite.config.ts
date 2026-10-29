import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import { tanstackRouter } from "@tanstack/router-plugin/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vitest/config"

// The Flask app serves the build (dist/) and the API; `npm run dev` proxies the API to it
export default defineConfig({
  plugins: [
    // Generates src/routeTree.gen.ts from src/routes/; must come before the React plugin
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "./src") } },
  server: {
    proxy: { "/api": { target: process.env.API_URL ?? "http://127.0.0.1:5000" } },
  },
  build: {
    // No inline scripts or styles: the app's Content-Security-Policy forbids them
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
})
