import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/static/ui/",
  build: { outDir: "../src/vault_mcp/static/ui", emptyOutDir: true },
  server: { proxy: { "/api": "http://localhost:8765" } },
  test: { environment: "jsdom", restoreMocks: true },
});
