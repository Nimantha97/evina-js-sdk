import { defineConfig } from "vitest/config";
import { resolve } from "path";

/**
 * Test runner config (NFR-MNT-1, NFR-MNT-2).
 *
 * Coverage thresholds are scoped to the server SDK core (packages/server/src).
 * The browser package is a Phase 2 stub and is intentionally excluded until it
 * has real logic. All EVINA interactions in tests hit a mock server, never live
 * EVINA (enforced by convention + later milestones).
 */
export default defineConfig({
  resolve: {
    alias: {
      "@ideabiz/evina-sdk": resolve(
        import.meta.dirname,
        "packages/server/src/index.ts",
      ),
    },
    // Allow .js imports to resolve to .ts sources in the test environment.
    // This is required because the source files use ESM-compliant .js
    // extensions (correct for Node runtime) but Vitest needs to find the
    // .ts originals during test execution (ADR-001, ADR-005).
    extensions: [".ts", ".tsx", ".js", ".jsx", ".json"],
  },
  test: {
    // vmThreads uses Vite's module transformer, which correctly resolves
    // .js extension imports to their .ts sources during test execution.
    // This is required because the source files use ESM-compliant .js
    // extensions (correct for Node runtime) but tests run against .ts sources.
    // (Replaces the original pool:"forks" which used Node's native ESM loader
    // and could not resolve .ts files referenced with .js extensions.)
    pool: "vmThreads",
    include: ["packages/**/test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["packages/server/src/**/*.ts"],
      // Exclude declaration files and pure type-only modules (interfaces compile
      // to zero runtime code, so they carry no coverage).
      exclude: ["**/*.d.ts", "packages/server/src/types.ts"],
      reporter: ["text", "lcov"],
      thresholds: {
        lines: 90,
        functions: 90,
        statements: 90,
        branches: 90,
      },
    },
  },
});
