import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 30000,
    environment: "node",
    coverage: {
      provider: "v8",
      // Product code only — tests, scripts, challenge fixtures, and the
      // website are covered by their own checks, not this report.
      include: ["src/**/*.ts"],
      reporter: ["text-summary", "lcov"],
      reportsDirectory: "coverage",
      // Floors sit just under the measured 2026-11-13 baseline
      // (86.26% stmts, 77.79% branches, 95.25% functions, 86.26% lines)
      // so ordinary refactors keep passing while real coverage drops fail.
      thresholds: {
        statements: 85,
        branches: 76,
        functions: 94,
        lines: 85,
      },
    },
  },
});
