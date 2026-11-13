import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { isNodeSqliteAvailable } from "../src/core/sqlite-runtime.js";
import { runShowcaseBenchmark } from "../src/engine/benchmark.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");

/** Every surface that publishes the aggregate showcase figure. */
const AGGREGATE_SURFACES = ["README.md", "STATE.md", "docs/readme/README_zh.md"] as const;

/**
 * Reads the published aggregate as `~<token>× … ~<cost>×`, in that order. The
 * figure always carries a `~`, which keeps the per-target table rows (bare
 * `**3,172.7×**`) and prose ranges (`300×–2,800×`) out of the match set.
 */
function publishedAggregate(rel: string): { readonly token: number; readonly cost: number } {
  const figures = [...read(rel).matchAll(/~([\d.,]+)×/g)]
    .map((match) => Number(match[1]!.replace(/,/g, "")))
    .filter((value) => Number.isFinite(value));
  expect(figures.length, `${rel} must state exactly one token and one cost figure`).toBe(2);
  return { token: figures[0]!, cost: figures[1]! };
}

/**
 * Small wobble is tolerated so this guard survives a seed or estimator tweak,
 * while still catching the ~40% drift these figures had accumulated.
 */
const TOLERANCE = 0.1;

describe("benchmark aggregate claim drift", () => {
  it("states one aggregate figure across README, STATE and the localized readme", () => {
    const [head, ...rest] = AGGREGATE_SURFACES.map((rel) => ({ rel, ...publishedAggregate(rel) }));
    for (const figure of rest) {
      expect(figure.token, `${figure.rel} token figure vs ${head!.rel}`).toBe(head!.token);
      expect(figure.cost, `${figure.rel} cost figure vs ${head!.rel}`).toBe(head!.cost);
    }
  });

  it.skipIf(!isNodeSqliteAvailable())(
    "keeps the published aggregate within 10% of the showcase run",
    async () => {
      const report = await runShowcaseBenchmark();
      for (const rel of AGGREGATE_SURFACES) {
        const { token, cost } = publishedAggregate(rel);
        expect(
          Math.abs(token - report.aggregateTokenMultiplier) / report.aggregateTokenMultiplier,
          `${rel} claims ${token}× vs computed ${report.aggregateTokenMultiplier}×`,
        ).toBeLessThan(TOLERANCE);
        expect(
          Math.abs(cost - report.aggregateCostMultiplier) / report.aggregateCostMultiplier,
          `${rel} claims ${cost}× vs computed ${report.aggregateCostMultiplier}×`,
        ).toBeLessThan(TOLERANCE);
      }
    },
  );
});
