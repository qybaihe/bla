import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const agents = readFileSync(join(ROOT, "AGENTS.md"), "utf8");

function bulletLine(marker: string): string {
  return agents.split(/\r?\n/).find((line) => line.includes(marker)) ?? "";
}

function claimedShields(marker: string): Set<string> {
  return new Set(
    [...bulletLine(marker).matchAll(/`([a-z0-9-]+\.ts)`/g)].map((match) => match[1]!),
  );
}

function shieldFiles(directory: string): Set<string> {
  return new Set(
    readdirSync(join(ROOT, directory)).filter(
      (entry) => entry.endsWith(".ts") && entry !== "index.ts",
    ),
  );
}

function missingFromAgents(directory: string, marker: string): string[] {
  const claimed = claimedShields(marker);
  return [...shieldFiles(directory)].filter((file) => !claimed.has(file));
}

describe("AGENTS.md module inventory", () => {
  it("lists every format shield", () => {
    expect(missingFromAgents("src/shields/formats", "`formats/`: Format-specific shields")).toEqual(
      [],
    );
  });

  it("lists every deception module", () => {
    expect(missingFromAgents("src/shields/deception", "`deception/`:")).toEqual([]);
  });

  it("does not name shields that no longer exist", () => {
    for (const [directory, marker] of [
      ["src/shields/formats", "`formats/`: Format-specific shields"],
      ["src/shields/deception", "`deception/`:"],
    ] as const) {
      const actual = shieldFiles(directory);
      expect([...claimedShields(marker)].filter((file) => !actual.has(file))).toEqual([]);
    }
  });
});