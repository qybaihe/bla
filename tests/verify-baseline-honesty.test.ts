import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { verifyTarget } from "../src/engine/verifier.js";

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "bla-verify-baseline-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const SOURCE = `function license(fingerprint) { return fingerprint === "abcd"; }\nmodule.exports = { license };\n`;

function amplification(report: ReturnType<typeof verifyTarget>) {
  const check = report.checks.find((c) => c.id === "token-bankruptcy-amplification");
  expect(check).toBeDefined();
  return check!;
}

describe("verify reports where the amplification baseline came from", () => {
  it("marks the baseline as measured when an original artifact is supplied", () => {
    const base = dir();
    const original = join(base, "app.original.js");
    const protectedPath = join(base, "app.js");
    writeFileSync(original, SOURCE, "utf8");
    writeFileSync(protectedPath, SOURCE, "utf8");

    const report = verifyTarget(protectedPath, original);
    const check = amplification(report);
    expect(check.baselineSource).toBe("measured");
    expect(check.details).not.toContain("assumed baseline");
  });

  it("marks the baseline as assumed when no original artifact is supplied", () => {
    const base = dir();
    const protectedPath = join(base, "app.js");
    writeFileSync(protectedPath, SOURCE, "utf8");

    const report = verifyTarget(protectedPath);
    const check = amplification(report);
    expect(check.baselineSource).toBe("assumed");
    expect(check.details).toContain("assumed baseline");
    expect(check.details).toContain("bla verify <target> <original>");
  });
});