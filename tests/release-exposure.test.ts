import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inspectReleaseExposure } from "../src/core/release-exposure.js";
import { runCli } from "../src/cli.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "bla-release-")); dirs.push(dir); return dir; };
const map = JSON.stringify({ version: 3, sources: ["harmless-example.ts"], sourcesContent: ["export const example = 1;"], names: [], mappings: "" });
afterEach(() => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe("read-only release exposure observations", () => {
  it("reports actual embedded content counts without source text or source names and leaves input unchanged", () => {
    const file = join(temp(), "bundle.js.map"); writeFileSync(file, map);
    const report = inspectReleaseExposure(file);
    expect(report).toMatchObject({ status: "complete", filesInspected: 1, networkAccessed: false, targetModified: false });
    expect(report.findings).toEqual([{ file: "bundle.js.map", kind: "embedded-source-text", evidenceBasis: "static-file-observation", representation: "standalone-map", embeddedSourceCount: 1, embeddedSourceBytes: 25 }]);
    expect(JSON.stringify(report)).not.toContain("example");
    expect(readFileSync(file, "utf8")).toBe(map);
  });
  it.each(["base64", "percent"])("observes %s inline map content", encoding => {
    const file = join(temp(), "bundle.js");
    const payload = encoding === "base64" ? ";base64," + Buffer.from(map).toString("base64") : "," + encodeURIComponent(map);
    writeFileSync(file, "//# sourceMappingURL=data:application/json" + payload);
    expect(inspectReleaseExposure(file).findings[0]).toMatchObject({ representation: "inline-map", embeddedSourceCount: 1 });
  });
  it("does not follow external, absolute or relative map references and does not disclose URLs", () => {
    const root = temp();
    writeFileSync(join(root, "bundle.js"), "//# sourceMappingURL=https://invalid.example/map?token=hidden\n//# sourceMappingURL=../outside.map\n//# sourceMappingURL=/absent.map");
    const report = inspectReleaseExposure(root);
    expect(report.status).toBe("complete");
    expect(report.filesInspected).toBe(1);
    expect(report.findings.map(f => f.kind)).toEqual(Array(3).fill("unverified-map-reference"));
    expect(JSON.stringify(report)).not.toMatch(/hidden|outside|absent|https/);
  });
  it("does not claim exposure for absent, null or empty sourcesContent", () => {
    const root = temp();
    [undefined, null, [], [null, ""]].forEach((sourcesContent, i) => writeFileSync(join(root, `${i}.map`), JSON.stringify({ version: 3, sourcesContent })));
    expect(inspectReleaseExposure(root)).toMatchObject({ status: "complete", findings: [] });
  });
  it.each(["{", '{"version":2}', '{"version":3,"sourcesContent":[42]}', '{"version":3,"sections":[]}'])("marks unsupported/malformed maps as incomplete: %s", body => {
    const file = join(temp(), "bundle.map"); writeFileSync(file, body);
    expect(inspectReleaseExposure(file)).toMatchObject({ status: "partial", findings: [] });
  });
  it("bounds file and inline map sizes", () => {
    const root = temp();
    writeFileSync(join(root, "large.map"), " ".repeat(2 * 1024 * 1024 + 1));
    writeFileSync(join(root, "inline.js"), "//# sourceMappingURL=data:application/json;base64," + Buffer.from(JSON.stringify({ version: 3, sourcesContent: ["a".repeat(512 * 1024)] })).toString("base64"));
    const report = inspectReleaseExposure(root);
    expect(report.status).toBe("partial");
    expect(report.limitations.map(x => x.reason).sort()).toEqual(["map-size-limit", "read-size-limit"]);
    expect(report.bytesRead).toBeLessThan(1024 * 1024);
  });
  it("refuses selected symlinks and skips links within the release tree", () => {
    const root = temp(); const external = temp(); writeFileSync(join(external, "private.map"), map);
    symlinkSync(external, join(root, "linked"), "dir");
    expect(inspectReleaseExposure(root)).toMatchObject({ status: "partial", filesInspected: 0, findings: [] });
    expect(() => inspectReleaseExposure(join(root, "linked"))).toThrow(/non-symlink/);
    expect(() => inspectReleaseExposure(join(root, "linked", "private.map"))).toThrow(/non-symlink/);
  });
  it("bounds recursion and skips unrelated file formats", () => {
    const root = temp(); writeFileSync(join(root, "ignored.txt"), map);
    let sub = root;
    for (let i = 0; i < 17; i++) { sub = join(sub, "deep"); mkdirSync(sub); }
    writeFileSync(join(sub, "source.map"), map);
    expect(inspectReleaseExposure(root)).toMatchObject({ status: "partial", filesInspected: 0, findings: [] });
  });
  it("bounds repeated reference observations", () => {
    const file = join(temp(), "bundle.js");
    writeFileSync(file, "//# sourceMappingURL=not-fetched.map\n".repeat(130));
    const report = inspectReleaseExposure(file);
    expect(report.findings).toHaveLength(128);
    expect(report.limitations).toContainEqual({ file: "bundle.js", reason: "observation-count-limit" });
  });
  it("reports malformed inline encoding without exposing its payload", () => {
    const file = join(temp(), "bundle.js");
    writeFileSync(file, "//# sourceMappingURL=data:application/json;base64,!!!private-value");
    const report = inspectReleaseExposure(file);
    expect(report.status).toBe("partial");
    expect(JSON.stringify(report)).not.toContain("private-value");
  });
  it("CLI emits structured observations and returns 2 for incomplete inspection, not efficacy", async () => {
    const output = vi.spyOn(console, "log").mockImplementation(() => {});
    const file = join(temp(), "bundle.map"); writeFileSync(file, map);
    expect(await runCli(["inspect-release", file, "--json"])).toBe(0);
    expect(JSON.parse(String(output.mock.calls[0]?.[0])).findings).toHaveLength(1);
    writeFileSync(file, "invalid");
    expect(await runCli(["inspect-release", file])).toBe(2);
  });
});
