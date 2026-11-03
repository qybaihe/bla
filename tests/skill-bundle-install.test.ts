import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runDoctor } from "../src/setup/doctor.js";
import {
  readInstallManifest,
  resolveBundledSkillBundle,
  runSetup,
  runUninstall,
} from "../src/setup/setup.js";

const tempDirs: string[] = [];
function makeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-skill-bundle-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const MATRIX = "references/counter-rea-matrix.md";

function setupCursor(home: string): string {
  runSetup({
    homeDir: home,
    clientIds: ["cursor"],
    mcpCommand: process.execPath,
    mcpArgs: [resolve(process.cwd(), "dist/cli.js"), "mcp"],
    yes: true,
  });
  return join(home, ".cursor", "skills", "blind-llm-agents");
}

describe("skill bundle install integrity", () => {
  it("bundles SKILL.md first plus every reference file", () => {
    const bundle = resolveBundledSkillBundle();
    expect(bundle[0]!.relativePath).toBe("SKILL.md");
    expect(bundle.map((f) => f.relativePath)).toContain(MATRIX);
  });

  it("fresh setup installs references so SKILL.md relative links resolve", () => {
    const home = makeHome();
    const skillDir = setupCursor(home);
    const skill = readFileSync(join(skillDir, "SKILL.md"), "utf8");
    const links = [...skill.matchAll(/\]\((references\/[^)]+)\)/g)].map((m) => m[1]!);
    expect(links.length).toBeGreaterThan(0);
    for (const rel of links) expect(existsSync(join(skillDir, rel))).toBe(true);
    const rec = readInstallManifest(home).clients.cursor!;
    expect(Object.keys(rec.writtenSkillFiles ?? {})).toContain(MATRIX);
  });

  it("doctor fails on a missing reference and warns on a modified one", () => {
    const home = makeHome();
    const skillDir = setupCursor(home);
    const ok = runDoctor({ homeDir: home, sqliteAvailableOverride: true });
    const cursorOk = ok.agentClients.find((c) => c.id === "cursor")!;
    expect(cursorOk.skillMissingFiles).toEqual([]);
    expect(cursorOk.status).toBe("pass");

    writeFileSync(join(skillDir, MATRIX), "tampered\n", "utf8");
    const warn = runDoctor({ homeDir: home, sqliteAvailableOverride: true });
    const cursorWarn = warn.agentClients.find((c) => c.id === "cursor")!;
    expect(cursorWarn.skillModifiedFiles).toEqual([MATRIX]);
    expect(cursorWarn.status).toBe("warn");

    unlinkSync(join(skillDir, MATRIX));
    const bad = runDoctor({ homeDir: home, sqliteAvailableOverride: true });
    const cursorBad = bad.agentClients.find((c) => c.id === "cursor")!;
    expect(cursorBad.skillMissingFiles).toEqual([MATRIX]);
    expect(cursorBad.status).toBe("fail");
    expect(bad.healthy).toBe(false);
    expect(cursorBad.issues.join("\n")).toContain(MATRIX);
  });

  it("uninstall removes the whole owned bundle and the empty skill dir", () => {
    const home = makeHome();
    const skillDir = setupCursor(home);
    runUninstall({ homeDir: home, clientIds: ["cursor"] });
    expect(existsSync(join(skillDir, MATRIX))).toBe(false);
    expect(existsSync(skillDir)).toBe(false);
  });

  it("uninstall preserves a user-modified reference", () => {
    const home = makeHome();
    const skillDir = setupCursor(home);
    writeFileSync(join(skillDir, MATRIX), "my notes\n", "utf8");
    runUninstall({ homeDir: home, clientIds: ["cursor"] });
    expect(readFileSync(join(skillDir, MATRIX), "utf8")).toBe("my notes\n");
  });
});
