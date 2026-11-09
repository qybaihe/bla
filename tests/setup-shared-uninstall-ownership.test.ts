import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveSupportedAgentClients } from "../src/setup/clients.js";
import { readInstallManifest, runSetup, runUninstall } from "../src/setup/setup.js";

const created: string[] = [];
function fakeHome(): string {
  const home = mkdtempSync(join(tmpdir(), "bla-shared-uninstall-"));
  created.push(home);
  return home;
}

afterEach(() => {
  for (const path of created.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("multi-client uninstall and shared skill ownership", () => {
  it("retains a shared skill when a targeted client still has a conflicting MCP configuration", () => {
    const home = fakeHome();
    const installed = runSetup({
      homeDir: home,
      clientIds: ["claude_desktop", "vscode"],
      yes: true,
    });
    expect(installed.status).toBe("applied");

    const sharedSkill = join(home, ".agents", "skills", "blind-llm-agents", "SKILL.md");
    expect(existsSync(sharedSkill)).toBe(true);

    const vscode = resolveSupportedAgentClients(home).find((client) => client.id === "vscode");
    expect(vscode).toBeDefined();
    writeFileSync(vscode!.configPath, "{ invalid JSON", "utf8");

    const result = runUninstall({
      homeDir: home,
      clientIds: ["claude_desktop", "vscode"],
    });
    expect(result.results.find((r) => r.clientId === "claude_desktop")?.status).toBe("removed");
    expect(result.results.find((r) => r.clientId === "vscode")?.status).toBe("conflict");
    expect(readInstallManifest(home).clients.vscode).toBeDefined();

    // VS Code still has a manifest-owned BLA installation. Uninstalling another
    // selected client must not remove the shared skill it still relies upon.
    expect(existsSync(sharedSkill)).toBe(true);
  });

  it("keeps an installed client's skill when its own MCP configuration is malformed", () => {
    const home = fakeHome();
    const installed = runSetup({
      homeDir: home,
      clientIds: ["vscode"],
      yes: true,
    });
    expect(installed.status).toBe("applied");
    const vscode = resolveSupportedAgentClients(home).find((client) => client.id === "vscode")!;
    const skill = join(home, ".agents", "skills", "blind-llm-agents", "SKILL.md");
    writeFileSync(vscode.configPath, "{ invalid JSON", "utf8");

    const result = runUninstall({ homeDir: home, clientIds: ["vscode"] });
    expect(result.conflicts).toHaveLength(1);
    expect(readInstallManifest(home).clients.vscode).toBeDefined();
    expect(existsSync(skill)).toBe(true);
  });

  it("removes the shared skill when every installed client using it is removed", () => {
    const home = fakeHome();
    const installed = runSetup({
      homeDir: home,
      clientIds: ["claude_desktop", "vscode"],
      yes: true,
    });
    expect(installed.status).toBe("applied");
    const sharedSkill = join(home, ".agents", "skills", "blind-llm-agents", "SKILL.md");

    const result = runUninstall({
      homeDir: home,
      clientIds: ["claude_desktop", "vscode"],
    });
    expect(result.conflicts).toEqual([]);
    expect(existsSync(sharedSkill)).toBe(false);
  });
});
