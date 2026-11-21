import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * `sync-site.mjs` runs on a release engineer's workstation and in CI, and it is
 * handed a path derived from `os.tmpdir()`. Passing that path through a shell
 * string let any metacharacter in the environment's `TMPDIR`/`TEMP` escape the
 * quoting and run arbitrary commands, so the script must stay argv-only. This is
 * a source contract rather than a spawn test, because the script clones a real
 * remote over the network.
 */
const source = readFileSync(join(process.cwd(), "scripts", "sync-site.mjs"), "utf8");

describe("sync-site stays off the shell", () => {
  it("uses execFileSync and never execSync", () => {
    expect(source).toMatch(/import \{[^}]*execFileSync[^}]*\} from "node:child_process"/);
    expect(source).not.toMatch(/\bexecSync\b/);
  });

  it("never asks for a shell", () => {
    expect(source).not.toMatch(/shell\s*:\s*true/);
    expect(source).not.toMatch(/\bshell:\s*process\.platform/);
  });

  it("passes the temp directory as an argv entry, not inside command text", () => {
    expect(source).toMatch(/"clone",\s*"--depth",\s*"1",\s*"[^"]+",\s*tmpDir\]\)/);
    // The original defect: `${tmpDir}` interpolated into a command template.
    expect(source).not.toMatch(/`[^`]*\$\{tmpDir\}[^`]*`/);
  });

  it("keeps the commit message a literal argument", () => {
    expect(source).toMatch(/"commit",\s*"-m",\s*"chore\(site\): sync website from qybaihe\/bla"/);
  });
});
