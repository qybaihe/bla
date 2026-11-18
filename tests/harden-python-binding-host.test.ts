import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readPythonDeclaredEntryModules } from "../src/core/dev-tooling.js";
import { hardenProject, type HardenProjectReport } from "../src/engine/harden.js";
import { PY3, python3 } from "./helpers/python-interpreter.js";

/**
 * Where the Python load-time check lives, and what the report says about it.
 *
 * The check only runs when the module that carries it is imported. A project
 * that declares console scripts is started through the package those scripts
 * import — an installed `acme-tool` never touches a `run.py` beside the
 * package — so a check hosted in `run.py` verified nothing on the path users
 * actually take, and the report did not say so.
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(dir: string, rel: string, text: string): void {
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), text);
}

// `python3`, or `python` where that is the real interpreter (Windows).
const hasPython = PY3 !== null;

const LICENSING = `import hashlib

_PRO = hashlib.sha256(b"ACME-PRO").hexdigest()


def tier_for(key):
    return "pro" if hashlib.sha256(key.encode()).hexdigest() == _PRO else "free"
`;
const CLI = `from . import licensing


def main():
    print("tier", licensing.tier_for("ACME-PRO"), licensing.tier_for("nope"))
    return 0
`;
const RUN = `from acme_tool.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
`;

function project(files: Readonly<Record<string, string>>): string {
  const dir = tempDir("bla-py-host-");
  for (const [rel, text] of Object.entries(files)) put(dir, rel, text);
  return dir;
}

function harden(dir: string): HardenProjectReport {
  return hardenProject({
    directory: dir,
    seed: "py-binding-host",
    intensity: "balanced",
    sidecarEntangle: true,
    applyStateRoot: tempDir("bla-py-host-state-"),
  });
}

/** What the report tells the caller to do: copy the project, lay the mirror over it. */
function stage(dir: string): string {
  const staged = tempDir("bla-py-host-stage-");
  cpSync(dir, staged, { recursive: true, filter: (src) => !src.includes(".bla-hardened") });
  cpSync(join(dir, ".bla-hardened"), staged, { recursive: true });
  rmSync(join(staged, "bla-harden-summary.json"), { force: true });
  return staged;
}

function python(cwd: string, args: readonly string[]): { status: number | null; out: string } {
  const run = spawnSync(python3(), args, {
    cwd,
    encoding: "utf8",
    timeout: 60000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
  // (Python writes "\r\n" on Windows.)
  return { status: run.status, out: `${run.stdout}${run.stderr}`.replace(/\r\n/g, "\n") };
}
const VIA_RUN_PY = ["run.py"] as const;
const VIA_CONSOLE_SCRIPT = ["-c", "import sys; from acme_tool.cli import main; sys.exit(main())"] as const;

/** Patch the gate the way someone removing the licence check would. */
function patchGate(staged: string, rel = "acme_tool/licensing.py"): void {
  const file = join(staged, rel);
  const source = readFileSync(file, "utf8");
  expect(source).toContain('else "free"');
  writeFileSync(file, source.replace('else "free"', 'else "pro"'));
}

describe("readPythonDeclaredEntryModules", () => {
  it("reads console and GUI scripts from pyproject.toml, and nothing else", () => {
    const dir = project({
      "pyproject.toml": [
        "[project]",
        'name = "acme-tool"',
        'description = "not.a.module:either"',
        "",
        "[project.urls]",
        'Homepage = "https://example.invalid/acme.tool:main"',
        "",
        "[project.scripts]  # how users start it",
        'acme-tool = "acme_tool.cli:main"',
        '"acme-admin" = \'acme_tool.admin.cli:run\'',
        "# commented = \"ignored.module:main\"",
        'again = "acme_tool.cli:other"',
        "",
        "[project.gui-scripts]",
        'acme-gui = "acme_tool.gui:start"',
        "",
        '[project.entry-points."pytest11"]',
        'acme = "acme_tool.pytest_plugin"',
        "",
        "[tool.poetry.scripts]",
        'acme-poetry = { callable = "acme_tool.poetry_entry:main", extras = ["x"] }',
        'broken = "not a module!"',
      ].join("\n"),
    });
    expect(readPythonDeclaredEntryModules(dir)).toEqual([
      "acme_tool.cli",
      "acme_tool.admin.cli",
      "acme_tool.gui",
      "acme_tool.poetry_entry",
    ]);
  });

  it("reads setup.cfg and setup.py, and is empty for a project that declares none", () => {
    const cfg = project({
      "setup.cfg": [
        "[metadata]",
        "name = acme",
        "",
        "[options.entry_points]",
        "console_scripts =",
        "    acme = acme.cli:main",
        "    acme-sync = acme.sync.runner:run",
        "pytest11 =",
        "    acme = acme.pytest_plugin",
        "gui_scripts = acme-gui = acme.gui:start",
        "",
        "[options.extras_require]",
        "dev = pytest",
      ].join("\n"),
    });
    expect(readPythonDeclaredEntryModules(cfg)).toEqual(["acme.cli", "acme.sync.runner", "acme.gui"]);

    const setupPy = project({
      "setup.py":
        "from setuptools import setup\nsetup(name='acme', entry_points={'console_scripts': ['acme=acme.cli:main', \"acme-db = acme.db.tool:run\"]})\n",
    });
    expect(readPythonDeclaredEntryModules(setupPy)).toEqual(["acme.cli", "acme.db.tool"]);

    expect(readPythonDeclaredEntryModules(project({ "pyproject.toml": "[project]\nname = 'p'\n" }))).toEqual([]);
    expect(readPythonDeclaredEntryModules(tempDir("bla-py-host-empty-"))).toEqual([]);
  });
});

describe.skipIf(!hasPython)("which Python module carries the load-time check", () => {
  const PACKAGE = {
    "run.py": RUN,
    "acme_tool/__init__.py": '"""Acme tool."""\n__version__ = "1.0"\n',
    "acme_tool/cli.py": CLI,
    "acme_tool/licensing.py": LICENSING,
  };

  it("a project with a console script is checked on every way in, not only through run.py", () => {
    const dir = project({
      ...PACKAGE,
      "pyproject.toml": '[project]\nname = "acme-tool"\n\n[project.scripts]\nacme-tool = "acme_tool.cli:main"\n',
    });
    const report = harden(dir);
    expect(report.overallSuccess).toBe(true);
    expect(report.pythonSidecarEntry).toBe("acme_tool/__init__.py");
    expect(report.pythonSidecarUncoveredEntries).toBeUndefined();
    // run.py sits above the package, so nothing pins it — and the report says so.
    expect(report.integrityBindingSkipped).toContainEqual({
      relativePath: "run.py",
      reason: "not bound: acme_tool/__init__.py only checks files in its own directory tree",
    });
    const steps = report.nextSteps?.join("\n") ?? "";
    expect(steps).toMatch(
      /acme_tool\/__init__\.py now verifies the hardened files in its directory tree every time it is imported, and only then\./,
    );
    expect(steps).toMatch(/does not cover 1 artifact\(s\) — run\.py/);
    expect(steps).toMatch(/smoke run against that staged copy/);

    const intact = stage(dir);
    expect(python(intact, VIA_RUN_PY)).toEqual({ status: 0, out: "tier pro free\n" });
    expect(python(intact, VIA_CONSOLE_SCRIPT)).toEqual({ status: 0, out: "tier pro free\n" });

    const patched = stage(dir);
    patchGate(patched);
    for (const how of [VIA_RUN_PY, VIA_CONSOLE_SCRIPT]) {
      const run = python(patched, how);
      expect(run.status, how.join(" ")).not.toBe(0);
      expect(run.out, how.join(" ")).toMatch(/integrity binding mismatch/);
      expect(run.out, how.join(" ")).not.toMatch(/tier pro pro/);
    }
  }, 120000);

  it("finds the package of a src/ layout and of a setup.cfg project", () => {
    const srcLayout = project({
      "pyproject.toml": '[project]\nname = "acme-tool"\n\n[project.scripts]\nacme-tool = "acme_tool.cli:main"\n',
      "src/acme_tool/__init__.py": '__version__ = "1.0"\n',
      "src/acme_tool/cli.py": CLI,
      "src/acme_tool/licensing.py": LICENSING,
    });
    expect(harden(srcLayout).pythonSidecarEntry).toBe("src/acme_tool/__init__.py");

    const setupCfg = project({
      ...PACKAGE,
      "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    acme-tool = acme_tool.cli:main\n",
    });
    expect(harden(setupCfg).pythonSidecarEntry).toBe("acme_tool/__init__.py");
  }, 120000);

  it("without a declared script the program entry keeps the check, and the report says when it runs", () => {
    const dir = project({ ...PACKAGE, "pyproject.toml": '[project]\nname = "acme-tool"\n' });
    const report = harden(dir);
    expect(report.pythonSidecarEntry).toBe("run.py");
    expect(report.pythonSidecarUncoveredEntries).toBeUndefined();
    expect(report.integrityBindingSkipped ?? []).toEqual([]);
    expect(report.nextSteps?.join("\n")).toMatch(
      /run\.py now verifies the hardened files in its directory tree every time it is imported, and only then\./,
    );

    const patched = stage(dir);
    expect(python(patched, VIA_RUN_PY)).toEqual({ status: 0, out: "tier pro free\n" });
    patchGate(patched);
    expect(python(patched, VIA_RUN_PY).out).toMatch(/integrity binding mismatch/);
  }, 120000);

  it("a script module outside any hardened package carries the check itself", () => {
    // No __init__.py at all: `tool.py` is what the installed script imports.
    const dir = project({
      "pyproject.toml": '[project]\nname = "t"\n\n[project.scripts]\ntool = "tool:main"\n',
      "tool.py": 'import helper\n\n\ndef main():\n    print("sum", helper.add(2, 3))\n    return 0\n',
      "helper.py": "def add(a, b):\n    return a + b\n",
      "run.py": 'import tool\n\nraise SystemExit(tool.main())\n',
    });
    const report = harden(dir);
    expect(report.pythonSidecarEntry).toBe("tool.py");
    expect(report.pythonSidecarUncoveredEntries).toBeUndefined();

    const staged = stage(dir);
    expect(python(staged, ["-c", "import tool; tool.main()"])).toEqual({ status: 0, out: "sum 5\n" });
    writeFileSync(join(staged, "helper.py"), `${readFileSync(join(staged, "helper.py"), "utf8")}\n# changed\n`);
    expect(python(staged, ["-c", "import tool; tool.main()"]).out).toMatch(/integrity binding mismatch/);
  }, 120000);

  it("names a declared script that never imports the module carrying the check", () => {
    const files = {
      "pyproject.toml": '[project]\nname = "acme-tool"\n\n[project.scripts]\nacme-tool = "acme_tool.cli:main"\n',
      "acme_tool/policy.py": 'LIMIT = 3\n\n\ndef allowed(n):\n    return n <= LIMIT\n',
      "acme_tool/cli.py": CLI,
      "acme_tool/licensing.py": LICENSING,
    };
    // `policy.py` is the documented place for the check; here nothing loads it.
    const unloaded = harden(project(files));
    expect(unloaded.pythonSidecarEntry).toBe("acme_tool/policy.py");
    expect(unloaded.pythonSidecarUncoveredEntries).toEqual(["acme_tool/cli.py"]);
    expect(unloaded.nextSteps?.join("\n")).toMatch(
      /acme_tool\/cli\.py is declared as a console script but never imports acme_tool\/policy\.py, so started that way nothing is verified — import it from that module and harden again\./,
    );

    const loaded = harden(
      project({ ...files, "acme_tool/cli.py": `from . import policy\n${CLI}` }),
    );
    expect(loaded.pythonSidecarEntry).toBe("acme_tool/policy.py");
    expect(loaded.pythonSidecarUncoveredEntries).toBeUndefined();
    expect(loaded.nextSteps?.join("\n")).not.toMatch(/declared as a console script/);
  }, 120000);
});
