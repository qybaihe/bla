import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  inspectPythonPyc,
  protectPythonPycBuffer,
} from "../src/shields/formats/python.js";
import {
  layoutForPycMagic,
  weavePythonPycBuffer,
} from "../src/shields/formats/python-pyc-weave.js";
import { buildWeavePlan } from "../src/shields/weave/weave-decoy.js";
import { PY3, python3 } from "./helpers/python-interpreter.js";

function compileSamplePyc(): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "bla-pyc-weave-"));
  try {
    const srcPath = join(dir, "sample.py");
    const pycPath = join(dir, "sample.pyc");
    writeFileSync(
      srcPath,
      [
        "def calculate(x, y):",
        "    return x + y",
        "",
        "def convert(v):",
        "    return str(v)",
        "",
        "def stats(xs):",
        "    return sum(xs) / max(len(xs), 1)",
        "",
      ].join("\n"),
      "utf8",
    );
    execFileSync(
      python3(),
      ["-c", `import py_compile; py_compile.compile(${JSON.stringify(srcPath)}, cfile=${JSON.stringify(pycPath)}, doraise=True)`],
      { stdio: "pipe" },
    );
    return readFileSync(pycPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function importAndCall(pyc: Buffer): { calculate: number; convert: string; stats: number } {
  const dir = mkdtempSync(join(tmpdir(), "bla-pyc-run-"));
  try {
    const pycPath = join(dir, "sample.pyc");
    writeFileSync(pycPath, pyc);
    const script = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("sample", ${JSON.stringify(pycPath)})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.calculate(2, 3))
print(mod.convert(7))
print(mod.stats([1, 2, 3, 4]))
`;
    const out = execFileSync(python3(), ["-c", script], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const lines = out.trim().split(/\r?\n/);
    return {
      calculate: Number(lines[0]),
      convert: lines[1]!,
      stats: Number(lines[2]),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function countCodeObjects(pyc: Buffer): number {
  // latin1 scan for TYPE_CODE bytes is noisy; use a marshal walk via python.
  const dir = mkdtempSync(join(tmpdir(), "bla-pyc-count-"));
  try {
    const pycPath = join(dir, "sample.pyc");
    writeFileSync(pycPath, pyc);
    const script = `
import marshal, types, sys
raw = open(${JSON.stringify(pycPath)}, "rb").read()
code = marshal.loads(raw[16:])
stack = [code]
n = 0
while stack:
    c = stack.pop()
    if isinstance(c, types.CodeType):
        n += 1
        stack.extend(x for x in c.co_consts if isinstance(x, types.CodeType))
print(n)
`;
    return Number(
      execFileSync(python3(), ["-c", script], { encoding: "utf8" }).trim(),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("python-pyc-weave", () => {
  it("maps CPython 3.11–3.14 magic numbers to the py311 CODE layout", () => {
    for (const magic of [3495, 3531, 3571, 3627]) {
      expect(layoutForPycMagic(magic)).toBe("py311");
    }
  });

  it.skipIf(!PY3)("maps current CPython magic to a known layout", () => {
    const pyc = compileSamplePyc();
    const magic = pyc.readUInt16LE(0);
    expect(layoutForPycMagic(magic)).toBe("py311"); // 3.11+ marshal CODE layout (3.11–3.15 magics)
  });

  it.skipIf(!PY3)("weave_decoys:true injects decoy TYPE_CODE into customer co_consts without breaking import", () => {
    const raw = compileSamplePyc();
    const before = importAndCall(raw);
    expect(before.calculate).toBe(5);
    expect(before.convert).toBe("7");
    expect(before.stats).toBeCloseTo(2.5);

    const codesBefore = countCodeObjects(raw);
    expect(codesBefore).toBe(4); // <module> + calculate + convert + stats

    const woven = weavePythonPycBuffer(raw, {
      intensity: "balanced",
      seed: "pyc-weave-test",
    });
    expect(woven).not.toBeNull();
    expect(woven!.customerDefsWoven).toBe(3);
    expect(woven!.decoyCodeObjectsInjected).toBeGreaterThanOrEqual(9); // 3 customer + 6 module

    const codesAfter = countCodeObjects(woven!.buffer);
    expect(codesAfter).toBe(codesBefore + woven!.decoyCodeObjectsInjected);

    const after = importAndCall(woven!.buffer);
    expect(after).toEqual(before);

    // Header preserved
    expect(woven!.buffer.subarray(0, 16).equals(raw.subarray(0, 16))).toBe(true);
  });

  it.skipIf(!PY3)("protectPythonPycBuffer weaveDecoys:false stays trailer-only (no co_consts CODE growth)", () => {
    const raw = compileSamplePyc();
    const before = countCodeObjects(raw);
    const res = protectPythonPycBuffer(raw, {
      intensity: "balanced",
      seed: "pyc-trailer",
      weaveDecoys: false,
    });
    expect(res.weaveDecoys).toBe(false);
    expect(res.decoyCodeObjectsInjected).toBe(0);
    expect(res.customerDefsWoven).toBe(0);
    expect(countCodeObjects(res.buffer)).toBe(before);
    expect(res.buffer.length).toBeGreaterThan(raw.length);
    expect(inspectPythonPyc(res.buffer).blaProtected).toBe(true);
    expect(importAndCall(res.buffer).calculate).toBe(5);
  });

  it.skipIf(!PY3)("protectPythonPycBuffer weaveDecoys:true weaves CODE + trailers", () => {
    const raw = compileSamplePyc();
    const before = countCodeObjects(raw);
    const res = protectPythonPycBuffer(raw, {
      intensity: "balanced",
      seed: "pyc-full",
      weaveDecoys: true,
    });
    expect(res.weaveDecoys).toBe(true);
    expect(res.customerDefsWoven).toBe(3);
    expect(res.decoyCodeObjectsInjected).toBeGreaterThanOrEqual(9);
    expect(countCodeObjects(res.buffer)).toBe(before + res.decoyCodeObjectsInjected);
    expect(res.buffer.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
    expect(inspectPythonPyc(res.buffer).blaProtected).toBe(true);
    expect(importAndCall(res.buffer)).toEqual({
      calculate: 5,
      convert: "7",
      stats: 2.5,
    });
  });

  it.skipIf(!PY3)("weave planner marks python-pyc as woven", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-plan-"));
    try {
      const pycPath = join(dir, "app.pyc");
      writeFileSync(pycPath, compileSamplePyc());
      const plan = buildWeavePlan(dir);
      const file = plan.targets.find((t) => t.relativePath.endsWith("app.pyc"));
      expect(file?.maturity).toBe("woven");
      expect(file?.status).toBe("ready");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
