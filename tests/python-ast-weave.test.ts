import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertNoForbiddenMarkers } from "../src/core/identifiers.js";
import { protectPythonSource } from "../src/shields/formats/python.js";
import {
  findCustomerPythonFunctionDefs,
  weavePythonDecoyCalls,
} from "../src/shields/formats/python-ast-weave.js";
import { SeededPrng } from "../src/core/prng.js";
import { PY3, python3 } from "./helpers/python-interpreter.js";

const temps: string[] = [];
afterEach(() => {
  for (const d of temps.splice(0)) {
    rmSync(d, { recursive: true, force: true });
  }
});

function extractDefBody(source: string, defName: string): string | null {
  const lines = source.split(/\r?\n/);
  const header = new RegExp(`^(async\\s+)?def\\s+${defName}\\s*\\(`);
  let start = -1;
  let defIndent = "";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const indent = /^([ \t]*)/.exec(line)?.[1] ?? "";
    if (header.test(line.slice(indent.length))) {
      start = i;
      defIndent = indent;
      break;
    }
  }
  if (start < 0) return null;
  const body: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === "") {
      body.push(line);
      continue;
    }
    const indent = /^([ \t]*)/.exec(line)?.[1] ?? "";
    if (indent.length <= defIndent.length) break;
    body.push(line);
  }
  return body.join("\n");
}

describe("python structural decoy weave", () => {
  it("finds customer FunctionDefs structurally and skips tarpit identities", () => {
    const src = [
      "def decoy_a(seed=0, depth=0):",
      "    return seed",
      "",
      "def calculate(x, y):",
      '    """sum"""',
      "    return x + y",
      "",
      "async def fetch_row(id):",
      "    return id",
      "",
    ].join("\n");
    const sites = findCustomerPythonFunctionDefs(src, new Set(["decoy_a"]));
    expect(sites.map((s) => s.name).sort()).toEqual(["calculate", "fetch_row"]);
  });

  it("weaveDecoys:true puts decoy xref inside customer def calculate", () => {
    const customer = [
      "def calculate(a, b):",
      '    """business entry"""',
      "    return a + b",
      "",
      "def helper(z):",
      "    return z * 2",
      "",
    ].join("\n");
    const out = protectPythonSource(customer, {
      intensity: "balanced",
      seed: "py-weave-on-1",
      weaveDecoys: true,
    });
    expect(out.weaveDecoys).toBe(true);
    expect(out.customerDefsWoven).toBeGreaterThanOrEqual(2);
    assertNoForbiddenMarkers(out.code, "python-weave-on");

    const body = extractDefBody(out.code, "calculate");
    expect(body).toBeTruthy();
    expect(body!).toMatch(/\["epoch"\]/);
    expect(body!).toMatch(/hash\(\w+\.__name__\)/);
    // Opaque-false guarded call should reference a decoy name as a call.
    expect(body!).toMatch(/\w+\(\d+,\s*0\)/);

    // Decoy defs themselves should not get a second weave layer of customer pattern
    // (skip by identity): their bodies already have epoch mutation from tarpit.
  });

  it("weaveDecoys:false leaves customer def without decoy call entanglement", () => {
    const customer = [
      "def calculate(a, b):",
      "    return a + b",
      "",
    ].join("\n");
    const out = protectPythonSource(customer, {
      intensity: "balanced",
      seed: "py-weave-off-1",
      weaveDecoys: false,
    });
    expect(out.weaveDecoys).toBe(false);
    expect(out.customerDefsWoven).toBe(0);
    const body = extractDefBody(out.code, "calculate");
    expect(body).toBeTruthy();
    expect(body!).toMatch(/return a \+ b/);
    expect(body!).not.toMatch(/hash\(\w+\.__name__\)/);
    expect(body!).not.toMatch(/\w+\(\d+,\s*0\)/);
  });

  it.skipIf(!PY3)("woven output still py_compile-clean when python3 is available", () => {
    const customer = [
      "#!/usr/bin/env python3",
      "# -*- coding: utf-8 -*-",
      '"""module doc"""',
      "from __future__ import annotations",
      "",
      "def calculate(a: int, b: int) -> int:",
      '    """entry"""',
      "    total = a + b",
      "    return total",
      "",
    ].join("\n");
    const out = protectPythonSource(customer, {
      intensity: "maximum",
      seed: "py-weave-compile-1",
      weaveDecoys: true,
    });
    const dir = mkdtempSync(join(tmpdir(), "bla-py-weave-"));
    temps.push(dir);
    const file = join(dir, "woven.py");
    writeFileSync(file, out.code, "utf8");
    execFileSync(python3(), ["-m", "py_compile", file], { stdio: "pipe" });
  });

  it("PRNG selects decoys without business-name rule tables", () => {
    const src = [
      "SLOT = {'epoch': 0}",
      "STATE = 1",
      "def alpha(seed=0, depth=0):",
      "    return seed",
      "def beta(seed=0, depth=0):",
      "    return seed",
      "def calculate(x):",
      "    return x",
      "",
    ].join("\n");
    const woven = weavePythonDecoyCalls({
      source: src,
      skipDefNames: ["alpha", "beta"],
      decoyFunctionNames: ["alpha", "beta"],
      sharedSlotName: "SLOT",
      stateVarName: "STATE",
      prng: new SeededPrng("unit-weave-prng"),
      intensity: "balanced",
    });
    expect(woven.customerDefsWoven).toBe(1);
    const body = extractDefBody(woven.code, "calculate");
    expect(body!).toMatch(/hash\((alpha|beta)\.__name__\)/);
  });
});
