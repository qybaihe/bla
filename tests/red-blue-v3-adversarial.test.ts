import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildWeavePlan,
  hardenProject,
  lintLaneIndependence,
  scanPackagingGates,
  verifyWeaveTarget,
} from "../src/index.js";

const temps: string[] = [];
afterEach(() => {
  for (const d of temps.splice(0)) {
    rmSync(d, { recursive: true, force: true });
  }
});

describe("BLA 3.0 Red-Blue Adversarial Rounds (Weave Evasion, Lane Oracles & Multi-Artifact Entanglement)", () => {
  it("Round A: blocks constant-false dead-branch calls (`1 === 2`, `false && fn()`) and write-only state stores in bla_verify_weave", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rb-round-a-"));
    temps.push(dir);
    const file = join(dir, "gate.js");
    writeFileSync(
      file,
      `
const state = { epoch: 1 };
function decoyHelper() {
  state.epoch = 2;
  return 42;
}
export function verifyKey(k) {
  if (1 === 2) {
    decoyHelper();
  }
  false && decoyHelper();
  state.epoch = 3;
  return k === "secret";
}
`.trim() + "\n",
      "utf8",
    );

    const report = verifyWeaveTarget(file);
    expect(report.overallPassed).toBe(false);
    const checks = Object.fromEntries(
      report.files[0]!.checks.map((c) => [c.id, c.passed]),
    );
    // `decoyHelper` is only called inside dead branches -> unreferenced!
    expect(checks["customer-entry-edges"]).toBe(false);
    // `1 === 2` is a constant-false dead branch -> opaque-true-entanglement fails!
    expect(checks["opaque-true-entanglement"]).toBe(false);
    // `state` is write-only in `verifyKey` and `decoyHelper` is unreachable -> shared-state-mutation fails!
    expect(checks["shared-state-mutation"]).toBe(false);
    expect(report.agentActions.length).toBeGreaterThanOrEqual(3);
  });

  it("Round B: blocks shadowed state parameters and disconnected multi-line no-op helpers in bla_verify_weave", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rb-round-b-"));
    temps.push(dir);
    const file = join(dir, "shadow.js");
    writeFileSync(
      file,
      `
const sessionState = { epoch: 1, quota: 10 };
function shadowedHelper(sessionState) {
  sessionState.epoch += 1;
  return sessionState.epoch;
}
function disconnectedNoop() {
  const local = 123;
  return local + 1;
}
export function checkToken(tok) {
  if ((sessionState.epoch & 1) !== 0) {
    shadowedHelper({ epoch: 0 });
    disconnectedNoop();
  }
  return tok.length === sessionState.quota;
}
`.trim() + "\n",
      "utf8",
    );

    const report = verifyWeaveTarget(file);
    expect(report.overallPassed).toBe(false);
    const checks = Object.fromEntries(
      report.files[0]!.checks.map((c) => [c.id, c.passed]),
    );
    // `shadowedHelper` only mutates its own parameter `sessionState`, not module-scoped `sessionState`
    expect(checks["shared-state-mutation"]).toBe(false);
    // `disconnectedNoop` touches no shared state and calls nothing
    expect(checks["filter-resistance"]).toBe(false);
  });

  it("Round C: catches camelCase homogeneous TEE/scare vocabulary (`verifyEnclaveQuote`, `checkTpm2Pcr`)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rb-round-c-"));
    temps.push(dir);
    const file = join(dir, "scare.js");
    writeFileSync(
      file,
      `
const state = { epoch: 1 };
function verifyEnclaveQuote(n) {
  state.epoch = (state.epoch + n) | 1;
  return state.epoch;
}
function checkTpm2Pcr(k) {
  if ((state.epoch & 1) !== 0) {
    verifyEnclaveQuote(k.length);
  }
  return k.length + (state.epoch & 0) === 8;
}
module.exports = { checkTpm2Pcr };
`.trim() + "\n",
      "utf8",
    );

    const report = verifyWeaveTarget(file);
    expect(report.overallPassed).toBe(false);
    const mixedCheck = report.files[0]!.checks.find(
      (c) => c.id === "mixed-stems",
    )!;
    expect(mixedCheck.passed).toBe(false);
    expect(
      report.agentActions.some((a) => a.checkId === "mixed-stems"),
    ).toBe(true);
  });

  it("Round D: blocks Python comment/string/dead-branch fake calls and untouched state dicts", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rb-round-d-"));
    temps.push(dir);
    const pyFile = join(dir, "service.py");
    writeFileSync(
      pyFile,
      `
_ledger_state = {"epoch": 1}

def orphan_helper(x):
    return x + 1

def verify_order(order_id):
    # orphan_helper(1)
    note = "orphan_helper(2)"
    if False:
        orphan_helper(3)
    if order_id:
        return True
    return False
`.trim() + "\n",
      "utf8",
    );

    const report = verifyWeaveTarget(pyFile);
    expect(report.overallPassed).toBe(false);
    const checks = Object.fromEntries(
      report.files[0]!.checks.map((c) => [c.id, c.passed]),
    );
    expect(checks["customer-entry-edges"]).toBe(false);
    expect(checks["shared-state-mutation"]).toBe(false);
    expect(checks["opaque-true-entanglement"]).toBe(false);
  });

  it("Round E: detects chained charCodeAt/bracket per-index checks and split-segment checks in bla_lint", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rb-round-e-"));
    temps.push(dir);

    const r1 = lintLaneIndependence(`
      function checkKey(key) {
        return key.charCodeAt(0) === 0x41 && key.charCodeAt(1) === 0x42 && key.charCodeAt(2) === 0x43;
      }
    `);
    expect(r1.looksLaneIndependent).toBe(true);
    expect(r1.findings.some((f) => f.id === "chained-per-index-compare")).toBe(
      true,
    );

    const r2 = lintLaneIndependence(`
      function checkSerial(serial) {
        const segs = serial.split("-");
        return segs[0] === "PRO1" && segs[1] === "2026" && segs[2] === "ABCD";
      }
    `);
    expect(r2.looksLaneIndependent).toBe(true);
    expect(r2.findings.some((f) => f.id === "split-segment-lane-compare")).toBe(
      true,
    );

    const gateFile = join(dir, "serial.js");
    writeFileSync(
      gateFile,
      `const segs = key.split("-"); if (segs[0] === "AAAA" && segs[1] === "BBBB") {}\n`,
      "utf8",
    );
    const gateScan = scanPackagingGates({ directory: dir });
    expect(gateScan.shouldRefuseBankrupt).toBe(true);
    expect(
      gateScan.remediationPlan.some((p) => p.gate === "lane-independence"),
    ).toBe(true);
  });

  it("Round F: multi-artifact hardenProject with selfSeal + sidecarEntangle + weaveDecoys passes post-harden weave verification and hard-fails on any file tamper", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rb-round-f-"));
    temps.push(dir);

    writeFileSync(
      join(dir, "helper.cjs"),
      `
const helperState = { epoch: 1, count: 0 };
function updateHelperCount(delta) {
  helperState.count = (helperState.count + delta) & 0xffff;
  return helperState.count;
}
function computeBonus(x) {
  if ((helperState.epoch & 1) !== 0) {
    updateHelperCount(x);
  }
  return x + 10 + (helperState.count & 0);
}
module.exports = { computeBonus };
`.trim() + "\n",
      "utf8",
    );

    writeFileSync(
      join(dir, "license.cjs"),
      `
const helper = require("./helper.cjs");
const sessionState = { epoch: 1, cursor: 0 };
function syncSessionCursor(step) {
  sessionState.cursor = (sessionState.cursor + step) & 0xffff;
  return sessionState.cursor;
}
function evaluateOrder(amount) {
  if ((sessionState.epoch & 1) !== 0) {
    syncSessionCursor(amount);
  }
  return helper.computeBonus(amount) + (sessionState.cursor & 0);
}
module.exports = { evaluateOrder };
`.trim() + "\n",
      "utf8",
    );

    writeFileSync(
      join(dir, "worker.py"),
      `
_worker_state = {"epoch": 1, "ticks": 0}

def record_worker_tick(step):
    _worker_state["ticks"] = (_worker_state["ticks"] + step) & 0xFFFF
    return _worker_state["ticks"]

def process_batch(items):
    if _worker_state["epoch"] >= 1:
        record_worker_tick(len(items))
    return len(items) * 2
`.trim() + "\n",
      "utf8",
    );

    // Surgical workorder prioritizes exported gate-or-auth/entry functions
    const plan = buildWeavePlan(dir);
    const licTarget = plan.targets.find((t) =>
      t.relativePath.endsWith("license.cjs"),
    )!;
    expect(licTarget.surgicalWorkorder!.entryFunctions[0]!.name).toBe(
      "evaluateOrder",
    );
    expect(licTarget.surgicalWorkorder!.entryFunctions[0]!.exported).toBe(true);

    // Harden with selfSeal + sidecarEntangle + weaveDecoys
    const hardenRep = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      selfSeal: true,
      sidecarEntangle: true,
      weaveDecoys: true,
    });
    expect(hardenRep.overallSuccess).toBe(true);
    expect(hardenRep.integrityCoverageSelfVerified).toBe(true);

    // Post-harden verification of the hardened output directory with verifyWeaveTarget
    const postWeave = verifyWeaveTarget(hardenRep.outputDirectory);
    expect(postWeave.overallPassed).toBe(true);
    expect(postWeave.weaveScore).toBe(100);
    expect(postWeave.agentActions).toHaveLength(0);

    // Execute hardened modules in a child Node process to test clean execution + tamper hard-fail
    const req = createRequire(import.meta.url);
    const hardenedLic = hardenRep.artifacts.find((a) =>
      a.relativePath.endsWith("license.cjs"),
    )!.outputPath;
    const hardenedHelper = hardenRep.artifacts.find((a) =>
      a.relativePath.endsWith("helper.cjs"),
    )!.outputPath;
    const hardenedWorker = hardenRep.artifacts.find((a) =>
      a.relativePath.endsWith("worker.py"),
    )!.outputPath;

    const loaded = req(hardenedLic) as { evaluateOrder: (n: number) => number };
    expect(loaded.evaluateOrder(5)).toBe(15);

    // Red Team Attack 1: Tamper with sibling helper.cjs -> entry must hard-fail!
    const origHelperBytes = readFileSync(hardenedHelper);
    try {
      writeFileSync(hardenedHelper, Buffer.concat([origHelperBytes, Buffer.from("\n// tamper\n")]));
      delete req.cache[req.resolve(hardenedLic)];
      delete req.cache[req.resolve(hardenedHelper)];
      expect(() => req(hardenedLic)).toThrow(/integrity (?:check failed|binding mismatch)/);
    } finally {
      writeFileSync(hardenedHelper, origHelperBytes);
    }

    // Red Team Attack 2: Delete sibling worker.py -> sidecarEntangle/selfSeal must hard-fail!
    const origWorkerBytes = readFileSync(hardenedWorker);
    try {
      unlinkSync(hardenedWorker);
      delete req.cache[req.resolve(hardenedLic)];
      delete req.cache[req.resolve(hardenedHelper)];
      expect(() => req(hardenedLic)).toThrow(/integrity (?:check failed|binding mismatch)/);
    } finally {
      writeFileSync(hardenedWorker, origWorkerBytes);
    }
  });
});
