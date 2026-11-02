import { describe, expect, it } from "vitest";
import * as vm from "node:vm";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import { SeededPrng } from "../src/core/prng.js";
import {
  encodeSplitShareString,
  generateShadowHeapChurnShield,
  generateSplitShareRuntimeHelper,
} from "../src/shields/runtime/memory-diff-shield.js";
import { generateFridaCaptureSaturation } from "../src/shields/exhaustion/frida-capture-saturation.js";
import { REA_BUDGET_BREAKER_MATRIX } from "../src/shields/exhaustion/rea-budget-matrix.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import { lintLaneIndependence } from "../src/engine/lane-independence-lint.js";

describe("Counter-REA Runtime Memory Diff & Heap Churn Shield", () => {
  it("Floods M0 -> M1 differential memory snapshots with > 35 synchronized decoy mutations on every function call", () => {
    const sourceCode = `
      let realLicenseCounter = 100;
      function checkEnterpriseSeat(seatId) {
        realLicenseCounter += 1;
        return "SEAT_OK:" + seatId + ":" + realLicenseCounter;
      }
      module.exports = { checkEnterpriseSeat, getCounter: () => realLicenseCounter };
    `;

    const protectedBundle = transformJavaScriptWithBlaShield(sourceCode, {
      intensity: "bankrupt",
      seed: "mem-diff-test",
    });

    expect(protectedBundle.shadowHeapSlotsChurned).toBe(64);
    expect(
      protectedBundle.memoryDiffShield.exceedsEnvironmentStepDiffLimit,
    ).toBe(true);
    expect(
      protectedBundle.memoryDiffShield.exceedsHardwareWatchpointLimit,
    ).toBe(true);

    const heapName = protectedBundle.memoryDiffShield.heapObjectName;
    const mod = { exports: {} as Record<string, (...args: unknown[]) => unknown> };
    const ctx = vm.createContext({
      module: mod,
      exports: mod.exports,
      Math,
      Object,
      Array,
      String,
      Number,
      Boolean,
    });

    vm.runInContext(protectedBundle.code, ctx, { timeout: 3000 });

    // Capture M0 snapshot of the shadow heap before invoking the business function
    const snapshotBefore = JSON.parse(
      vm.runInContext(`JSON.stringify(${heapName})`, ctx) as string,
    );

    // Execute the protected business function once (M0 -> M1 transition)
    const out1 = mod.exports.checkEnterpriseSeat!("seat-42");
    expect(out1).toBe("SEAT_OK:seat-42:101");

    // Capture M1 snapshot after invoking the business function
    const snapshotAfter = JSON.parse(
      vm.runInContext(`JSON.stringify(${heapName})`, ctx) as string,
    );

    // 1. Verify >= 8 shadow slots mutated their 32-bit key/digest words in-place
    let mutatedSlots = 0;
    for (let i = 0; i < snapshotBefore.slots.length; i++) {
      if (
        JSON.stringify(snapshotBefore.slots[i].words) !==
        JSON.stringify(snapshotAfter.slots[i].words)
      ) {
        mutatedSlots++;
      }
    }
    expect(mutatedSlots).toBe(8);

    // 2. Verify > 20 diffEnvelope fields mutated (exceeding REA's STEP_DIFFERENCE_LIMIT = 20)
    const beforeEnvKeys = Object.keys(snapshotBefore.diffEnvelope);
    let mutatedDiffFields = 0;
    for (const k of beforeEnvKeys) {
      if (snapshotBefore.diffEnvelope[k] !== snapshotAfter.diffEnvelope[k]) {
        mutatedDiffFields++;
      }
    }
    expect(mutatedDiffFields).toBeGreaterThan(
      REA_INTERNAL_LIMITS.ENVIRONMENT_COMPARE_STEP_DIFF_LIMIT,
    );

    // 3. Verify splitShareA and splitShareB both mutated in-place in memory
    expect(snapshotAfter.splitShareA).not.toEqual(snapshotBefore.splitShareA);
    expect(snapshotAfter.splitShareB).not.toEqual(snapshotBefore.splitShareB);
  });

  it("Reconstructs Split-Share XOR strings with 100% accuracy while mutating both share buffers in RAM on every read", () => {
    const prng = new SeededPrng("split-share-test");
    const secret = "sk-live-enclave-quorum-998877665544332211";
    const encoded = encodeSplitShareString(secret, prng);

    // Neither share contains the raw ASCII char codes of the secret
    const rawCharCodes = Array.from(secret, (ch) => ch.charCodeAt(0));
    expect(encoded.shareA).not.toEqual(rawCharCodes);
    expect(encoded.shareB).not.toEqual(rawCharCodes);

    const helper = generateSplitShareRuntimeHelper("test99");
    const shareA = [...encoded.shareA];
    const shareB = [...encoded.shareB];

    const readerFn = new Function(
      "shareA",
      "shareB",
      `${helper.code}\nreturn ${helper.helperFunctionName}(shareA, shareB);`,
    ) as (a: number[], b: number[]) => string;

    for (let round = 0; round < 10; round++) {
      const prevA = [...shareA];
      const prevB = [...shareB];
      const decoded = readerFn(shareA, shareB);

      // Output is 100% invariant across all reads
      expect(decoded).toBe(secret);

      // Both memory buffers mutated in-place on this read
      expect(shareA).not.toEqual(prevA);
      expect(shareB).not.toEqual(prevB);
    }
  });


  it("R9: shadow-heap decoy tables avoid lane-lint BYTE_COMPARE_ARRAY even beside key identifiers", () => {
    const prng = new SeededPrng("r9-lane-quiet-decoy");
    const shield = generateShadowHeapChurnShield(prng, "bankrupt");
    // Must not emit [n, n, n, n+] numeric literals (R8 red residual → R9 blue).
    expect(shield.code).not.toMatch(
      /\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d+)\s*){3,}\]/,
    );
    expect(shield.code).toContain('splitShareA: "');
    expect(shield.code).toContain(".split(\",\").map");
    expect(shield.code).toContain(".concat([");
    const report = lintLaneIndependence(
      "// key guess input lane entitlement gate\n" + shield.code,
    );
    expect(report.looksLaneIndependent).toBe(false);
    expect(report.findings).toEqual([]);
  });

  it("Triggers Frida capture saturation and realm-agnostic ring churn even when globalThis.Frida is isolated in Frida Gum", () => {
    const prng = new SeededPrng("frida-realm-isolated");
    const sat = generateFridaCaptureSaturation(prng, "bankrupt");
    expect(sat.realmAgnosticRingSlots).toBe(32);

    // Run in a clean context with NO globalThis.Frida and NO globalThis.Interceptor
    const fnNameMatch = sat.code.match(/function\s+(fridaCaptureSaturator_[a-f0-9]+)/);
    expect(fnNameMatch).not.toBeNull();
    const fnName = fnNameMatch![1]!;

    const runFn = new Function(
      `${sat.code}\nreturn ${fnName}();`,
    ) as () => { description: string; payload: Record<string, unknown> };

    const envelope = runFn();
    expect(envelope).not.toBeNull();
    expect(envelope.description.length).toBeGreaterThan(
      REA_INTERNAL_LIMITS.LLDB_MAX_SELECTOR_BYTES,
    );
  });

  it("Catalogs REA's LLDB, GDB, Rizin, and Environment-Compare runtime limits and emits native shadow heap slots", () => {
    expect(REA_INTERNAL_LIMITS.LLDB_MAX_TRACE_BYTES).toBe(8_388_608);
    expect(REA_INTERNAL_LIMITS.LLDB_MAX_TRACE_FRAMES).toBe(65_536);
    expect(REA_INTERNAL_LIMITS.LLDB_MAX_OTHER_STOPS).toBe(256);
    expect(REA_INTERNAL_LIMITS.GDB_MAX_COMMAND_OUTPUT_RECORDS).toBe(16_384);
    expect(REA_INTERNAL_LIMITS.RIZIN_MAX_COMMAND_FRAMES).toBe(4_096);
    expect(REA_INTERNAL_LIMITS.ENVIRONMENT_COMPARE_STEP_DIFF_LIMIT).toBe(20);

    const matrixIds = REA_BUDGET_BREAKER_MATRIX.map((m) => m.id);
    expect(matrixIds).toContain("lldb-trace-frames");
    expect(matrixIds).toContain("lldb-other-stops");
    expect(matrixIds).toContain("gdb-command-output-records");
    expect(matrixIds).toContain("rizin-command-frames");
    expect(matrixIds).toContain("environment-compare-step-diff");

    const cHeader = emitCompileTimeNativeHeader("c", { intensity: "balanced", seed: "c-mem" });
    expect(cHeader.content).toContain("shadow_heap_slots[32]");

    const goHeader = emitCompileTimeNativeHeader("go", { intensity: "balanced", seed: "go-mem" });
    expect(goHeader.content).toContain("ShadowHeapSlots = [16]uint32");
  });
});
