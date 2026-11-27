import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { generateRuntimeDeceptionSnippet } from "../src/shields/runtime/runtime-shield.js";

/**
 * Static de-blinding tools (LASIK-class) locate BLA's decorative shadow-runtime
 * decoy by its fixed strings — the old build emitted a byte-identical event
 * list plus `HARDWARE_ENCLAVE_DELEGATED` / `RING0_SEALED` / `AF_VSOCK_RING0`
 * and fixed hash salts every time. Those literals are now seed-derived. This
 * suite pins: (1) the decoy still runs with no side effects and stays
 * plausible, (2) the chosen literals vary across seeds (no single fixed
 * fingerprint), and (3) output is reproducible for a given seed.
 */

function registeredEventsFor(code: string): string[] {
  const events: string[] = [];
  const fakeGlobal: Record<string, unknown> = {
    navigator: { webdriver: true },
    addEventListener: (evName: string) => {
      events.push(evName);
    },
  };
  fakeGlobal.globalThis = fakeGlobal;
  const ctx = vm.createContext(fakeGlobal);
  vm.runInContext(code, ctx, { timeout: 2000 });
  return events;
}

function statusToken(code: string): string {
  return /status: "([A-Z0-9_]+)"/.exec(code)?.[1] ?? "";
}
function attestationToken(code: string): string {
  return /attestationState: "([A-Z0-9_]+)"/.exec(code)?.[1] ?? "";
}

describe("anti static de-blinding: runtime decoy strings carry no fixed fingerprint", () => {
  it("emits plausible, distinct, seed-derived event names and still runs clean", () => {
    for (let n = 0; n < 6; n++) {
      const prng = new SeededPrng(`rt-decoy-seed-${n}`);
      const snippet = generateRuntimeDeceptionSnippet(prng, "bankrupt", []);
      const events = registeredEventsFor(snippet.code);
      expect(events.length).toBe(10);
      expect(new Set(events).size).toBe(10);
      for (const ev of events) {
        expect(ev).toMatch(/^[a-z0-9]+:[a-z0-9-]+:[a-z0-9-]+$/);
      }
      expect(statusToken(snippet.code)).toMatch(/^[A-Z0-9_]+$/);
      expect(attestationToken(snippet.code)).toMatch(/^[A-Z0-9_]+$/);
    }
  });

  it("varies the decoy literals across seeds (no single greppable fingerprint)", () => {
    const statuses = new Set<string>();
    const attests = new Set<string>();
    const firstEvents = new Set<string>();
    for (let n = 0; n < 24; n++) {
      const snippet = generateRuntimeDeceptionSnippet(
        new SeededPrng(`rt-vary-${n}`),
        "bankrupt",
        [],
      );
      statuses.add(statusToken(snippet.code));
      attests.add(attestationToken(snippet.code));
      firstEvents.add(registeredEventsFor(snippet.code)[0] ?? "");
    }
    // Across 24 seeds we expect real spread, not a single fixed literal.
    expect(statuses.size).toBeGreaterThan(1);
    expect(attests.size).toBeGreaterThan(1);
    expect(firstEvents.size).toBeGreaterThan(3);
  });

  it("is reproducible for a given seed", () => {
    const a = generateRuntimeDeceptionSnippet(new SeededPrng("rt-repro"), "bankrupt", []);
    const b = generateRuntimeDeceptionSnippet(new SeededPrng("rt-repro"), "bankrupt", []);
    expect(a.code).toBe(b.code);
  });
});
