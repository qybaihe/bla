import { describe, expect, it } from "vitest";
import { assertNoForbiddenMarkers } from "../src/core/identifiers.js";
import { SeededPrng } from "../src/core/prng.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import { protectPythonSource } from "../src/shields/formats/python.js";
import { generatePythonTarpit } from "../src/shields/tarpit/tarpit-generator.js";

const TEE_GREP = /TPM2_|NitroEnclave|hardware_enclave_stub|verify_enclave_attestation|authenticate_tpm/i;
const MUNDANE_HINT = /invoice|session_cache|telemetry|locale|backoff|wal_segment|catalog_facet|worker_pool|report_cursor|transport_frame|metric_histogram|gateway_policy|pipeline_shard|audit_sample|connection_pool|lookup_vector/i;

describe("Python decoy density + vocabulary diversification (WorkBuddy peel)", () => {
  it("emits no greppable _bla_ / BLA-SHIELD markers at maximum intensity", () => {
    const out = protectPythonSource("def main():\n    return 1\n", {
      intensity: "maximum",
      seed: "wb-python-density-1",
    });
    assertNoForbiddenMarkers(out.code, "python-maximum");
    expect(out.code).not.toContain("BLA-SHIELD");
    expect(out.code).not.toMatch(/\bpass\s*$/m);
    expect(out.decoyFunctionsInjected).toBeGreaterThanOrEqual(18);
  });

  it("mixes mundane stems so TEE/TPM grep cannot discard the whole decoy set", () => {
    const prng = new SeededPrng("wb-vocab-mix");
    const chaff = generateChaffPayloads(prng, "maximum");
    const tarpit = generatePythonTarpit(prng, "maximum", chaff);
    const names = tarpit.decoyFunctionNames.join("\n");
    expect(names).toMatch(MUNDANE_HINT);
    // Scare minority may still appear, but must not be 100% of decoy names.
    const scareHits = tarpit.decoyFunctionNames.filter((n) =>
      /enclave|tpm|vsock|hsm|attestation/i.test(n),
    ).length;
    expect(scareHits).toBeLessThan(tarpit.decoyFunctionNames.length);
  });

  it("decoy bodies mutate shared state and warm-init actually calls them", () => {
    const prng = new SeededPrng("wb-live-xref");
    const chaff = generateChaffPayloads(prng, "balanced");
    const tarpit = generatePythonTarpit(prng, "balanced", chaff);
    expect(tarpit.code).toMatch(/: dict = \{"epoch":/);
    expect(tarpit.code).toMatch(/\["warm"\]\s*=/);
    expect(tarpit.code).toMatch(/hash\(\w+\.__name__\)/);
    // At least two distinct body shapes (bytearray / nested _fold / window)
    const shapes = [
      /bytearray\(8\)/,
      /def _fold\(/,
      /window = \[/,
      /ord\(tag\[/,
    ].filter((re) => re.test(tarpit.code));
    expect(shapes.length).toBeGreaterThanOrEqual(2);
    expect(tarpit.crossReferenceEdges).toBeGreaterThanOrEqual(30);
  });

  it("chaff payloads are not exclusively TPM/Nitro/enclave scare strings", () => {
    const samples: string[] = [];
    for (const seed of ["chaff-a", "chaff-b", "chaff-c", "chaff-d"]) {
      const payloads = generateChaffPayloads(new SeededPrng(seed), "maximum");
      samples.push(...payloads.map((p) => p.rawText));
    }
    const altHits = samples.filter((s) =>
      /Billing Pipeline|Cache Topology|Scheduler Fabric|Observability Boundary|Localization Runtime|Storage Adapter|remote_rating_worker|cache_projection|QUEUE_LEASE_CONTRACT/i.test(
        s,
      ),
    );
    expect(altHits.length).toBeGreaterThanOrEqual(2);
    // Still keep some classic honey for intentional misdirection.
    expect(samples.some((s) => TEE_GREP.test(s))).toBe(true);
  });

  it("never emits the golden constant 0x9e3779b9 in Python tarpit mixers", () => {
    for (const seed of ["golden-py-1", "golden-py-2", "golden-py-3"]) {
      const prng = new SeededPrng(seed);
      const chaff = generateChaffPayloads(prng, "bankrupt");
      const tarpit = generatePythonTarpit(prng, "maximum", chaff);
      expect(tarpit.code).not.toMatch(/0x9e3779b9/i);
      expect(tarpit.code).not.toMatch(/\b2654435769\b/);
    }
  });
});
