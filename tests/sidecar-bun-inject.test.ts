import { describe, expect, it } from "vitest";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  BUN_SIDECAR_COMPANION_KIND,
  BUN_SIDECAR_COMPANION_SUFFIX,
  bindBunSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarBunCompanionNote,
  SIDECAR_ENTANGLE_SCHEMA,
  verifyBunSidecarCompanionNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import { protectTarget } from "../src/engine/protector.js";
import { SeededPrng } from "../src/core/prng.js";
import {
  BUN_TRAILER,
  generateBunStandaloneDecoyGraph,
} from "../src/shields/formats/bun-standalone.js";

/** Minimal ELF-like bytes ending with a Bun appended-trailer decoy graph. */
function fixtureBunCarrier(): Buffer {
  const payload = Buffer.alloc(64, 0x41);
  // Offsets(32) + trailer — enough for detectBunStandaloneGraph appended-trailer.
  const offsets = Buffer.alloc(32, 0);
  offsets.writeBigUInt64LE(BigInt(payload.length), 0);
  return Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]), // ELF64 magic-ish head
    Buffer.alloc(120, 0),
    payload,
    offsets,
    BUN_TRAILER,
  ]);
}

describe("sidecar Bun companion-note strip⇒fail", () => {
  it("generateSidecarBunCompanionNote rejects non-hex expected digests", () => {
    expect(() =>
      generateSidecarBunCompanionNote({
        entryPath: "app",
        sidecarPaths: ["app.bunfs-snapshot"],
        expectedHex: "deadbeef",
      }),
    ).toThrow(/64-char/);
  });

  it("bindBunSidecarEntanglement leaves entry bytes untouched and emits companion note", () => {
    const entry = fixtureBunCarrier();
    const snapshot = Buffer.from("decoy-graph-bytes\n");
    const before = Buffer.from(entry);
    const bound = bindBunSidecarEntanglement({
      entryPath: "app",
      sidecarPaths: ["app.bunfs-snapshot"],
      seedTag: "bun-inject-v1",
      entryBytes: entry,
      sidecarBytes: [snapshot],
    });
    expect(bound.plan.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("bun-companion-note");
    expect(bound.inject.kind).toBe(BUN_SIDECAR_COMPANION_KIND);
    expect(bound.inject.companionSuffix).toBe(BUN_SIDECAR_COMPANION_SUFFIX);
    expect(bound.inject.expectedHex).toBe(bound.digest.hex);
    expect(Buffer.compare(entry, before)).toBe(0);
    const parsed = JSON.parse(bound.inject.noteJson);
    expect(parsed.kind).toBe(BUN_SIDECAR_COMPANION_KIND);
    expect(parsed.digest).toBe(bound.digest.hex);
    expect(parsed.sidecarPaths).toEqual(["app.bunfs-snapshot"]);
  });

  it("digest matches computeSidecarBindingDigest sidecars-mode", () => {
    const entry = fixtureBunCarrier();
    const snap = Buffer.from("sidecar-payload\n");
    const digest = computeSidecarBindingDigest(
      { pathLabel: "app", bytes: entry },
      [{ pathLabel: "app.bunfs-snapshot", bytes: snap }],
      "parity-bun-v1",
    );
    const inject = generateSidecarBunCompanionNote({
      entryPath: "app",
      sidecarPaths: ["app.bunfs-snapshot"],
      seedTag: "parity-bun-v1",
      expectedHex: digest.hex,
    });
    expect(inject.expectedHex).toBe(digest.hex);
    expect(inject.expectedU32).toBe(digest.u32);
    expect(inject.note.digest).toBe(digest.hex);
  });

  it("verify: intact sidecars pass; mutate or strip snapshot fails", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-bun-inject-"));
    try {
      const entry = fixtureBunCarrier();
      const snapName = "app.bunfs-snapshot";
      const snapBytes = Buffer.from("bun-decoy-graph\n");
      writeFileSync(join(dir, snapName), snapBytes);
      const bound = bindBunSidecarEntanglement({
        entryPath: "app",
        sidecarPaths: [snapName],
        seedTag: "verify-bun-v1",
        entryBytes: entry,
        sidecarBytes: [snapBytes],
      });
      const notePath = join(dir, `app${BUN_SIDECAR_COMPANION_SUFFIX}`);
      writeFileSync(notePath, bound.noteBytes);

      const ok = verifyBunSidecarCompanionNote({
        noteBytes: readFileSync(notePath),
        baseDir: dir,
      });
      expect(ok.ok).toBe(true);
      expect(ok.measuredHex).toBe(bound.digest.hex);

      writeFileSync(join(dir, snapName), Buffer.from("tampered\n"));
      const bad = verifyBunSidecarCompanionNote({
        noteBytes: readFileSync(notePath),
        baseDir: dir,
      });
      expect(bad.ok).toBe(false);
      expect(bad.reason).toMatch(/mismatch/);

      rmSync(join(dir, snapName));
      const missing = verifyBunSidecarCompanionNote({
        noteBytes: readFileSync(notePath),
        baseDir: dir,
      });
      expect(missing.ok).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget with sidecarEntangle plants companion note next to Bun carrier; binary byte-exact", () => {
    const hostElf = "/bin/true";
    if (!existsSync(hostElf)) return;
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-bun-protect-"));
    try {
      const input = join(dir, "app");
      const output = join(dir, "out", "app");
      const graph = generateBunStandaloneDecoyGraph(
        new SeededPrng("bun-entangle-embedded"),
        "stealth",
      ).buffer;
      writeFileSync(input, Buffer.concat([readFileSync(hostElf), graph]));
      chmodSync(input, 0o755);
      const inputBytes = readFileSync(input);
      const res = protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "balanced",
        seed: "bun-entangle-protect-1",
        sidecarEntangle: true,
      });
      expect(res.counteredReaVectors).toContain("bun-standalone-module-graph");
      expect(res.sidecarEntangle).toBe(true);
      expect(existsSync(`${output}.bunfs-snapshot`)).toBe(true);
      expect(existsSync(`${output}${BUN_SIDECAR_COMPANION_SUFFIX}`)).toBe(true);
      // Runtime red line: Bun/EOF carrier stays byte-exact.
      expect(readFileSync(output).equals(inputBytes)).toBe(true);
      const verified = verifyBunSidecarCompanionNote({
        noteBytes: readFileSync(`${output}${BUN_SIDECAR_COMPANION_SUFFIX}`),
        baseDir: join(dir, "out"),
      });
      expect(verified.ok).toBe(true);

      // Strip snapshot ⇒ verify fails.
      rmSync(`${output}.bunfs-snapshot`);
      expect(
        verifyBunSidecarCompanionNote({
          noteBytes: readFileSync(`${output}${BUN_SIDECAR_COMPANION_SUFFIX}`),
          baseDir: join(dir, "out"),
        }).ok,
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget default (sidecarEntangle off) does not plant companion note", () => {
    const hostElf = "/bin/true";
    if (!existsSync(hostElf)) return;
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-bun-off-"));
    try {
      const input = join(dir, "app");
      const output = join(dir, "out", "app");
      const graph = generateBunStandaloneDecoyGraph(
        new SeededPrng("bun-entangle-off"),
        "stealth",
      ).buffer;
      writeFileSync(input, Buffer.concat([readFileSync(hostElf), graph]));
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "balanced",
        seed: "bun-entangle-off-1",
        sidecarEntangle: false,
      });
      expect(existsSync(`${output}.bunfs-snapshot`)).toBe(true);
      expect(existsSync(`${output}${BUN_SIDECAR_COMPANION_SUFFIX}`)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
