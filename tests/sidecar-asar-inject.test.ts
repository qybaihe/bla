import { describe, expect, it } from "vitest";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ASAR_SIDECAR_ARCHIVE_NOTE_KIND,
  ASAR_SIDECAR_ARCHIVE_NOTE_PATH,
  bindAsarSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarAsarArchiveNote,
  SIDECAR_ENTANGLE_SCHEMA,
  verifyAsarSidecarArchiveNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import { packAsarBuffer, unpackAsarBuffer } from "../src/shields/formats/asar.js";
import { protectTarget } from "../src/engine/protector.js";

describe("sidecar ASAR archive-note strip⇒fail", () => {
  it("generateSidecarAsarArchiveNote rejects non-hex expected digests", () => {
    expect(() =>
      generateSidecarAsarArchiveNote({
        entryPath: "app.asar",
        sidecarPaths: ["enclave/hardware-tee-bridge.js"],
        expectedHex: "deadbeef",
      }),
    ).toThrow(/64-char/);
  });

  it("bindAsarSidecarEntanglement emits archive note without mutating caller buffers", () => {
    const entry = Buffer.from("asar-placeholder");
    const bridge = Buffer.from("export function verifyHardwareEnclaveLease(){return true}\n");
    const before = Buffer.from(entry);
    const bound = bindAsarSidecarEntanglement({
      entryPath: "app.asar",
      sidecarPaths: ["enclave/hardware-tee-bridge.js"],
      seedTag: "asar-inject-v1",
      entryBytes: entry,
      sidecarBytes: [bridge],
    });
    expect(bound.plan.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("asar-archive-note");
    expect(bound.inject.kind).toBe(ASAR_SIDECAR_ARCHIVE_NOTE_KIND);
    expect(bound.inject.archiveNotePath).toBe(ASAR_SIDECAR_ARCHIVE_NOTE_PATH);
    expect(bound.inject.expectedHex).toBe(bound.digest.hex);
    expect(Buffer.compare(entry, before)).toBe(0);
    const parsed = JSON.parse(bound.inject.noteJson);
    expect(parsed.kind).toBe(ASAR_SIDECAR_ARCHIVE_NOTE_KIND);
    expect(parsed.digest).toBe(bound.digest.hex);
    expect(parsed.sidecarPaths).toEqual(["enclave/hardware-tee-bridge.js"]);
  });

  it("digest matches computeSidecarBindingDigest sidecars-mode", () => {
    const entry = Buffer.from("asar-bytes");
    const bridge = Buffer.from("bridge-body\n");
    const digest = computeSidecarBindingDigest(
      { pathLabel: "app.asar", bytes: entry },
      [{ pathLabel: "enclave/hardware-tee-bridge.js", bytes: bridge }],
      "parity-asar-v1",
    );
    const inject = generateSidecarAsarArchiveNote({
      entryPath: "app.asar",
      sidecarPaths: ["enclave/hardware-tee-bridge.js"],
      seedTag: "parity-asar-v1",
      expectedHex: digest.hex,
    });
    expect(inject.expectedHex).toBe(digest.hex);
    expect(inject.expectedU32).toBe(digest.u32);
    expect(inject.note.digest).toBe(digest.hex);
  });

  it("verify: intact members pass; mutate or strip bridge fails", () => {
    const bridgePath = "enclave/hardware-tee-bridge.js";
    const bridgeBytes = Buffer.from("bridge-ok\n");
    const bound = bindAsarSidecarEntanglement({
      entryPath: "app.asar",
      sidecarPaths: [bridgePath],
      seedTag: "verify-asar-v1",
      entryBytes: Buffer.from("entry"),
      sidecarBytes: [bridgeBytes],
    });
    const packed = packAsarBuffer([
      { relativePath: "main.js", content: Buffer.from("console.log(1)\n") },
      { relativePath: bridgePath, content: bridgeBytes },
      { relativePath: ASAR_SIDECAR_ARCHIVE_NOTE_PATH, content: bound.noteBytes },
    ]);

    const ok = verifyAsarSidecarArchiveNote({ asarBytes: packed });
    expect(ok.ok).toBe(true);
    expect(ok.measuredHex).toBe(bound.digest.hex);

    const tampered = packAsarBuffer([
      { relativePath: "main.js", content: Buffer.from("console.log(1)\n") },
      { relativePath: bridgePath, content: Buffer.from("tampered\n") },
      { relativePath: ASAR_SIDECAR_ARCHIVE_NOTE_PATH, content: bound.noteBytes },
    ]);
    const bad = verifyAsarSidecarArchiveNote({ asarBytes: tampered });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/mismatch/);

    const stripped = packAsarBuffer([
      { relativePath: "main.js", content: Buffer.from("console.log(1)\n") },
      { relativePath: ASAR_SIDECAR_ARCHIVE_NOTE_PATH, content: bound.noteBytes },
    ]);
    const missing = verifyAsarSidecarArchiveNote({ asarBytes: stripped });
    expect(missing.ok).toBe(false);
  });

  it("protectTarget with sidecarEntangle plants .bla/sidecar.v1.json; strip bridge fails verify", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-asar-protect-"));
    try {
      const input = join(dir, "app.asar");
      const output = join(dir, "out", "app.asar");
      writeFileSync(
        input,
        packAsarBuffer([
          { relativePath: "main.js", content: Buffer.from("exports.x = 1;\n") },
          {
            relativePath: "package.json",
            content: Buffer.from('{"main":"main.js"}\n'),
          },
        ]),
      );
      const res = protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "balanced",
        seed: "asar-entangle-protect-1",
        sidecarEntangle: true,
      });
      expect(res.counteredReaVectors).toContain("asar-header-admission");
      expect(res.sidecarEntangle).toBe(true);
      expect(existsSync(output)).toBe(true);
      const members = unpackAsarBuffer(readFileSync(output));
      expect(members.some((m) => m.relativePath === ASAR_SIDECAR_ARCHIVE_NOTE_PATH)).toBe(
        true,
      );
      expect(
        members.some((m) => m.relativePath === "enclave/hardware-tee-bridge.js"),
      ).toBe(true);
      const verified = verifyAsarSidecarArchiveNote({
        asarBytes: readFileSync(output),
      });
      expect(verified.ok).toBe(true);

      // Strip decoy bridge ⇒ verify fails.
      const withoutBridge = members.filter(
        (m) => m.relativePath !== "enclave/hardware-tee-bridge.js",
      );
      const strippedAsar = packAsarBuffer(withoutBridge);
      expect(
        verifyAsarSidecarArchiveNote({ asarBytes: strippedAsar }).ok,
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget default (sidecarEntangle off) does not plant archive note", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-asar-off-"));
    try {
      const input = join(dir, "app.asar");
      const output = join(dir, "out", "app.asar");
      writeFileSync(
        input,
        packAsarBuffer([
          { relativePath: "main.js", content: Buffer.from("exports.x = 1;\n") },
        ]),
      );
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "stealth",
        seed: "asar-entangle-off",
      });
      const members = unpackAsarBuffer(readFileSync(output));
      expect(members.some((m) => m.relativePath === ASAR_SIDECAR_ARCHIVE_NOTE_PATH)).toBe(
        false,
      );
      // decoy bridge still planted by protect
      expect(
        members.some((m) => m.relativePath === "enclave/hardware-tee-bridge.js"),
      ).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
