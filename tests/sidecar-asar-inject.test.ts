import { describe, expect, it } from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";
import {
  ASAR_SIDECAR_ARCHIVE_NOTE_KIND,
  ASAR_SIDECAR_ARCHIVE_NOTE_PATH,
  ASAR_SIDECAR_MAIN_JS_MARKER,
  asarMemberPathFromMain,
  bindAsarSidecarEntanglement,
  computeSidecarBindingDigest,
  entangleAsarMainJsWithSidecars,
  generateSidecarAsarArchiveNote,
  generateSidecarAsarMainJsPreamble,
  selectAsarMainJsMember,
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

  it("asarMemberPathFromMain resolves nested mains back to asar root", () => {
    expect(asarMemberPathFromMain("main.js", "enclave/hardware-tee-bridge.js")).toBe(
      "enclave/hardware-tee-bridge.js",
    );
    expect(asarMemberPathFromMain("src/main.js", "enclave/hardware-tee-bridge.js")).toBe(
      "../enclave/hardware-tee-bridge.js",
    );
    expect(asarMemberPathFromMain("a/b/main.js", "a/c/x.js")).toBe("../c/x.js");
  });

  it("selectAsarMainJsMember prefers package.json#main", () => {
    expect(
      selectAsarMainJsMember([
        { relativePath: "package.json", content: Buffer.from('{"main":"src/boot.js"}\n') },
        { relativePath: "src/boot.js", content: Buffer.from("exports.ok=1\n") },
        { relativePath: "main.js", content: Buffer.from("exports.other=1\n") },
      ]),
    ).toBe("src/boot.js");
  });

  it("generateSidecarAsarMainJsPreamble matches digest and fails closed when sidecar missing", () => {
    const bridgePath = "enclave/hardware-tee-bridge.js";
    const bridgeBytes = Buffer.from("bridge-body\n");
    const entryLabel = "app.asar";
    const digest = computeSidecarBindingDigest(
      { pathLabel: entryLabel, bytes: Buffer.from("ignored") },
      [{ pathLabel: bridgePath, bytes: bridgeBytes }],
      "asar-main-js-v1",
      "sidecars",
    );
    const inject = generateSidecarAsarMainJsPreamble({
      entryPath: entryLabel,
      mainRelativePath: "main.js",
      sidecarPaths: [bridgePath],
      seedTag: "asar-main-js-v1",
      expectedHex: digest.hex,
    });
    expect(inject.bindingName).toBe(ASAR_SIDECAR_MAIN_JS_MARKER);
    expect(inject.preamble).toContain(ASAR_SIDECAR_MAIN_JS_MARKER);
    expect(inject.sidecarReadPaths).toEqual([bridgePath]);

    const dir = mkdtempSync(join(tmpdir(), "bla-asar-main-js-"));
    try {
      mkdirSync(join(dir, "enclave"), { recursive: true });
      writeFileSync(join(dir, bridgePath), bridgeBytes);
      writeFileSync(join(dir, "main.js"), `${inject.preamble}\nexports.x = 1;\n`);
      const src = readFileSync(join(dir, "main.js"), "utf8");
      const nodeRequire = createRequire(join(dir, "main.js"));
      const sandbox: Record<string, unknown> = {
        require: nodeRequire,
        exports: {},
        module: { exports: {} },
        console,
        Buffer,
        process,
        __dirname: dir,
        __filename: join(dir, "main.js"),
      };
      runInNewContext(src, sandbox, { filename: join(dir, "main.js") });
      expect(sandbox.exports).toMatchObject({ x: 1 });

      // Strip bridge ⇒ hard fail
      rmSync(join(dir, bridgePath));
      expect(() =>
        runInNewContext(
          src,
          {
            require: nodeRequire,
            exports: {},
            module: { exports: {} },
            console,
            Buffer,
            process,
            __dirname: dir,
            __filename: join(dir, "main.js"),
          },
          { filename: join(dir, "main.js") },
        ),
      ).toThrow(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget with sidecarEntangle prepends ASAR main JS preamble", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-asar-main-"));
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
        seed: "asar-main-preamble-1",
        sidecarEntangle: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.counteredReaVectors).toContain("asar-sidecar-entangle");
      const members = unpackAsarBuffer(readFileSync(output));
      const main = members.find((m) => m.relativePath === "main.js");
      expect(main).toBeTruthy();
      expect(main!.content.toString("utf8")).toContain(ASAR_SIDECAR_MAIN_JS_MARKER);
      expect(verifyAsarSidecarArchiveNote({ asarBytes: readFileSync(output) }).ok).toBe(
        true,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("entangleAsarMainJsWithSidecars is idempotent on marker", () => {
    const bridge = Buffer.from("b\n");
    const bound = bindAsarSidecarEntanglement({
      entryPath: "app.asar",
      sidecarPaths: ["enclave/hardware-tee-bridge.js"],
      seedTag: "idem-asar-main",
      entryBytes: Buffer.from("e"),
      sidecarBytes: [bridge],
    });
    const once = entangleAsarMainJsWithSidecars({
      members: [
        { relativePath: "main.js", content: Buffer.from("exports.x=1\n") },
        { relativePath: "enclave/hardware-tee-bridge.js", content: bridge },
        { relativePath: ASAR_SIDECAR_ARCHIVE_NOTE_PATH, content: bound.noteBytes },
      ],
      entryPath: "app.asar",
      expectedHex: bound.digest.hex,
      sidecarPaths: ["enclave/hardware-tee-bridge.js"],
      seedTag: "idem-asar-main",
    });
    expect(once).not.toBeNull();
    const twice = entangleAsarMainJsWithSidecars({
      members: once!.members,
      entryPath: "app.asar",
      expectedHex: bound.digest.hex,
      sidecarPaths: ["enclave/hardware-tee-bridge.js"],
      seedTag: "idem-asar-main",
    });
    const main1 = once!.members.find((m) => m.relativePath === "main.js")!.content.toString("utf8");
    const main2 = twice!.members.find((m) => m.relativePath === "main.js")!.content.toString("utf8");
    expect(main2).toBe(main1);
    expect(main1.includes(ASAR_SIDECAR_MAIN_JS_MARKER)).toBe(true);
    expect(main1.split(ASAR_SIDECAR_MAIN_JS_MARKER).length - 1).toBeGreaterThanOrEqual(1);
  });


});
