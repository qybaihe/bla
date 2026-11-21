import { describe, expect, it } from "vitest";
import {
  generateSidecarAsarMainJsPreamble,
  generateSidecarGgufLoaderSnippet,
  generateSidecarJsPreamble,
  generateSidecarPycLoaderSnippet,
  generateSidecarPythonPreamble,
  generateSidecarSafetensorsLoaderSnippet,
  generateSidecarWasmLoaderSnippet,
} from "../src/shields/runtime/sidecar-entangle.js";

const HEX = "a".repeat(64);

/** Values that are invalid identifiers in both JavaScript and Python. */
const HOSTILE_NAMES = ["x\nimport os", "x = 1", "1bad", "x;alert(1)", "x-y", ""];

/** Valid in JavaScript (`$` is an identifier character), never in Python. */
const PYTHON_ONLY_HOSTILE = ["$ok", "a$b"];

/**
 * Every preamble/loader generator interpolates `bindingName` into the code that
 * ships inside the protected artifact, so each one must validate it. Only two
 * sites did before this suite; the six below cover the rest.
 */
describe("sidecar bindingName override validation", () => {
  const flatten = (preamble: string): string => preamble.replace(/\s+/g, " ");

  it("generateSidecarJsPreamble keeps rejecting non-identifiers", () => {
    for (const bindingName of HOSTILE_NAMES) {
      expect(() =>
        generateSidecarJsPreamble({
          entryPath: "main.js",
          sidecarPaths: ["sib.js"],
          expectedHex: HEX,
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarJsPreamble({
      entryPath: "main.js",
      sidecarPaths: ["sib.js"],
      expectedHex: HEX,
      bindingName: "$myBinding",
    });
    expect(ok.bindingName).toBe("$myBinding");
    expect(ok.preamble).toContain("var $myBinding = 0;");
  });

  it("generateSidecarPythonPreamble rejects non-identifiers", () => {
    for (const bindingName of [...HOSTILE_NAMES, ...PYTHON_ONLY_HOSTILE]) {
      expect(() =>
        generateSidecarPythonPreamble({
          entryPath: "main.py",
          sidecarPaths: ["sib.py"],
          expectedHex: HEX,
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarPythonPreamble({
      entryPath: "main.py",
      sidecarPaths: ["sib.py"],
      expectedHex: HEX,
      bindingName: "_my_binding",
    });
    expect(ok.bindingName).toBe("_my_binding");
    expect(ok.preamble).toContain("_my_binding = 0");
  });

  it("generateSidecarWasmLoaderSnippet rejects non-identifiers", () => {
    for (const bindingName of HOSTILE_NAMES) {
      expect(() =>
        generateSidecarWasmLoaderSnippet({
          codeIdentityHex: HEX,
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarWasmLoaderSnippet({
      codeIdentityHex: HEX,
      bindingName: "$wasmBinding",
    });
    expect(ok.bindingName).toBe("$wasmBinding");
    expect(ok.preamble).toContain("var $wasmBinding = { ok: false };");
  });

  it("generateSidecarAsarMainJsPreamble rejects non-identifiers", () => {
    for (const bindingName of HOSTILE_NAMES) {
      expect(() =>
        generateSidecarAsarMainJsPreamble({
          entryPath: "main.js",
          mainRelativePath: "main.js",
          sidecarPaths: ["bridge.js"],
          expectedHex: HEX,
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarAsarMainJsPreamble({
      entryPath: "main.js",
      mainRelativePath: "main.js",
      sidecarPaths: ["bridge.js"],
      expectedHex: HEX,
      bindingName: "$asarBinding",
    });
    expect(ok.bindingName).toBe("$asarBinding");
    expect(flatten(ok.preamble)).toContain("var $asarBinding = 0;");
  });

  it("generateSidecarPycLoaderSnippet rejects non-identifiers", () => {
    for (const bindingName of [...HOSTILE_NAMES, ...PYTHON_ONLY_HOSTILE]) {
      expect(() =>
        generateSidecarPycLoaderSnippet({
          codeIdentityHex: HEX,
          pycRelPaths: ["sample.pyc"],
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarPycLoaderSnippet({
      codeIdentityHex: HEX,
      pycRelPaths: ["sample.pyc"],
      bindingName: "_pyc_binding",
    });
    expect(ok.bindingName).toBe("_pyc_binding");
    expect(ok.preamble).toContain("def _pyc_binding():");
  });

  it("generateSidecarGgufLoaderSnippet rejects non-identifiers", () => {
    for (const bindingName of [...HOSTILE_NAMES, ...PYTHON_ONLY_HOSTILE]) {
      expect(() =>
        generateSidecarGgufLoaderSnippet({
          codeIdentityHex: HEX,
          ggufRelPaths: ["model.gguf"],
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarGgufLoaderSnippet({
      codeIdentityHex: HEX,
      ggufRelPaths: ["model.gguf"],
      bindingName: "_gguf_binding",
    });
    expect(ok.bindingName).toBe("_gguf_binding");
    expect(ok.preamble).toContain("def _gguf_binding():");
  });

  it("generateSidecarSafetensorsLoaderSnippet rejects non-identifiers", () => {
    for (const bindingName of [...HOSTILE_NAMES, ...PYTHON_ONLY_HOSTILE]) {
      expect(() =>
        generateSidecarSafetensorsLoaderSnippet({
          codeIdentityHex: HEX,
          safetensorsRelPaths: ["model.safetensors"],
          bindingName,
        }),
      ).toThrow(/identifier/);
    }
    const ok = generateSidecarSafetensorsLoaderSnippet({
      codeIdentityHex: HEX,
      safetensorsRelPaths: ["model.safetensors"],
      bindingName: "_safetensors_binding",
    });
    expect(ok.bindingName).toBe("_safetensors_binding");
    expect(ok.preamble).toContain("def _safetensors_binding():");
  });

  it("defaults are unaffected for every generator", () => {
    const js = generateSidecarJsPreamble({
      entryPath: "main.js",
      sidecarPaths: ["sib.js"],
      expectedHex: HEX,
    });
    expect(js.bindingName).toMatch(/^_verifySiblingDigest_[0-9a-f]{8}$/);

    const py = generateSidecarPythonPreamble({
      entryPath: "main.py",
      sidecarPaths: ["sib.py"],
      expectedHex: HEX,
    });
    expect(py.bindingName).toMatch(/^_verify_sibling_digest_[0-9a-f]{8}$/);

    const wasm = generateSidecarWasmLoaderSnippet({ codeIdentityHex: HEX });
    expect(wasm.bindingName).toMatch(/^_installWasmSidecarLoaderHook_[0-9a-f]{8}$/);

    const asar = generateSidecarAsarMainJsPreamble({
      entryPath: "main.js",
      mainRelativePath: "main.js",
      sidecarPaths: ["bridge.js"],
      expectedHex: HEX,
    });
    expect(asar.bindingName).toBe("__blaAsarSidecarDigest");

    const pyc = generateSidecarPycLoaderSnippet({
      codeIdentityHex: HEX,
      pycRelPaths: ["sample.pyc"],
    });
    expect(pyc.bindingName).toMatch(/^_installPycSidecarLoaderHook_[0-9a-f]{8}$/);

    const gguf = generateSidecarGgufLoaderSnippet({
      codeIdentityHex: HEX,
      ggufRelPaths: ["model.gguf"],
    });
    expect(gguf.bindingName).toMatch(/^_installGgufSidecarLoaderHook_[0-9a-f]{8}$/);

    const safetensors = generateSidecarSafetensorsLoaderSnippet({
      codeIdentityHex: HEX,
      safetensorsRelPaths: ["model.safetensors"],
    });
    expect(safetensors.bindingName).toMatch(/^_installSafetensorsSidecarLoaderHook_[0-9a-f]{8}$/);
  });
});
