import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { detectArtifactFormat } from "../core/detector.js";
import {
  BUN_SIDECAR_COMPANION_SUFFIX,
  verifyAsarSidecarArchiveNote,
  verifyBunSidecarCompanionNote,
  verifyGgufSidecarMetadataNote,
  verifyPycSidecarMarshalNote,
  verifySafetensorsSidecarMetadataNote,
  verifyDexSidecarStringPoolNote,
  verifyWasmSidecarCustomSection,
} from "../shields/runtime/sidecar-entangle.js";

export type SidecarVerifierKind =
  | "bun-companion-note"
  | "wasm-custom-section"
  | "asar-archive-note"
  | "pyc-marshal-note"
  | "gguf-metadata-note"
  | "safetensors-metadata-note"
  | "dex-string-pool-note"
  | "runtime-only"
  | "entry-missing";

export interface SidecarVerifyReport {
  readonly ok: boolean;
  readonly entryPath: string;
  readonly format: string;
  readonly verifier: SidecarVerifierKind;
  readonly reason: string;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
}

function report(
  ok: boolean,
  entryPath: string,
  format: string,
  verifier: SidecarVerifierKind,
  reason: string,
  extra: { expectedHex?: string; measuredHex?: string } = {},
): SidecarVerifyReport {
  return {
    ok,
    entryPath,
    format,
    verifier,
    reason,
    ...(extra.expectedHex !== undefined ? { expectedHex: extra.expectedHex } : {}),
    ...(extra.measuredHex !== undefined ? { measuredHex: extra.measuredHex } : {}),
  };
}

/**
 * Offline strip⇒fail verification for an artifact's sidecar entanglement.
 * Dispatches to the format-specific `verify*Sidecar*` host check; formats
 * whose binding only exists inside the runtime preamble are reported as
 * `runtime-only` instead of being silently treated as verified.
 */
export function verifySidecarTarget(
  entryPath: string,
  baseDir?: string,
): SidecarVerifyReport {
  const abs = resolve(entryPath);
  if (!existsSync(abs)) {
    return report(false, abs, "unknown", "entry-missing", "entry path not found");
  }
  const bytes = readFileSync(abs);
  const dir = baseDir !== undefined ? resolve(baseDir) : dirname(abs);
  const format = detectArtifactFormat(abs);

  const companionPath = `${abs}${BUN_SIDECAR_COMPANION_SUFFIX}`;
  if (existsSync(companionPath)) {
    const result = verifyBunSidecarCompanionNote({
      noteBytes: readFileSync(companionPath),
      baseDir: dir,
    });
    return report(
      result.ok,
      abs,
      format,
      "bun-companion-note",
      result.ok
        ? "bun companion note intact"
        : (result.reason ?? "bun companion note verification failed"),
      { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
    );
  }

  switch (format) {
    case "wasm": {
      const result = verifyWasmSidecarCustomSection({ wasmBytes: bytes, baseDir: dir });
      return report(
        result.ok,
        abs,
        format,
        "wasm-custom-section",
        result.ok
          ? "wasm sidecar custom section intact"
          : (result.reason ?? "wasm sidecar verification failed"),
        { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
      );
    }
    case "electron-asar": {
      const result = verifyAsarSidecarArchiveNote({ asarBytes: bytes });
      return report(
        result.ok,
        abs,
        format,
        "asar-archive-note",
        result.ok
          ? "asar archive note intact"
          : (result.reason ?? "asar sidecar verification failed"),
        { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
      );
    }
    case "python-pyc": {
      const result = verifyPycSidecarMarshalNote({ entryBytes: bytes, baseDir: dir });
      return report(
        result.ok,
        abs,
        format,
        "pyc-marshal-note",
        result.ok
          ? "pyc marshal note intact"
          : (result.reason ?? "pyc sidecar verification failed"),
        { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
      );
    }
    case "model-gguf": {
      const result = verifyGgufSidecarMetadataNote({ entryBytes: bytes, baseDir: dir });
      return report(
        result.ok,
        abs,
        format,
        "gguf-metadata-note",
        result.ok
          ? "gguf metadata note intact"
          : (result.reason ?? "gguf sidecar verification failed"),
        { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
      );
    }
    case "model-safetensors": {
      const result = verifySafetensorsSidecarMetadataNote({
        entryBytes: bytes,
        baseDir: dir,
      });
      return report(
        result.ok,
        abs,
        format,
        "safetensors-metadata-note",
        result.ok
          ? "safetensors metadata note intact"
          : (result.reason ?? "safetensors sidecar verification failed"),
        { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
      );
    }
    case "android-dex": {
      const result = verifyDexSidecarStringPoolNote({
        entryBytes: bytes,
        baseDir: dir,
      });
      return report(
        result.ok,
        abs,
        format,
        "dex-string-pool-note",
        result.ok
          ? "dex string-pool note intact"
          : (result.reason ?? "dex sidecar verification failed"),
        { expectedHex: result.expectedHex, measuredHex: result.measuredHex },
      );
    }
    default:
      return report(
        false,
        abs,
        format,
        "runtime-only",
        `no offline sidecar verifier for ${format}; strip⇒fail binding is checked at runtime`,
      );
  }
}
