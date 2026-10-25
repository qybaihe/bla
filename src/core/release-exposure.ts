import { constants, closeSync, fstatSync, lstatSync, openSync, opendirSync, readSync, realpathSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";

export interface ReleaseExposureFinding {
  file: string;
  kind: "embedded-source-text" | "unverified-map-reference";
  evidenceBasis: "static-file-observation";
  representation: "standalone-map" | "inline-map" | "reference";
  /** Counts only: source names, content and reference URLs are deliberately omitted. */
  embeddedSourceCount?: number;
  embeddedSourceBytes?: number;
}
export interface ReleaseExposureReport {
  evidenceBasis: "static-file-observation";
  status: "complete" | "partial";
  scope: "local-map-and-js-ts-css-files-only";
  filesInspected: number;
  bytesRead: number;
  findings: ReleaseExposureFinding[];
  limitations: Array<{ file: string; reason: string }>;
  networkAccessed: false;
  targetModified: false;
}

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_MAP_BYTES = 512 * 1024;
const MAX_ENTRIES = 10_000;
const MAX_DEPTH = 16;

/** Read-only bounded inspection of a stable local release tree, not a security verdict.
 * Never resolves source-map references or reads source paths listed in maps.
 */
export function inspectReleaseExposure(target: string): ReleaseExposureReport {
  const root = resolve(target);
  // Refuse symlinks in the selected path, including ancestor components.
  if (realpathSync(root) !== root || lstatSync(root).isSymbolicLink()) {
    throw new Error("Release inspection requires a non-symlink target path and ancestors.");
  }
  const report: ReleaseExposureReport = {
    evidenceBasis: "static-file-observation", status: "complete", scope: "local-map-and-js-ts-css-files-only", filesInspected: 0,
    bytesRead: 0, findings: [], limitations: [], networkAccessed: false, targetModified: false,
  };
  const label = (path: string) => relative(root, path) || basename(root);
  const limit = (path: string, reason: string) => {
    report.status = "partial";
    report.limitations.push({ file: label(path), reason });
  };
  function inspectMap(text: string, file: string, representation: "standalone-map" | "inline-map") {
    if (Buffer.byteLength(text) > MAX_MAP_BYTES) { limit(file, "map-size-limit"); return; }
    let map: unknown;
    try { map = JSON.parse(text); } catch { limit(file, "invalid-source-map-json"); return; }
    if (!map || typeof map !== "object" || !("version" in map) || map.version !== 3) {
      limit(file, "unsupported-source-map"); return;
    }
    if ("sections" in map) { limit(file, "indexed-source-map-not-inspected"); return; }
    if (!("sourcesContent" in map) || map.sourcesContent == null) return;
    if (!Array.isArray(map.sourcesContent) || map.sourcesContent.some(v => v !== null && typeof v !== "string")) {
      limit(file, "invalid-sources-content"); return;
    }
    const embedded = map.sourcesContent.filter((v): v is string => typeof v === "string" && v.length > 0);
    if (embedded.length && report.findings.length >= 4096) { limit(file, "observation-count-limit"); return; }
    if (embedded.length) report.findings.push({ file: label(file), kind: "embedded-source-text",
      evidenceBasis: "static-file-observation", representation,
      embeddedSourceCount: embedded.length, embeddedSourceBytes: embedded.reduce((sum, v) => sum + Buffer.byteLength(v), 0) });
  }
  function inspectFile(path: string) {
    if (!/\.(?:map|[cm]?js|jsx|[cm]?ts|tsx|css)$/i.test(path)) return;
    let fd: number | undefined;
    try {
      // O_NOFOLLOW prevents final-component symlink replacement on supporting platforms.
      if (realpathSync(path) !== path) { limit(path, "symlink-not-inspected"); return; }
      fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      const stat = fstatSync(fd);
      if (!stat.isFile()) { limit(path, "non-regular-file"); return; }
      if (stat.size > MAX_FILE_BYTES || report.bytesRead + stat.size + 1 > MAX_TOTAL_BYTES) {
        limit(path, "read-size-limit"); return;
      }
      const buffer = Buffer.alloc(stat.size + 1);
      let length = 0;
      while (length < buffer.length) {
        const count = readSync(fd, buffer, length, buffer.length - length, null);
        if (!count) break;
        length += count;
      }
      report.bytesRead += length;
      if (length !== stat.size) { limit(path, "file-changed-during-read"); return; }
      report.filesInspected++;
      const text = buffer.subarray(0, length).toString("utf8");
      if (/\.map$/i.test(path)) { inspectMap(text, path, "standalone-map"); return; }
      // Lexical observation only: a marker in a string can also match; not proof a browser uses it.
      let markers = 0;
      for (const match of text.matchAll(/(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)/g)) {
        if (++markers > 128 || report.findings.length >= 4096) { limit(path, "observation-count-limit"); break; }
        const ref = match[1]!;
        if (!ref.startsWith("data:")) {
          report.findings.push({ file: label(path), kind: "unverified-map-reference",
            evidenceBasis: "static-file-observation", representation: "reference" });
          continue;
        }
        const inline = /^data:application\/json(?:;charset=utf-8)?(;base64)?,(.*)$/i.exec(ref);
        if (!inline) { limit(path, "unsupported-inline-map-encoding"); continue; }
        if (inline[2]!.length > MAX_MAP_BYTES * 4) { limit(path, "inline-map-size-limit"); continue; }
        try {
          const payload = inline[2]!;
          if (inline[1] && (!/^[A-Za-z0-9+/]*={0,2}$/.test(payload) || payload.length % 4 !== 0)) {
            limit(path, "invalid-inline-map-encoding"); continue;
          }
          inspectMap(inline[1] ? Buffer.from(payload, "base64").toString("utf8") : decodeURIComponent(payload), path, "inline-map");
        } catch { limit(path, "invalid-inline-map-encoding"); }
      }
    } catch { limit(path, "unreadable-or-changed-file"); }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  let entries = 0;
  function visit(path: string, depth: number): void {
    if (++entries > MAX_ENTRIES) return;
    try {
      const stat = lstatSync(path);
      if (stat.isSymbolicLink() || realpathSync(path) !== path) { limit(path, "symlink-not-inspected"); return; }
      if (!stat.isDirectory()) { if (stat.isFile()) inspectFile(path); else limit(path, "non-regular-file"); return; }
      if (depth >= MAX_DEPTH) { limit(path, "directory-depth-limit"); return; }
      const dir = opendirSync(path);
      try {
        let entry;
        while ((entry = dir.readSync()) !== null) {
          if (entries >= MAX_ENTRIES) { limit(path, "entry-count-limit"); break; }
          visit(join(path, entry.name), depth + 1);
        }
      } finally { dir.closeSync(); }
    } catch { limit(path, "unreadable-or-changed-path"); }
  }
  visit(root, 0);
  report.findings.sort((a, b) => a.file.localeCompare(b.file) || a.kind.localeCompare(b.kind));
  report.limitations.sort((a, b) => a.file.localeCompare(b.file) || a.reason.localeCompare(b.reason));
  return report;
}
