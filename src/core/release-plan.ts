import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";

export type ReleaseConsistencyErrorCode =
  | "INVALID_PACKAGE_VERSION"
  | "IDENTITY_VERSION_MISMATCH"
  | "DISPATCH_VERSION_MISMATCH"
  | "TRIGGER_TAG_MISMATCH"
  | "INVALID_COMMIT_SHA"
  | "TAG_COMMIT_MISMATCH"
  | "INVALID_TARBALL_HASH"
  | "ASSET_HASH_CONFLICT";

export class ReleaseConsistencyError extends Error {
  public readonly code: ReleaseConsistencyErrorCode;

  public constructor(code: ReleaseConsistencyErrorCode, message: string) {
    super(message);
    this.name = "ReleaseConsistencyError";
    this.code = code;
  }
}

export interface ReleaseConsistencyInput {
  readonly packageVersion: string;
  readonly identityVersion?: string | null;
  readonly dispatchVersion?: string | null;
  readonly triggerRef?: string | null;
  readonly headSha: string;
  readonly existingTagSha?: string | null;
  readonly tarballSha256: string;
  readonly existingReleaseAssetSha256?: string | null;
  readonly aliasTarballSha256?: string | null;
  readonly existingAliasReleaseAssetSha256?: string | null;
}

export interface ReleaseConsistencyPlan {
  readonly version: string;
  readonly canonicalTag: string;
  readonly headSha: string;
  readonly tagAction: "create" | "verify-existing-idempotent";
  readonly releaseAssetAction: "upload-new" | "skip-identical";
  readonly tarballSha256: string;
  readonly aliasTarballSha256: string | null;
}

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const GIT_SHA_RE = /^[0-9a-f]{7,40}$/i;
const SHA256_RE = /^[0-9a-f]{64}$/i;

export function verifyReleaseConsistency(
  input: ReleaseConsistencyInput,
): ReleaseConsistencyPlan {
  const pkgVer = (input.packageVersion ?? "").trim();
  if (!SEMVER_RE.test(pkgVer)) {
    throw new ReleaseConsistencyError(
      "INVALID_PACKAGE_VERSION",
      `Invalid package.json version '${input.packageVersion}': expected strict semver (X.Y.Z)`,
    );
  }

  if (input.identityVersion !== undefined && input.identityVersion !== null) {
    const idVer = input.identityVersion.trim();
    if (idVer !== pkgVer) {
      throw new ReleaseConsistencyError(
        "IDENTITY_VERSION_MISMATCH",
        `BLA_IDENTITY.version '${idVer}' does not match package.json version '${pkgVer}'`,
      );
    }
  }

  const headSha = (input.headSha ?? "").trim().toLowerCase();
  if (!GIT_SHA_RE.test(headSha)) {
    throw new ReleaseConsistencyError(
      "INVALID_COMMIT_SHA",
      `Invalid checkout commit SHA '${input.headSha}'`,
    );
  }

  const tarballSha256 = (input.tarballSha256 ?? "").trim().toLowerCase();
  if (!SHA256_RE.test(tarballSha256)) {
    throw new ReleaseConsistencyError(
      "INVALID_TARBALL_HASH",
      `Invalid tarball SHA-256 digest '${input.tarballSha256}'`,
    );
  }

  let aliasTarballSha256: string | null = null;
  if (input.aliasTarballSha256 !== undefined && input.aliasTarballSha256 !== null) {
    aliasTarballSha256 = input.aliasTarballSha256.trim().toLowerCase();
    if (!SHA256_RE.test(aliasTarballSha256)) {
      throw new ReleaseConsistencyError(
        "INVALID_TARBALL_HASH",
        `Invalid alias tarball SHA-256 digest '${input.aliasTarballSha256}'`,
      );
    }
  }

  // 1. Validate workflow_dispatch version input if provided
  if (input.dispatchVersion !== undefined && input.dispatchVersion !== null) {
    const rawDispatch = input.dispatchVersion.trim();
    if (rawDispatch.length > 0 && rawDispatch !== "none") {
      const normalizedDispatch = rawDispatch.startsWith("v")
        ? rawDispatch.slice(1)
        : rawDispatch.startsWith("bla-agents-")
          ? rawDispatch.slice("bla-agents-".length)
          : rawDispatch;
      if (normalizedDispatch !== pkgVer) {
        throw new ReleaseConsistencyError(
          "DISPATCH_VERSION_MISMATCH",
          `workflow_dispatch version input '${rawDispatch}' does not match package.json version '${pkgVer}'`,
        );
      }
    }
  }

  // 2. Validate trigger tag ref if triggered by a tag push
  if (input.triggerRef !== undefined && input.triggerRef !== null) {
    const ref = input.triggerRef.trim();
    if (
      ref.startsWith("refs/tags/") ||
      ref.startsWith("bla-agents-") ||
      /^v\d+\./.test(ref)
    ) {
      const tagName = ref.startsWith("refs/tags/") ? ref.slice("refs/tags/".length) : ref;
      let extractedVersion: string | null = null;
      if (tagName.startsWith("bla-agents-")) {
        extractedVersion = tagName.slice("bla-agents-".length);
      } else if (tagName.startsWith("v")) {
        extractedVersion = tagName.slice(1);
      }
      if (!extractedVersion || extractedVersion !== pkgVer) {
        throw new ReleaseConsistencyError(
          "TRIGGER_TAG_MISMATCH",
          `Trigger tag '${tagName}' does not match package.json version '${pkgVer}'`,
        );
      }
    }
  }

  const canonicalTag = `bla-agents-${pkgVer}`;

  // 3. Verify existing tag commit matches checkout commit
  let tagAction: ReleaseConsistencyPlan["tagAction"] = "create";
  if (
    input.existingTagSha !== undefined &&
    input.existingTagSha !== null &&
    input.existingTagSha.trim().length > 0
  ) {
    const existingSha = input.existingTagSha.trim().toLowerCase();
    if (!GIT_SHA_RE.test(existingSha)) {
      throw new ReleaseConsistencyError(
        "INVALID_COMMIT_SHA",
        `Invalid existing tag commit SHA '${input.existingTagSha}'`,
      );
    }
    if (existingSha !== headSha) {
      throw new ReleaseConsistencyError(
        "TAG_COMMIT_MISMATCH",
        `Existing tag '${canonicalTag}' points to commit ${existingSha}, which differs from checkout commit ${headSha}; refusing cross-commit release overwrite`,
      );
    }
    tagAction = "verify-existing-idempotent";
  }

  // 4. Verify existing release asset SHA-256 matches packed tarball SHA-256
  let releaseAssetAction: ReleaseConsistencyPlan["releaseAssetAction"] = "upload-new";
  if (
    input.existingReleaseAssetSha256 !== undefined &&
    input.existingReleaseAssetSha256 !== null &&
    input.existingReleaseAssetSha256.trim().length > 0
  ) {
    const existingAssetHash = input.existingReleaseAssetSha256.trim().toLowerCase();
    if (existingAssetHash !== tarballSha256) {
      throw new ReleaseConsistencyError(
        "ASSET_HASH_CONFLICT",
        `Existing release asset SHA-256 (${existingAssetHash}) differs from packed tarball SHA-256 (${tarballSha256}); refusing to clobber`,
      );
    }
    releaseAssetAction = "skip-identical";
  }

  if (
    aliasTarballSha256 !== null &&
    input.existingAliasReleaseAssetSha256 !== undefined &&
    input.existingAliasReleaseAssetSha256 !== null &&
    input.existingAliasReleaseAssetSha256.trim().length > 0
  ) {
    const existingAliasHash = input.existingAliasReleaseAssetSha256.trim().toLowerCase();
    if (existingAliasHash !== aliasTarballSha256) {
      throw new ReleaseConsistencyError(
        "ASSET_HASH_CONFLICT",
        `Existing alias release asset SHA-256 (${existingAliasHash}) differs from packed alias tarball SHA-256 (${aliasTarballSha256}); refusing to clobber`,
      );
    }
  }

  return {
    version: pkgVer,
    canonicalTag,
    headSha,
    tagAction,
    releaseAssetAction,
    tarballSha256,
    aliasTarballSha256,
  };
}

export interface PackagePublishInputState {
  readonly primaryPublished: boolean;
  readonly aliasPublished?: boolean;
  readonly primaryTarballSha256?: string;
  readonly publishedPrimarySha256?: string | null;
  readonly aliasTarballSha256?: string;
  readonly publishedAliasSha256?: string | null;
}

export interface NpmPublishRetryPlan {
  readonly primaryAction: "publish" | "skip-already-published";
  readonly aliasAction: "publish" | "skip-already-published";
  readonly shouldPublishPrimary: boolean;
  readonly shouldPublishAlias: boolean;
  readonly requiresPublish: boolean;
  readonly allCompletedAfterPlan: boolean;
}

/**
 * Computes an idempotent dual-package (`bla-agents` primary + `bla-shield` alias)
 * npm publish plan so that a retry after `primary` succeeds and `alias` fails
 * safely completes `alias` without failing on `primary` or clobbering different bytes.
 */
export function planNpmPublishRetry(state: PackagePublishInputState): NpmPublishRetryPlan {
  if (
    state.primaryPublished &&
    state.primaryTarballSha256 &&
    state.publishedPrimarySha256 &&
    state.primaryTarballSha256.trim().toLowerCase() !==
      state.publishedPrimarySha256.trim().toLowerCase()
  ) {
    throw new ReleaseConsistencyError(
      "ASSET_HASH_CONFLICT",
      `Published primary package SHA-256 (${state.publishedPrimarySha256}) differs from local tarball SHA-256 (${state.primaryTarballSha256})`,
    );
  }

  if (
    state.aliasPublished &&
    state.aliasTarballSha256 &&
    state.publishedAliasSha256 &&
    state.aliasTarballSha256.trim().toLowerCase() !==
      state.publishedAliasSha256.trim().toLowerCase()
  ) {
    throw new ReleaseConsistencyError(
      "ASSET_HASH_CONFLICT",
      `Published alias package SHA-256 (${state.publishedAliasSha256}) differs from local alias tarball SHA-256 (${state.aliasTarballSha256})`,
    );
  }

  const shouldPublishPrimary = !state.primaryPublished;
  const shouldPublishAlias = !(state.aliasPublished ?? false);

  return {
    primaryAction: shouldPublishPrimary ? "publish" : "skip-already-published",
    aliasAction: shouldPublishAlias ? "publish" : "skip-already-published",
    shouldPublishPrimary,
    shouldPublishAlias,
    requiresPublish: shouldPublishPrimary || shouldPublishAlias,
    allCompletedAfterPlan: true,
  };
}

export interface PackedPackageArtifact {
  readonly packageName: string;
  readonly version: string;
  readonly tarballPath: string;
  readonly tarballFilename: string;
  readonly sha256: string;
}

export interface DualPackResult {
  readonly version: string;
  readonly primary: PackedPackageArtifact;
  readonly alias: PackedPackageArtifact;
  readonly sha256SumsPath: string;
}

function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

/**
 * Packs both `bla-agents` (primary) and `bla-shield` (alias) tarballs into `outDir`
 * without mutating the repository working tree, and writes `SHA256SUMS.txt`.
 */
export function packDualReleaseTarballs(repoDir: string, outDir: string): DualPackResult {
  const absRepo = resolve(repoDir);
  const absOut = resolve(outDir);
  mkdirSync(absOut, { recursive: true });

  const pkgJsonPath = join(absRepo, "package.json");
  if (!existsSync(pkgJsonPath)) {
    throw new Error(`package.json not found in '${absRepo}'`);
  }
  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8")) as {
    name: string;
    version: string;
  };
  const version = pkgJson.version;

  // 1. Pack primary (`bla-agents-<version>.tgz`) directly into `absOut`
  execFileSync(npmCmd, ["pack", "--pack-destination", absOut], {
    cwd: absRepo,
    stdio: "pipe",
  });

  const primaryFilename = `bla-agents-${version}.tgz`;
  const primaryPath = join(absOut, primaryFilename);
  if (!existsSync(primaryPath)) {
    throw new Error(`Expected packed tarball at '${primaryPath}'`);
  }
  const primarySha256 = sha256File(primaryPath);

  // 2. Build alias (`bla-shield-<version>.tgz`) in an isolated temp staging directory
  const stageDir = mkdtempSync(join(tmpdir(), "bla-alias-pack-"));
  try {
    execFileSync("tar", ["-xzf", primaryPath, "-C", stageDir], {
      stdio: "pipe",
    });
    const unpackedPkgDir = join(stageDir, "package");
    const unpackedPkgJsonPath = join(unpackedPkgDir, "package.json");
    const unpackedPkg = JSON.parse(readFileSync(unpackedPkgJsonPath, "utf8")) as Record<
      string,
      unknown
    >;
    unpackedPkg.name = "bla-shield";
    writeFileSync(unpackedPkgJsonPath, JSON.stringify(unpackedPkg, null, 2) + "\n", "utf8");

    execFileSync(npmCmd, ["pack", "--pack-destination", absOut, "--ignore-scripts"], {
      cwd: unpackedPkgDir,
      stdio: "pipe",
    });
  } finally {
    rmSync(stageDir, { recursive: true, force: true });
  }

  const aliasFilename = `bla-shield-${version}.tgz`;
  const aliasPath = join(absOut, aliasFilename);
  if (!existsSync(aliasPath)) {
    throw new Error(`Expected packed alias tarball at '${aliasPath}'`);
  }
  const aliasSha256 = sha256File(aliasPath);

  const sha256SumsPath = join(absOut, "SHA256SUMS.txt");
  const sumsContent = [
    `${primarySha256}  ${basename(primaryPath)}`,
    `${aliasSha256}  ${basename(aliasPath)}`,
    "",
  ].join("\n");
  writeFileSync(sha256SumsPath, sumsContent, "utf8");

  return {
    version,
    primary: {
      packageName: "bla-agents",
      version,
      tarballPath: primaryPath,
      tarballFilename: primaryFilename,
      sha256: primarySha256,
    },
    alias: {
      packageName: "bla-shield",
      version,
      tarballPath: aliasPath,
      tarballFilename: aliasFilename,
      sha256: aliasSha256,
    },
    sha256SumsPath,
  };
}
