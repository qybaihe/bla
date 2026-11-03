# Format appendix: Android DEX / APK / IL2CPP

Load this when hardening Android packages, DEX, or Unity IL2CPP metadata.

## What BLA touches

- **DEX**: string/type-table densification with recomputed SHA-1 / Adler32 (see Counter-REA matrix ↔ `mobile-game.ts`).
- **APK / ZIP**: member-level hardening for unprotected members; **signed APKs fail closed** — resign after shield, or shield unsigned inputs.
- **IL2CPP**: enclave-type / metadata decoys around Unity `0xFAB11BAF` surfaces.

## Agent workflow

1. Prefer `bla_discover` / `bla_harden` `{ "dry_run": true }` on the build output dir to see which `.dex` / `.apk` / native members are in scope (`truncated` matters on large trees).
2. Harden with `bla_harden` (directory) or `bla_defend` (named artifact). Use `confirm_overwrite` when re-running into an existing output.
3. Do not treat a high `defenseScore` as proof against offline crypto attacks — score scope is Counter-REA gates + exposure drop.

## Related matrix rows

See [counter-rea-matrix.md](./counter-rea-matrix.md) rows for `AndroidDex.ts` / `Il2CppMetadata.ts`.
