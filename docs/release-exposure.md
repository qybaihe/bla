# Read-only release source-map inspection

```sh
bla inspect-release ./dist --json
```

The `inspectReleaseExposure(target)` library API and `inspect-release` command
observe local release files without modifying them, fetching references, running
bundles, or reading source paths named by maps. The command always emits JSON.

- `embedded-source-text`: a version 3 map contains nonempty `sourcesContent`
  strings. Evidence is the number of strings and their UTF-8 byte count. This
  demonstrates embedded text, **not** whether that text is confidential, deployed,
  publicly accessible, or an original source. `sourcesContent` can be fabricated
  or honey/decoy content: its presence does not authenticate original source or
  automatically establish a secret or intellectual-property leak.
- `unverified-map-reference`: a lexical `sourceMappingURL` marker names a
  non-data reference. Relative, absolute, and remote references are **never
  followed**. This does not establish that the referenced map exists or that a
  browser uses the marker (a marker inside a string can also match).

No source text, source names from maps, or reference URL/query values are emitted.
Local release filenames are included for remediation. There is no credential
scanner, automatic removal, defense score change, or claim of stopping REA.

## Coverage and limits

Inspection covers `.map`, JS/TS (`js`, `mjs`, `cjs`, `jsx`, `ts`, `mts`, `cts`,
`tsx`) and CSS files in the selected tree. Inline JSON maps support base64 and
percent encoding, optionally with `charset=utf-8`. Indexed maps, other encodings,
HTML, archive members, binaries, other embedded metadata, and runtime-produced
maps are not inspected. No findings is **not a clean/security verdict**.

Limits: 2 MiB per file, 32 MiB total reads, 512 KiB decoded map text, 10,000 tree
entries, 16 directory levels, 128 markers per file, and 4,096 findings. Traversal
stops at limits; truncated coverage, unsupported/malformed maps, unreadable paths,
and symlinks produce `partial` status and explicit limitations. Traversal order
at a limit depends on filesystem enumeration order; complete reports are sorted
by filename and kind. Unsupported file extensions are outside the stated scope,
not reported individually. Maps without embedded text do not imply source text
is unavailable through other channels.

Selected symlink paths (including symlink ancestors) are rejected, and links
inside a directory are skipped. Files are opened read-only with `O_NOFOLLOW`
where available and checked with `fstat`. Scan a **stable local tree or snapshot**:
portable Node filesystem APIs cannot make ancestor checks atomic against a
concurrently hostile process replacing directories. This is not a filesystem
sandbox for attacker-controlled live trees. `targetModified: false` describes
this tool's writes, not modifications by other processes.

Exit codes: `0` means inspection completed within the stated scope (even with
findings); `2` means partial inspection; `1` means an invocation/target error.
Use the structured findings in your release policy rather than interpreting
exit code zero as absence of disclosure. For actual unwanted embedded source,
review your build's source-map publishing configuration and re-inspect the
release artifact; this command deliberately makes no changes.
