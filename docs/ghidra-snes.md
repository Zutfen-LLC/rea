# ghidra-snes extension identity inspection

REA can fingerprint a caller-installed
[ghidra-snes](https://github.com/joshleaves/ghidra-snes) Ghidra extension
before any SNES-related work. This inspection establishes the extension's
installed identity and prerequisites only. **Successful fingerprint inspection
does not mean REA supports SNES ROMs.** REA does not admit SNES targets, does
not import ROMs, and does not run `SnesRomLoader` through any CLI or MCP
interface; those are separately reviewed downstream tasks. The upstream
feasibility study behind this integration is
[Zutfen-LLC/retro-reconstruction PR #6](https://github.com/Zutfen-LLC/retro-reconstruction/pull/6)
(`docs/architecture/REA_65816_FEASIBILITY.md`).

## Purpose

Fingerprinting gives a deterministic, read-only answer to "which ghidra-snes
installation is present, and is it complete for the selected Ghidra version?"
before any provider execution. The identity binds installed content to a
Ghidra compatibility version so a stale or mismatched extension can never be
silently reused. It is content identity, not a signature, not a sandbox for
installed code, and not proof of successful Ghidra execution.

## Required installed layout

The extension is installed by the caller under
`$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-snes`, with at least:

```
ghidra-snes/
  Module.manifest
  extension.properties          # name=SNES Loader, version=<Ghidra version>
  data/languages/65816.ldefs    # declares language 65816:LE:24:snes
  data/languages/65816.sla      # compiled processor (build product)
  data/languages/65816-snes.pspec
  data/languages/65816.cspec
  lib/ghidra-snes.jar            # exact installed loader artifact
```

The upstream **source** tree ships `65816.slaspec`, not the compiled `65816.sla`;
a usable installed extension requires the build product. REA checks for the
compiled artifacts and refuses incomplete installations. The pinned installed
snapshot (`joshleaves/ghidra-snes@d33ce5db`, built for Ghidra 12.0.4) was
independently inspected: `lib/ghidra-snes.jar` contains
`ghidra_snes/loader/SnesRomLoader.class`. Admission requires that exact regular
file path, not an arbitrary `lib/*.jar` or a JAR elsewhere. REA hashes the loader
bytes with the rest of the installation under the same resource and mutation
checks; it does not parse the JAR to verify its class contents or execute them.
The filename requirement is not authentication of those bytes. A loader at a
different filename or path is refused; repackaging at the required path changes
its fingerprint but is not independently rejected. A file at the expected path
is a prerequisite, not a guarantee the loader runs under the selected Ghidra build.

## Inspection inputs and resource limits

Inspection is bounded, following the installed PSP/Allegrex extension
precedent: at most 1,024 inventory entries, 16 directory levels, 64 MiB of
inspected content, and 64 KiB for `extension.properties`. The file inventory is
sorted lexicographically, and the SHA-256 digest covers each file's relative
path, size, and actual content. Symlinks and nonregular entries are refused.
File replacement, truncation, and concurrent modification during inspection are
detected through regular-file identity checks and fail closed. Cancellation is
honored throughout directory traversal and file reading. Content identity never
depends on mtimes or directory enumeration order.

## Identity fields and digest behavior

`src/ghidra/GhidraSnesExtension.ts` exports:

- `ghidraSnesExtensionSchema` — the validated identity schema.
- `GhidraSnesExtension` — the typed identity: stable extension ID
  (`ghidra-snes`, an internal REA identity, deliberately **not** the upstream
  Java property `name=SNES Loader`), canonical absolute installed root,
  selected Ghidra compatibility version, and the deterministic SHA-256 digest.
- `inspectGhidraSnesExtension(root, ghidraVersion, signal?)` — the read-only
  inspector.
- `resolveGhidraSnesExtension(installation, signal?)` — resolves the
  prerequisite from one explicitly caller-selected Ghidra installation. It
  never scans user-home directories or the system for extensions, and it is
  independent of target admission and provider launch.

The digest changes whenever any inspected content changes (a rebuilt `.sla`,
an edited language definition, a different loader JAR). Unchanged content
produces the same digest across repeated inspections, mtime changes, and
different filesystem enumeration orders.

## Ghidra version binding

`extension.properties`'s `version` property declares the extension's compatible
**Ghidra** version — for the pinned upstream snapshot
`joshleaves/ghidra-snes@d33ce5db` this is `12.0.4`. The inspector requires that
property to equal the caller-selected Ghidra version and refuses mismatches
with an actionable reason, before any provider execution. REA's verified Ghidra
build is 12.1.4 accepting the 12.1.x line; a 12.0.4-targeted extension
therefore cannot be represented as compatible with a selected 12.1.x
installation. Cross-version compatibility is a separately authorized task;
this inspection claims no interoperability and does not modify REA's Ghidra
version support.

## Refusals

Missing installations, noncanonical or symlinked roots, symlinked or
nonregular entries, missing compiled components, malformed Java Properties
metadata (the established parser's syntax, escaping, continuation, and
duplicate-key semantics apply), incompatible Ghidra versions, resource-limit
violations, mutation during inspection, and cancellation all fail closed with
distinct reasons. Inspection produces no installation, extraction, execution,
or network side effects.

## Caller-owned installation model

Ghidra and ghidra-snes are bring-your-own. REA never downloads, installs,
builds, vendors, or executes the extension; it only reads the caller-selected
installation directory. Do not modify the installation while a session is
running.

## Upstream provenance and license cautions

Reference upstream: `joshleaves/ghidra-snes` at commit
`d33ce5dbfbc3645f00449be1c7ca1c1c65e81756`, whose repository MIT license does
**not** establish rights over every bundled file: the 65816 language components
derive from `achan1989/ghidra-65816` (MIT), SPC7110 checksum behavior from
`Optiroc/SuperFamicheck` (MIT), and other bundled third-party content carries
its own terms. None of that material may be copied into REA. This inspection
reads files without copying them; no ghidra-snes binaries, language
specifications, ROMs, or game content are committed to this repository, and
synthetic tests use independently authored text only.

## Fingerprint validity is not runnable compatibility

A valid fingerprint proves installed content identity and metadata binding
only. It does not prove `SnesRomLoader` executes, that Ghidra loads the
extension, or that any SNES image can be analyzed. Real-extension execution
under this inspection is version-compatibility unverified: the pinned upstream
extension targets Ghidra 12.0.4 while REA's verified Ghidra line is 12.1.x, so
no compatible installed pairing exists to test.

## Future integration boundaries

Downstream tasks — SNES target admission (`--target-format snes-rom`),
`SnesRomLoader` launch integration, reset-vector entry seeding, bank-mapping
attestation, and CLI/MCP surface changes — are separately scoped and reviewed.
This module intentionally adds no CLI or MCP capability and admits no target.
