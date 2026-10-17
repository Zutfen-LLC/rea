# ghidra-snes extension identity inspection and SNES target admission

REA can fingerprint a caller-installed
[ghidra-snes](https://github.com/joshleaves/ghidra-snes) Ghidra extension
before any SNES-related work, admit a SNES cartridge as a typed `snes-rom`
target with a pinned analysis profile, and — for the qualified plain `lorom`
and `hirom` mappings — import the cartridge through the real
`SnesRomLoader`, seed its reset-vector entry, and independently attest the
loader-established per-bank file-backed mapping from measured import
observations. The upstream feasibility study behind this integration is
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
with an actionable reason, before any provider execution. The launcher carries the resolved extension
root, Ghidra version, and SHA-256 from the committed profile and re-inspects
that exact installed root immediately before starting the analysis process.
Missing, replaced, modified, or incompatible content refuses launch; the
caller must reopen to resolve a fresh profile after intentional changes.
This is a final pre-spawn content check, not a filesystem lock against
concurrent edits after the check. REA's verified Ghidra
build is 12.1.4 accepting the 12.1.x line; a 12.0.4-targeted extension
therefore cannot be represented as compatible with a selected 12.1.x
installation. Cross-version compatibility is a separately authorized task;
this inspection claims no interoperability and does not modify REA's Ghidra
version support.

A 12.1.x-compatible installation exists today only as a caller **port build**:
rebuild the pinned upstream source against the selected 12.1.x distribution —
Ghidra's own `support/buildExtension.gradle` tokenizes `extension.properties`
`version=@extversion@` to the building distribution's version — then compile
`data/languages/65816.slaspec` with that same distribution's `support/sleigh`,
because the upstream build ships only the `.slaspec` and the inspector requires
the compiled `.sla`. Upstream has published no 12.1.x-targeted release. One
such pairing passed inspection and real execution checks on 2026-10-16; see
the [qualified pairing record](#qualified-pairing-record-2026-10-16).

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

## SNES target admission and profile

Opening a file with `--target-format snes-rom` (CLI) or `format: "snes-rom"`
(MCP `open_binary`) admits it as a typed executable target whose architecture
is the declared `65816` family. The selection is explicit — a `.sfc` suffix or
unrecognized bytes never select it — and it refuses the raw-binary
`architecture`/`entry_point` flags, because the SNES lane owns its language
and defers load semantics to the pinned loader rather than to a flat
file-offset mapping.

Admission validates the cartridge's internal header at the standard LoROM,
HiROM, and ExHiROM candidate offsets (shifted by a supported copier prefix).
The checks mirror the caller-installed ghidra-snes loader's own load-spec
criteria, so REA admits exactly what the pinned loader would accept and no
more: the file size must be bank-aligned with an optional `0x200`-byte
copier header; the header checksum and complement must be XOR partners; the
mapping-mode nibble at `$FFD5` must be one the loader recognizes (`lorom`,
`hirom`, `s-dd1`, `sa-1`, `exhirom`, `spc7110`); the declared ROM size must
cover the payload and stay under the loader's bound; the 21-byte title must
be printable; and the whole-image checksum (with the loader's
mirror-to-declared-size expansion) must match. Exactly one candidate may
pass — zero or several valid headers fail closed as unusable or ambiguous
cartridge metadata. The cartridge's 21-byte title text is never recorded in
target metadata.

The typed target carries the file digest plus the admitted cartridge facts
(header offset, copier offset, payload and declared sizes, declared mapping
mode and raw mapping-mode byte with its FastROM speed bit, checksum word).
These are file declarations, not established load semantics: the bank mapping
and reset-vector entry are established only by the pinned `SnesRomLoader`
when it runs, and every analysis result attests them from measured import
observations rather than assuming them from these facts. Resolving the
profile additionally requires a selected, available Ghidra installation with
a complete, version-matching ghidra-snes extension (see the inspection
sections above); missing, incomplete, or version-mismatched extensions fail
closed. `REA_GHIDRA_LANGUAGE_ID` cannot override the pinned
`65816:LE:24:snes` language.

The committed profile is deterministic for unchanged inputs: it pins
`loader=SnesRomLoader`, `language_id=65816:LE:24:snes`, the compiler
specification, the cartridge facts, the execution-lane semantics
(`mapping_attestation`, `entry_resolution`, `entry_seed`,
`load_image_evidence`), and the inspected extension identity (including its
content digest), so any extension rebuild or cartridge change produces a
different profile digest. Snapshot reuse stays profile-exact: a snapshot from
any other lane (for example a raw-binary profile) can never satisfy a
`snes-rom` open. IDA and Hopper refuse `snes-rom` targets as unsupported
formats.

Admission is provider-independent at resolve time and Ghidra-bound at profile
time; there is no auto-detection lane and no assumption that a mapping mode
equals a verified memory mapping. Synthetic RED/GREEN admission and profile
tests build their cartridge bytes in test code; no ROM images are committed.

## SnesRomLoader execution and per-bank mapping attestation

Opening a `snes-rom` session whose admitted mapping is `lorom` or `hirom`
launches one read-only ephemeral `analyzeHeadless` import with
`-loader SnesRomLoader -processor 65816:LE:24:snes -cspec default` and the
`ReaGhidraPrepareSnes` pre-analysis script. The script refuses anything but
the pinned language and the loader's `SNES ROM Loader` executable format,
verifies that the admitted reset-vector word is file-backed at its committed
canonical-bank address and file offset, resolves the entry from the vector
value in the canonical header bank, requires the entry to land inside
file-backed canonical ROM, and only then seeds the entry point, disassembly,
and the entry function before default auto-analysis — mirroring the raw-binary
and DOS lanes' preparation seam. The script clears `REA SNES ROM prepared`
first and sets it only after the complete vector read, disassembly, and
entry-function creation succeed. The bridge independently requires that
marker for `SNES ROM Loader` before serving requests, so an omitted, failed,
or skipped pre-script cannot establish a usable analysis session. Every other declared mapping (`s-dd1`,
`sa-1`, `exhirom`, `spc7110`) refuses the execution lane outright rather
than approximating a coprocessor layout, and an admitted reset vector that
cannot resolve inside the canonical payload also fails closed before launch.

The executable capacity comes from pinned upstream `RomMapType.ranges()`:
LoROM `$80-$FF` high halves and HiROM `$C0-$FF` full windows each represent
at most 4 MiB. The execution and attestation lanes refuse larger payloads,
including valid 6 MiB cartridges declaring 8 MiB. Exact 4 MiB payloads remain
supported. This restriction does not change the separate generic cartridge
admission contract, which may admit headers for larger or unqualified layouts.

`inspect_native_load_image` (CLI and MCP) then verifies the measured import
independently: it re-admits the cartridge from the captured snapshot bytes,
re-derives every canonical bank (LoROM high-window banks from `$80`, HiROM
full-window banks from `$C0`), the anchored `bank_00_rom_mirror`, the
loader's uninitialized `snes_low_ram`/`snes_io`/`snes_wram` blocks, the
declared mapping-mode and speed bytes, and the reset-vector entry, and
compares each against Ghidra's measured mappings — block names, inclusive
address windows, source file indices, file offsets, and per-bank content
digests. For the ROM mirror the bridge additionally measures the actual
byte-mapped source range and address space from Ghidra, and attestation
compares them with the independently derived expected anchor. The mirror's
`canonical_start` records the measured source, or `null` when unknown;
missing, unmeasurable, wrong-bank, wrong-range, or wrong-space backing can
never verify solely because the visible block has the right shape. The new
observation field is optional outside the SNES lane. The exact block set is compared, so unexpected extra file-backed
mappings, missing banks, or a lost mirror surface as `mismatch` checks;
a snapshot that no longer re-admits, an unqualified mapping, or an entry
outside the canonical banks is an error, not a mismatch. The result records
the canonical banks, mirrors, system blocks, and reset-vector resolution
with both expected and observed values, and carries explicit limitations:
no decompiler is claimed for `65816:LE:24:snes`, the FastROM bit is recorded
but not emulated, and decode coverage extends only to code reachable from
seeded entries.

The qualification lane `npm run verify:ghidra:65816` (bring-your-own
`GHIDRA_INSTALL_DIR` with the extension installed) builds fully synthetic
LoROM and Fast HiROM cartridges from independently authored 65816 opcode
bytes, asserts the verified per-bank attestation, seeded entry function,
M/X-mode-dependent instruction widths, and the far-call reference through
the real provider over MCP and CLI, and exercises the corrupt-mapper,
broken-checksum, and `sa-1` refusal controls. No commercial ROM is read,
generated, or committed at any point.

## Fingerprint validity is not runnable compatibility

A valid fingerprint proves installed content identity and metadata binding
only. It does not prove `SnesRomLoader` executes, that Ghidra loads the
extension, or that any SNES image can be analyzed; those facts require
separately recorded execution evidence, such as the qualification below.

## Qualified pairing record (2026-10-16)

One real REA/Ghidra/ghidra-snes pairing was qualified on Linux x64 (tracker:
[Zutfen-LLC/retro-reconstruction issue
#21](https://github.com/Zutfen-LLC/retro-reconstruction/issues/21)):

- **Ghidra** `12.1.4 PUBLIC` build `20260921`
  (`ghidra_12.1.4_PUBLIC_20260921.zip`, sha256
  `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`),
  Temurin JDK `21.0.12.1+1`, Gradle wrapper 9.3.1 from the upstream
  extension.
- **Extension source**
  `joshleaves/ghidra-snes@d33ce5dbfbc3645f00449be1c7ca1c1c65e81756`. The
  unmodified source compiles against the 12.1.4 API. The installed artifact
  is a local port build as described above (version token stamped `12.1.4`,
  `plugin.ghidraCompatibility=12.1.4`, SLEIGH compiled by 12.1.4's
  `support/sleigh`); the port patch is not upstream and confers no upstream
  compatibility claim.
- **REA inspected identity**: `ghidra_version=12.1.4`, digest
  `f650c5bd3986355ea7d0bc1279a31d4097e40fb652cdab75c2c52b97d092a42b`,
  stable across repeated inspections.
- **Executed, not inspection-only**: `analyzeHeadless` import of a fully
  hand-authored synthetic two-bank LoROM 65816 fixture (sha256
  `1d5bd865fdf679b43bc5fde5dd49904aeb92bbbc746ab21456a45578a81209e2`; no
  commercial content) with `-loader SnesRomLoader -processor
  65816:LE:24:snes` succeeded; memory blocks, reset-vector resolution, seeded
  functions, M/X-dependent disassembly and JSL/RTL references matched the
  earlier Ghidra 12.0.4 evidence byte for byte. REA's `verify:ghidra:raw`
  lane passed against the same installation with the extension present
  (`mocked: false`), and REA's language catalog resolved
  `65816:LE:24:snes`/`default` from the installed extension.
- **Negative controls**: a corrupt mapper byte and a broken checksum are
  refused at import (`No load spec found`); an installation without the
  extension fails closed (`Invalid loader name specified: SnesRomLoader`);
  a 12.0.4-stamped copy is refused for a selected 12.1.4 (`ghidra-snes
  extension metadata does not match`).
- **Unsupported capabilities observed**: the Ghidra decompiler opens the
  program but produces no pseudocode for `65816:LE:24:snes` (decompilation
  does not complete, null result); `Module.manifest` parse warnings appear
  on headless startup (cosmetic; loading and import still succeed). At the
  time of this record SNES target admission was unimplemented; it has since
  been added, but `SnesRomLoader` integration through REA's CLI/MCP
  execution surface and Fast HiROM mapping remain unimplemented and
  separately scoped; this record does not claim REA analyzes SNES ROMs.

## Qualified execution record (2026-10-16)

One real `SnesRomLoader` execution-and-attestation qualification ran on Linux
x64 against the same installation as the pairing record above (Ghidra
`12.1.4 PUBLIC` build `20260921`, port-built ghidra-snes
`d33ce5dbfbc3645f00449be1c7ca1c1c65e81756`, inspected digest
`f650c5bd…`), through REA's `npm run verify:ghidra:65816` lane on the exact
head submitted for review:

- **SYNTHETIC_LOROM = PASS.** A fully synthetic two-bank LoROM cartridge
  (sha256 `eb598f2b3bfda4676c4c597a2cb0c9cfc366e46ed5479dde014e9e1b08a887b1`,
  64 KiB, independently authored 65816 opcodes) imported through REA's MCP
  and CLI with `status: verified` for every canonical bank mapping, the
  anchored mirror, system blocks, the reset vector `$80:FFFC → $80:8000`, the
  seeded entry function, M/X-mode-dependent instruction widths (8-bit and
  16-bit `LDA` immediates), and the `JSL`→`$81:8000` far-call reference.
- **SYNTHETIC_FAST_HIROM = PASS.** A fully synthetic Fast HiROM cartridge
  (map mode `$31`, sha256
  `f6fecff65f040c214e1d8af6aadae5c7f116f5502a7c4ea3331c03fd4bc0adef`,
  128 KiB) imported the same way: full-window banks `$C0`/`$C1`, mirror
  anchored at `$C0:8000`, reset vector `$C0:FFFC → $C0:8000`, seeded entry
  function, mode-dependent widths, and the `JSL`→`$C1:0000` reference.
- **SNES_ROM_IMPORT = PASS** for these two lanes, with CLI/MCP parity,
  unchanged sources, and complete runtime cleanup observed by the lane.
- **Negative controls refused as designed:** a corrupted mapping-mode byte
  and a broken checksum complement never reach execution; an `sa-1`
  cartridge admits as a target but every analysis operation refuses its
  unqualified execution lane.
- **Not claimed:** no decompiler/pseudocode lane for `65816:LE:24:snes`, no
  coprocessor/ExHiROM execution, no real ROM analysis, and no compatibility
  with any private commercial cartridge — a synthetic Fast HiROM pass does
  not qualify the private Secret of Evermore reference, which requires a
  separately gated investigation.

## Exact-head correction qualification (2026-10-17 UTC)

The PR #5 correction round retains the reviewed implementation as an ancestor
and corrects mirror-source measurement, canonical capacity, launch-time
extension integrity, and the mandatory preparation handshake. Exact final
commit identities, RED/GREEN logs, final-head checks, and hosted CI receipts
are recorded in [REA PR #5](https://github.com/Zutfen-LLC/rea/pull/5) and
[tracker #23](https://github.com/Zutfen-LLC/retro-reconstruction/issues/23).
The earlier execution record above is historical, not evidence for the
corrected head.

The isolated qualification installation uses the same authenticated Ghidra
`12.1.4 PUBLIC` build `20260921` archive SHA-256 recorded above, Temurin
`21.0.12.1+1`, and the pinned ghidra-snes source. The local port changes only
`extension.properties` to use Ghidra's build-version token and sets the
build's compatibility property to `12.1.4`; the loader is installed at the
required `lib/ghidra-snes.jar` path and SLEIGH is compiled by that distribution.
This is a fresh port build, not the historical installed artifact. Its
inspected installed-content SHA-256 is
`b1d626da536044ef8ca6b597ce6f2b1b12990d1573663bd2303e9f91f412d734`.

The extended `verify:ghidra:65816` lane observes both original positive
synthetic cartridges through CLI and MCP, including measured mirror sources,
M/X-dependent instruction widths, `JSL` references, source immutability, and
cleanup. It additionally:

- Opens valid 6 MiB/declared-8 MiB cartridges through generic admission for
  both mappings, then requires the specific canonical-capacity analysis refusal.
- Executes real headless imports with skipped preparation, invalid preparation
  arguments, an unmappable reset vector, and an entry-data conflict. Each must
  reach the exact bridge preparation refusal, publish no endpoint, and serve no
  analysis; a prepared control must serve load-image inspection and shutdown.
- Removes ephemeral projects and generated workspaces and requires the final
  observed process lineage to have no descendants.

These controls passed in the real 12.1.4 environment. They establish only the
bounded synthetic LoROM/Fast HiROM lanes; exact 4 MiB capacity is additionally
covered by hermetic attestation tests, not a new full-size real-provider claim.
No decompiler, unsupported mapper, or private Secret of Evermore compatibility
is established. The launch-time identity check does not lock installed files
against mutations after its final read.

## Future integration boundaries

SNES target admission, the pinned analysis profile, the `lorom`/`hirom`
`SnesRomLoader` execution lane with reset-vector entry seeding, and the
per-bank file-backed mapping attestation are implemented (see
[SNES target admission and profile](#snes-target-admission-and-profile) and
[SnesRomLoader execution and per-bank mapping
attestation](#snesromloader-execution-and-per-bank-mapping-attestation)).
Still downstream and separately scoped: coprocessor and ExHiROM execution
lanes (currently refused rather than approximated) and any decompiler
verification for `65816:LE:24:snes`. A passing synthetic Fast HiROM
qualification does not by itself qualify a private commercial ROM; that
requires a separately authorized investigation against the actual cartridge.
