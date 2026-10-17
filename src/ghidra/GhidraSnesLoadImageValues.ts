import { createHash } from "node:crypto";

import {
  nativeLoadImageSchema,
  type NativeLoadImage,
  type NativeLoadImageCheck,
  type NativeLoadImageObservation,
} from "../domain/native/nativeLoadImage.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { admitSnesRom } from "../domain/snesRom.js";
import { err, ok, type Result } from "../domain/result.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
const address = (offset: number): string => `0x${offset.toString(16)}`;

/** Loader-established canonical chunk of one SNES bank. */
interface CanonicalChunk {
  readonly name: string;
  readonly bank: number;
  readonly start: number;
  readonly end: number;
  readonly length: number;
  readonly fileOffset: number;
}

/** Reset-vector resolution inside the canonical header bank. */
interface ResetVectorResolution {
  readonly vectorAddress: number;
  readonly vectorFileOffset: number;
  readonly value: number;
  readonly entry: number;
  readonly entryChunk: CanonicalChunk;
  readonly entryFileOffset: number;
}

const canonicalChunks = (
  mapping: "lorom" | "hirom",
  romOffset: number,
  romSizeBytes: number,
): CanonicalChunk[] => {
  const chunks: CanonicalChunk[] = [];
  const bankBytes = mapping === "lorom" ? 0x8000 : 0x10000;
  const windowOffset = mapping === "lorom" ? 0x8000 : 0x0000;
  const firstBank = mapping === "lorom" ? 0x80 : 0xc0;
  for (let index = 0; ; index += 1) {
    const payloadOffset = index * bankBytes;
    if (payloadOffset >= romSizeBytes) break;
    const bank = firstBank + index;
    if (bank > 0xff) break;
    const length = Math.min(bankBytes, romSizeBytes - payloadOffset);
    const start = (bank << 16) + windowOffset;
    chunks.push({
      name: `bank_${bank.toString(16).padStart(2, "0")}_${mapping}`,
      bank,
      start,
      end: start + length - 1,
      length,
      fileOffset: romOffset + payloadOffset,
    });
  }
  return chunks;
};

/**
 * Canonical anchor of the loader's bank-$00 high-half ROM mirror. Each branch
 * translates one rule of the installed extension's
 * MemoryMap.firstBankMirrorStart/canonicalRomMirrorStart: the standard header
 * locations anchor by mapping type, and any other admitted header location
 * anchors at its LoROM-relative file position. The mirror exists only when
 * its full 0x8000-byte window is covered by canonical banks.
 */
const mirrorAnchor = (
  mapping: "lorom" | "hirom",
  headerLocation: number,
): number => {
  if (headerLocation === 0x7fbf)
    return mapping === "lorom" ? 0x808000 : 0xc00000;
  if (headerLocation === 0xffbf) return 0xc08000;
  if (headerLocation === 0x40ffbf) return 0x408000;
  return headerLocation - 0x7fbf;
};

const chunkContaining = (
  chunks: readonly CanonicalChunk[],
  cpuAddress: number,
): CanonicalChunk | undefined =>
  chunks.find((chunk) => cpuAddress >= chunk.start && cpuAddress <= chunk.end);

const resolveResetVector = (
  bytes: Buffer,
  mapping: "lorom" | "hirom",
  romOffset: number,
  romSizeBytes: number,
  headerOffset: number,
  chunks: readonly CanonicalChunk[],
): Result<ResetVectorResolution, string> => {
  const vectorFileOffset = headerOffset + 0x3d;
  const payloadOffset = vectorFileOffset - romOffset;
  if (payloadOffset < 0 || payloadOffset + 2 > romSizeBytes)
    return err(
      `The admitted reset-vector offset 0x${vectorFileOffset.toString(16)} lies outside the cartridge payload`,
    );
  const located = canonicalVectorAddress(mapping, payloadOffset);
  const backing = chunkContaining(chunks, located.address);
  if (backing === undefined)
    return err(
      `The reset vector at 0x${located.address.toString(16)} is not inside a file-backed canonical ${mapping} bank`,
    );
  const value = bytes.readUInt16LE(vectorFileOffset);
  const entry = (located.entryBank << 16) | value;
  const entryChunk = chunkContaining(chunks, entry);
  if (entryChunk === undefined)
    return err(
      `The reset vector value 0x${value.toString(16)} resolves to 0x${entry.toString(16)}, outside the file-backed canonical ${mapping} banks; the entry cannot be established`,
    );
  return ok({
    vectorAddress: located.address,
    vectorFileOffset,
    value,
    entry,
    entryChunk,
    entryFileOffset: entryChunk.fileOffset + (entry - entryChunk.start),
  });
};

/** Canonical CPU address of the reset-vector word for a payload offset. */
const canonicalVectorAddress = (
  mapping: "lorom" | "hirom",
  payloadOffset: number,
): { readonly address: number; readonly entryBank: number } => {
  const bankBytes = mapping === "lorom" ? 0x8000 : 0x10000;
  const firstBank = mapping === "lorom" ? 0x80 : 0xc0;
  const bankIndex = Math.floor(payloadOffset / bankBytes);
  return {
    address:
      ((firstBank + bankIndex) << 16) +
      (mapping === "lorom"
        ? 0x8000 + (payloadOffset % 0x8000)
        : payloadOffset % 0x10000),
    entryBank: firstBank + bankIndex,
  };
};

/**
 * Canonical reset-vector coordinates for the prepare script: the address of
 * the $FFFC reset word inside the admitted header's canonical bank and its
 * committed file offset. The entry value itself is read only from the file,
 * by the loader-established import.
 */
export const snesResetVectorCoordinates = (cartridge: {
  readonly headerOffset: number;
  readonly romOffset: number;
  readonly romSizeBytes: number;
  readonly declaredMapping: string;
}): Result<
  {
    readonly mapping: "lorom" | "hirom";
    readonly vectorAddress: string;
    readonly vectorFileOffset: number;
  },
  string
> => {
  if (
    cartridge.declaredMapping !== "lorom" &&
    cartridge.declaredMapping !== "hirom"
  )
    return err(
      `The declared mapping '${cartridge.declaredMapping}' has no qualified SnesRomLoader execution lane`,
    );
  const mapping = cartridge.declaredMapping;
  const vectorFileOffset = cartridge.headerOffset + 0x3d;
  const payloadOffset = vectorFileOffset - cartridge.romOffset;
  if (payloadOffset < 0 || payloadOffset + 2 > cartridge.romSizeBytes)
    return err(
      `The admitted reset-vector offset 0x${vectorFileOffset.toString(16)} lies outside the cartridge payload`,
    );
  return ok({
    mapping,
    vectorAddress: `0x${canonicalVectorAddress(mapping, payloadOffset).address.toString(16)}`,
    vectorFileOffset,
  });
};

const snesLimitations = [
  "Verification independently re-admits the cartridge from the captured snapshot bytes and covers every file-backed canonical bank's address window, source file offset and content digest, the loader's uninitialized system blocks, the anchored bank-$00 ROM mirror, the declared mapping/speed bytes, and the seeded reset-vector entry. Mapping ends are inclusive.",
  "The canonical bank layout, mirror anchor, and entry resolution mirror the caller-installed ghidra-snes SnesRomLoader's observed import behavior; they describe the analysis image, not a running SNES. Hardware mirror banks beyond the loader's model, coprocessor mappings, and runtime bus behavior are not verified.",
  "Instruction decode follows the 65816 M/X register-mode tracking from the seeded entry; mode switches through indirect or self-modifying code can locally drift, and coverage claims extend only to code reachable from seeded entries.",
  "The 65816:LE:24:snes language has no verified decompiler contract; no pseudocode lane is claimed. A verified import does not establish original source ownership or recovered program behavior.",
  "A mismatching memory digest identifies the reported source range; it does not locate the first differing byte inside that range.",
];

/**
 * Verify a measured SnesRomLoader import against the session's immutable
 * snapshot: re-admit the cartridge from bytes, independently derive every
 * canonical bank mapping, the mirror anchor, and the reset-vector entry, and
 * compare each against the provider's measured observations. Contradictions
 * surface as mismatch checks; unadmittable bytes, unsupported declared
 * mappings, or an entry outside the canonical banks fail closed.
 */
export const attestGhidraSnesRomLoadImage = async (input: {
  readonly bytes: Buffer;
  readonly targetSha256: string;
  readonly observations: NativeLoadImageObservation;
}): Promise<Result<NativeLoadImage, string>> => {
  const { bytes, targetSha256, observations } = input;
  if (sha256(bytes) !== targetSha256)
    return err(
      "Ghidra SNES load-image snapshot digest does not match the admitted target",
    );
  const cartridge = await admitSnesRom({
    fileSize: bytes.length,
    readAt: async (offset, length) => {
      if (offset < 0 || length < 0 || offset + length > bytes.length)
        throw new Error(`re-admission read out of bounds: ${offset}+${length}`);
      return bytes.subarray(offset, offset + length);
    },
  });
  if (!cartridge.ok)
    return err(
      `The captured SNES snapshot no longer admits as a valid cartridge: ${cartridge.error.reason}`,
    );
  const facts = cartridge.value;
  if (facts.declaredMapping !== "lorom" && facts.declaredMapping !== "hirom")
    return err(
      `The declared mapping '${facts.declaredMapping}' is outside the qualified lorom/hirom SnesRomLoader execution lanes`,
    );
  const mapping = facts.declaredMapping;
  const chunks = canonicalChunks(mapping, facts.romOffset, facts.romSizeBytes);
  const vector = resolveResetVector(
    bytes,
    mapping,
    facts.romOffset,
    facts.romSizeBytes,
    facts.headerOffset,
    chunks,
  );
  if (!vector.ok) return vector;

  const checks: NativeLoadImageCheck[] = [];
  const check = (
    name: string,
    expected: JsonValue,
    observed: JsonValue,
    fileOffset: number | null = null,
    location: string | null = null,
  ): void => {
    checks.push({
      name,
      matched: JSON.stringify(expected) === JSON.stringify(observed),
      expected,
      observed,
      file_offset: fileOffset,
      address: location,
    });
  };

  check("executable_format", "SNES ROM Loader", observations.executable_format);
  check("language_id", "65816:LE:24:snes", observations.language_id);
  check("compiler_spec_id", "default", observations.compiler_spec_id);
  check("image_base", "0x0", observations.image_base);
  check("default_address_space", "bus", observations.default_address_space);
  check("source_file_count", 1, observations.source_files.length);
  const source = observations.source_files[0];
  check("source_file_size", bytes.length, source?.size ?? null);
  check("original_file_sha256", targetSha256, source?.original_sha256 ?? null);
  check("modified_file_sha256", targetSha256, source?.modified_sha256 ?? null);

  const byBlock = new Map<string, NativeLoadImageObservation["mappings"]>();
  for (const mappingRow of observations.mappings) {
    const existing = byBlock.get(mappingRow.block);
    if (existing === undefined) byBlock.set(mappingRow.block, [mappingRow]);
    else existing.push(mappingRow);
  }
  const sole = (
    name: string,
  ): NativeLoadImageObservation["mappings"][number] | null => {
    const rows = byBlock.get(name);
    return rows !== undefined && rows.length === 1 ? rows[0]! : null;
  };
  const unbackedShape = (name: string, start: number, length: number): void => {
    const observed = sole(name);
    check(`blocks[${name}].start`, address(start), observed?.start ?? null);
    check(
      `blocks[${name}].end`,
      address(start + length - 1),
      observed?.end ?? null,
    );
    check(`blocks[${name}].length`, length, observed?.length ?? null);
    check(`blocks[${name}].initialized`, false, observed?.initialized ?? null);
    check(`blocks[${name}].loaded`, true, observed?.loaded ?? null);
    check(`blocks[${name}].overlay`, false, observed?.overlay ?? null);
    check(
      `blocks[${name}].source_file_index`,
      null,
      observed?.source_file_index ?? null,
    );
  };
  const systemBlocks: { name: string; start: number; length: number }[] = [
    { name: "snes_low_ram", start: 0x000000, length: 0x2000 },
    { name: "snes_io", start: 0x002000, length: 0x4000 },
    { name: "snes_wram", start: 0x7e0000, length: 0x20000 },
  ];
  for (const block of systemBlocks)
    unbackedShape(block.name, block.start, block.length);

  const anchored = chunkContaining(
    chunks,
    mirrorAnchor(mapping, facts.headerOffset - facts.romOffset),
  );
  const mirrorCovered =
    anchored !== undefined &&
    mirrorAnchor(mapping, facts.headerOffset - facts.romOffset) + 0x8000 - 1 <=
      anchored.end;
  const mirrorStart = 0x008000;
  if (mirrorCovered) unbackedShape("bank_00_rom_mirror", mirrorStart, 0x8000);
  else
    check(
      "blocks[bank_00_rom_mirror].absent",
      null,
      sole("bank_00_rom_mirror") ?? null,
    );

  // Check metadata carries the independently expected bank address, so a
  // missing bank still records where it should have been.
  for (const chunk of chunks) {
    const observed = sole(chunk.name);
    const at = `banks[${chunk.name}]`;
    check(
      `${at}.start`,
      address(chunk.start),
      observed?.start ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.end`,
      address(chunk.end),
      observed?.end ?? null,
      chunk.fileOffset,
      observed?.end ?? null,
    );
    check(
      `${at}.length`,
      chunk.length,
      observed?.length ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.file_offset`,
      chunk.fileOffset,
      observed?.file_offset ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.initialized`,
      true,
      observed?.initialized ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.loaded`,
      true,
      observed?.loaded ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.overlay`,
      false,
      observed?.overlay ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.source_file_index`,
      0,
      observed?.source_file_index ?? null,
      chunk.fileOffset,
      observed?.start ?? null,
    );
    check(
      `${at}.sha256`,
      sha256(bytes.subarray(chunk.fileOffset, chunk.fileOffset + chunk.length)),
      observed?.sha256 ?? null,
      chunk.fileOffset,
      address(chunk.start),
    );
  }
  const fileBacked = observations.mappings.filter(
    (row) => row.source_file_index !== null,
  );
  check(
    "canonical_bank_set",
    chunks.map((chunk) => chunk.name).sort(),
    fileBacked.map((row) => row.block).sort(),
  );
  const expectedBlocks = [
    ...systemBlocks.map((block) => block.name),
    ...(mirrorCovered ? ["bank_00_rom_mirror"] : []),
    ...chunks.map((chunk) => chunk.name),
  ].sort();
  check(
    "block_set",
    expectedBlocks,
    observations.mappings.map((row) => row.block).sort(),
  );

  check(
    "entry_points",
    [address(vector.value.entry)],
    [...observations.entry_points].sort(),
  );
  check("relocation_records", [], observations.relocations);

  return ok(
    nativeLoadImageSchema.parse({
      status: checks.every((item) => item.matched) ? "verified" : "mismatch",
      format: "snes-rom",
      target_sha256: targetSha256,
      language_id: "65816:LE:24:snes",
      compiler_spec_id: "default",
      declared_mapping: mapping,
      mapping_mode_byte: facts.mappingModeByte,
      declared_speed: facts.declaredSpeed,
      rom_offset: facts.romOffset,
      rom_size_bytes: facts.romSizeBytes,
      declared_rom_size_bytes: facts.declaredRomSizeBytes,
      checksum: facts.checksum,
      canonical_banks: chunks.map((chunk) => ({
        name: chunk.name,
        bank: `0x${chunk.bank.toString(16)}`,
        start: address(chunk.start),
        end: address(chunk.end),
        length: chunk.length,
        file_offset: chunk.fileOffset,
        sha256: sha256(
          bytes.subarray(chunk.fileOffset, chunk.fileOffset + chunk.length),
        ),
      })),
      mirror_banks: mirrorCovered
        ? [
            {
              name: "bank_00_rom_mirror",
              start: address(mirrorStart),
              end: address(mirrorStart + 0x8000 - 1),
              length: 0x8000,
              canonical_start: address(
                mirrorAnchor(mapping, facts.headerOffset - facts.romOffset),
              ),
            },
          ]
        : [],
      system_blocks: systemBlocks.map((block) => ({
        name: block.name,
        start: address(block.start),
        end: address(block.start + block.length - 1),
        length: block.length,
      })),
      reset_vector: {
        address: address(vector.value.vectorAddress),
        file_offset: vector.value.vectorFileOffset,
        value_hex: `0x${vector.value.value.toString(16)}`,
        entry: address(vector.value.entry),
        entry_file_offset: vector.value.entryFileOffset,
      },
      observations,
      checks,
      limitations: snesLimitations,
    }),
  );
};
