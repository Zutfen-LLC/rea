import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import type {
  NativeLoadImage,
  NativeLoadImageObservation,
} from "../domain/native/nativeLoadImage.js";
import {
  SNES_HIROM_TITLE_BASE,
  SNES_LOROM_TITLE_BASE,
  snesCartridgeImage,
  snesHeaderBase,
} from "../../tests/fixtures/snesCartridge.js";
import { admitSnesRom } from "../domain/snesRom.js";
import {
  attestGhidraSnesRomLoadImage,
  snesResetVectorCoordinates,
} from "./GhidraSnesLoadImageValues.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

/** Narrow an attested result to its snes-rom variant. */
const snesResult = (
  value: NativeLoadImage,
): Extract<NativeLoadImage, { format: "snes-rom" }> => {
  if (!("format" in value) || value.format !== "snes-rom")
    throw new Error("not a snes-rom result");
  return value;
};

// Independently authored 65816 fixture code: native-mode entry with M/X
// mode switches, 8/16-bit immediates, a far JSL call and a loop; the far
// bank holds an indexed subroutine ending in RTL.
const LOROM_ENTRY_CODE = Buffer.from([
  0x78, // SEI
  0x18, // CLC
  0xfb, // XCE
  0xc2,
  0x10, // REP #$10 (16-bit index)
  0xe2,
  0x20, // SEP #$20 (8-bit A)
  0xa9,
  0x34, // LDA #$34
  0xc2,
  0x20, // REP #$20 (16-bit A)
  0xa9,
  0x56,
  0x78, // LDA #$7856
  0x22,
  0x00,
  0x80,
  0x81, // JSL $818000
  0x9c,
  0x00,
  0x20,
  0x7e, // STA $7e2000 (absolute long)
  0x80,
  0xfe, // BRA -2
]);
const LOROM_FAR_CODE = Buffer.from([
  0xa2,
  0x00,
  0x00, // LDX #$0000
  0xe8, // INX
  0x6b, // RTL
]);
const HIROM_ENTRY_CODE = Buffer.from([
  0x78, // SEI
  0x18, // CLC
  0xfb, // XCE
  0xc2,
  0x30, // REP #$30 (16-bit A and index)
  0xa9,
  0xab,
  0xcd, // LDA #$cdab
  0x22,
  0x00,
  0x00,
  0xc1, // JSL $c10000
  0x80,
  0xfe, // BRA -2
]);
const HIROM_FAR_CODE = Buffer.from([
  0xa2,
  0x12,
  0x34, // LDX #$3412
  0xca, // DEX
  0x6b, // RTL
]);

const loromImage = (): Buffer =>
  snesCartridgeImage({
    mapperByte: 0x20,
    resetVector: 0x8000,
    code: [
      { offset: 0x0000, bytes: LOROM_ENTRY_CODE },
      { offset: 0x8000, bytes: LOROM_FAR_CODE },
    ],
  });

const fastHiromImage = (): Buffer =>
  snesCartridgeImage({
    sizeBytes: 0x20000,
    headerBases: [SNES_HIROM_TITLE_BASE],
    mapperByte: 0x31,
    resetVector: 0x8000,
    code: [
      { offset: 0x8000, bytes: HIROM_ENTRY_CODE },
      { offset: 0x10000, bytes: HIROM_FAR_CODE },
    ],
  });

/**
 * Simulate the bridge's inspect_native_load_image measurement for a
 * SnesRomLoader import, from the empirically observed block layout: canonical
 * file-backed banks, the anchored bank-$00 ROM mirror, and the loader's
 * uninitialized system blocks. Independently authored from the attestation
 * under test so agreement is evidence, not tautology.
 */
const measuredObservations = (
  bytes: Buffer,
  input: {
    readonly mapping: "lorom" | "hirom";
    readonly romOffset: number;
    readonly banks: readonly {
      readonly bank: number;
      readonly start: number;
      readonly length: number;
      readonly fileOffset: number;
    }[];
    readonly entry: number;
  },
): NativeLoadImageObservation => {
  const hex = (value: number): string => `0x${value.toString(16)}`;
  const blockName = (bank: number): string =>
    `bank_${bank.toString(16).padStart(2, "0")}_${input.mapping}`;
  const unbacked = (name: string, start: number, length: number) => ({
    block: name,
    start: hex(start),
    end: hex(start + length - 1),
    address_space: "bus",
    initialized: false,
    loaded: true,
    overlay: false,
    length,
    source_file_index: null,
    file_offset: null,
    sha256: null,
  });
  return {
    executable_format: "SNES ROM Loader",
    language_id: "65816:LE:24:snes",
    compiler_spec_id: "default",
    image_base: "0x0",
    default_address_space: "bus",
    source_files: [
      {
        name: "game.sfc",
        size: bytes.length,
        original_sha256: sha256(bytes),
        modified_sha256: sha256(bytes),
      },
    ],
    mappings: [
      unbacked("snes_low_ram", 0x000000, 0x2000),
      unbacked("snes_io", 0x002000, 0x4000),
      {
        ...unbacked("bank_00_rom_mirror", 0x008000, 0x8000),
        byte_mapped_source: {
          start: input.mapping === "lorom" ? "0x808000" : "0xc08000",
          end: input.mapping === "lorom" ? "0x80ffff" : "0xc0ffff",
          address_space: "bus",
        },
      },
      unbacked("snes_wram", 0x7e0000, 0x20000),
      ...input.banks.map((bank) => ({
        block: blockName(bank.bank),
        start: hex(bank.start),
        end: hex(bank.start + bank.length - 1),
        address_space: "bus",
        initialized: true,
        loaded: true,
        overlay: false,
        length: bank.length,
        source_file_index: 0,
        file_offset: bank.fileOffset,
        sha256: sha256(
          bytes.subarray(bank.fileOffset, bank.fileOffset + bank.length),
        ),
      })),
    ],
    relocations: [],
    entry_points: [hex(input.entry)],
    entry_context: [{ address: hex(input.entry), registers: [] }],
  };
};

const loromBanks = (romOffset: number, romSize = 0x10000) =>
  Array.from({ length: Math.ceil(romSize / 0x8000) }, (_, index) => ({
    bank: 0x80 + index,
    start: 0x808000 + index * 0x10000,
    length: Math.min(0x8000, romSize - index * 0x8000),
    fileOffset: romOffset + index * 0x8000,
  }));

const hiromBanks = (romOffset: number, romSize = 0x20000) =>
  Array.from({ length: Math.ceil(romSize / 0x10000) }, (_, index) => ({
    bank: 0xc0 + index,
    start: 0xc00000 + index * 0x10000,
    length: Math.min(0x10000, romSize - index * 0x10000),
    fileOffset: romOffset + index * 0x10000,
  }));

const attest = (bytes: Buffer, observations: NativeLoadImageObservation) =>
  attestGhidraSnesRomLoadImage({
    bytes,
    targetSha256: sha256(bytes),
    observations,
  });

describe("attestGhidraSnesRomLoadImage positive controls", () => {
  it("verifies a synthetic two-bank LoROM import end to end", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("verified");
    expect(snesResult(attested.value)).toMatchObject({
      format: "snes-rom",
      declared_mapping: "lorom",
      mapping_mode_byte: 0x20,
      declared_speed: "slow",
      rom_offset: 0,
      rom_size_bytes: 0x10000,
    });
    expect(snesResult(attested.value).canonical_banks).toHaveLength(2);
    expect(snesResult(attested.value).canonical_banks[0]).toMatchObject({
      name: "bank_80_lorom",
      file_offset: 0,
    });
    expect(snesResult(attested.value).reset_vector).toMatchObject({
      address: "0x80fffc",
      file_offset: 0x7ffc,
      entry: "0x808000",
    });
  });

  it("verifies a synthetic Fast HiROM import with full-window banks", async () => {
    const bytes = fastHiromImage();
    const observations = measuredObservations(bytes, {
      mapping: "hirom",
      romOffset: 0,
      banks: hiromBanks(0),
      entry: 0xc08000,
    });
    const attested = await attestGhidraSnesRomLoadImage({
      bytes,
      targetSha256: sha256(bytes),
      observations,
    });
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("verified");
    expect(snesResult(attested.value)).toMatchObject({
      declared_mapping: "hirom",
      mapping_mode_byte: 0x31,
      declared_speed: "fast",
    });
    expect(snesResult(attested.value).canonical_banks).toHaveLength(2);
    expect(snesResult(attested.value).canonical_banks[1]).toMatchObject({
      name: "bank_c1_hirom",
      start: "0xc10000",
      file_offset: 0x10000,
      length: 0x10000,
    });
    expect(snesResult(attested.value).reset_vector).toMatchObject({
      address: "0xc0fffc",
      file_offset: 0xfffc,
      entry: "0xc08000",
    });
  });

  it("verifies a copier-headered LoROM dump against shifted file offsets", async () => {
    const payload = loromImage();
    const bytes = Buffer.concat([Buffer.alloc(0x200, 0xff), payload]);
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0x200,
      banks: loromBanks(0x200),
      entry: 0x808000,
    });
    const attested = await attestGhidraSnesRomLoadImage({
      bytes,
      targetSha256: sha256(bytes),
      observations,
    });
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("verified");
    expect(snesResult(attested.value).rom_offset).toBe(0x200);
    expect(snesResult(attested.value).reset_vector).toMatchObject({
      file_offset: 0x200 + 0x7ffc,
      entry: "0x808000",
    });
  });
});

describe("attestGhidraSnesRomLoadImage fail-closed boundaries", () => {
  it("refuses a snapshot whose bytes do not match the admitted target", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    const attested = await attestGhidraSnesRomLoadImage({
      bytes: Buffer.concat([bytes, Buffer.alloc(1, 0xea)]),
      targetSha256: sha256(bytes),
      observations,
    });
    expect(attested.ok).toBe(false);
    if (attested.ok) throw new Error("digest mismatch was accepted");
    expect(attested.error).toContain("does not match the admitted target");
  });

  it("refuses bytes that no longer re-admit as a valid cartridge", async () => {
    const bytes = loromImage();
    const corrupted = Buffer.from(bytes);
    corrupted.writeUInt16LE(
      corrupted.readUInt16LE(snesHeaderBase(SNES_LOROM_TITLE_BASE) + 0x1f) ^ 1,
      snesHeaderBase(SNES_LOROM_TITLE_BASE) + 0x1f,
    );
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    const attested = await attestGhidraSnesRomLoadImage({
      bytes: corrupted,
      targetSha256: sha256(corrupted),
      observations,
    });
    expect(attested.ok).toBe(false);
  });

  it("refuses declared mappings outside the qualified lorom/hirom lanes", async () => {
    const bytes = snesCartridgeImage({ mapperByte: 0x23 });
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    const attested = await attestGhidraSnesRomLoadImage({
      bytes,
      targetSha256: sha256(bytes),
      observations,
    });
    expect(attested.ok).toBe(false);
    if (attested.ok) throw new Error("unsupported mapper was attested");
    expect(attested.error).toContain("sa-1");
  });

  it("refuses a reset vector that resolves outside the canonical banks", async () => {
    const bytes = snesCartridgeImage({
      mapperByte: 0x20,
      resetVector: 0x0040,
    });
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x800040,
    });
    const attested = await attest(bytes, observations);
    expect(attested.ok).toBe(false);
    if (attested.ok) throw new Error("unbacked entry was accepted");
    expect(attested.error).toContain("reset vector");
  });
});

describe("attestGhidraSnesRomLoadImage mismatch detection", () => {
  it("reports a mismatch for a shifted canonical bank file offset", async () => {
    const bytes = loromImage();
    const banks = loromBanks(0).map((bank, index) =>
      index === 1 ? { ...bank, fileOffset: bank.fileOffset + 1 } : bank,
    );
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks,
      entry: 0x808000,
    });
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("mismatch");
    expect(
      snesResult(attested.value).checks.some(
        (check) => !check.matched && check.name.includes("file_offset"),
      ),
    ).toBe(true);
  });

  it("reports a mismatch for a corrupted canonical bank digest", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    observations.mappings[4]!.sha256 = `0${observations.mappings[4]!.sha256!.slice(1)}`;
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("mismatch");
    expect(
      snesResult(attested.value).checks.some(
        (check) => !check.matched && check.name.endsWith(".sha256"),
      ),
    ).toBe(true);
  });

  it("reports a mismatch for a missing canonical bank", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0).slice(0, 1),
      entry: 0x808000,
    });
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("mismatch");
    expect(
      snesResult(attested.value).checks.some(
        (check) => !check.matched && check.name === "canonical_bank_set",
      ),
    ).toBe(true);
  });

  it("reports a mismatch for an unexpected extra file-backed mapping", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    observations.mappings.push({
      ...observations.mappings[4]!,
      block: "bank_7f_lorom",
      start: "0x7f8000",
      end: "0x7fffff",
      file_offset: 0x0,
    });
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("mismatch");
  });

  it("reports a mismatch for an unseeded or wrong entry point", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    observations.entry_points = [];
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("mismatch");
    expect(
      snesResult(attested.value).checks.some(
        (check) => !check.matched && check.name === "entry_points",
      ),
    ).toBe(true);
  });

  it("reports a mismatch for a lost bank-$00 ROM mirror", async () => {
    const bytes = loromImage();
    const observations = measuredObservations(bytes, {
      mapping: "lorom",
      romOffset: 0,
      banks: loromBanks(0),
      entry: 0x808000,
    });
    observations.mappings = observations.mappings.filter(
      (mapping) => mapping.block !== "bank_00_rom_mirror",
    );
    const attested = await attest(bytes, observations);
    if (!attested.ok) throw attested.error;
    expect(snesResult(attested.value).status).toBe("mismatch");
  });
});

describe("qualified loader boundaries", () => {
  describe.each(["lorom", "hirom"] as const)("%s mirror source", (mapping) => {
    it.each([
      ["absent", undefined],
      ["unmeasurable", null],
      [
        "wrong anchor",
        { start: "0x818000", end: "0x81ffff", address_space: "bus" },
      ],
      [
        "wrong end",
        {
          start: mapping === "lorom" ? "0x808000" : "0xc08000",
          end: "0xc0fffe",
          address_space: "bus",
        },
      ],
      [
        "wrong space",
        {
          start: mapping === "lorom" ? "0x808000" : "0xc08000",
          end: mapping === "lorom" ? "0x80ffff" : "0xc0ffff",
          address_space: "other",
        },
      ],
    ] as const)(
      "refuses a correct-shaped mirror with %s source",
      async (_label, source) => {
        const bytes = mapping === "lorom" ? loromImage() : fastHiromImage();
        const observations = measuredObservations(bytes, {
          mapping,
          romOffset: 0,
          banks: mapping === "lorom" ? loromBanks(0) : hiromBanks(0),
          entry: mapping === "lorom" ? 0x808000 : 0xc08000,
        });
        const mirror = observations.mappings.find(
          (row) => row.block === "bank_00_rom_mirror",
        )!;
        if (source === undefined) delete mirror.byte_mapped_source;
        else mirror.byte_mapped_source = source;
        const result = await attest(bytes, observations);
        if (!result.ok) throw result.error;
        const image = snesResult(result.value);
        expect(image.status).toBe("mismatch");
        expect(image.mirror_banks[0]?.canonical_start).toBe(
          source?.start ?? null,
        );
        expect(
          image.checks.find(
            (check) =>
              check.name === "blocks[bank_00_rom_mirror].byte_mapped_source",
          )?.matched,
        ).toBe(false);
      },
    );
  });

  it.each(["lorom", "hirom"] as const)(
    "%s accepts exact canonical capacity but refuses a valid 6MiB payload declaring 8MiB",
    async (mapping) => {
      for (const sizeBytes of [0x600000, 0x400000]) {
        const bytes = snesCartridgeImage({
          sizeBytes,
          romSizeExponent: sizeBytes === 0x400000 ? 12 : 13,
          mapperByte: mapping === "lorom" ? 0x20 : 0x31,
          headerBases: [
            mapping === "lorom" ? SNES_LOROM_TITLE_BASE : SNES_HIROM_TITLE_BASE,
          ],
          resetVector: 0x8000,
        });
        const admitted = await admitSnesRom({
          fileSize: bytes.length,
          readAt: async (offset, length) =>
            bytes.subarray(offset, offset + length),
        });
        if (!admitted.ok) throw admitted.error;
        expect(admitted.value.romSizeBytes).toBe(sizeBytes);
        const coordinates = snesResetVectorCoordinates(admitted.value);
        const observations = measuredObservations(bytes, {
          mapping,
          romOffset: 0,
          // Model the actual upstream range exhaustion, not invented banks.
          banks:
            mapping === "lorom"
              ? loromBanks(0, 0x400000)
              : hiromBanks(0, 0x400000),
          entry: mapping === "lorom" ? 0x808000 : 0xc08000,
        });
        const result = await attest(bytes, observations);
        if (sizeBytes === 0x400000) {
          if (!coordinates.ok) throw coordinates.error;
          if (!result.ok) throw result.error;
          expect(snesResult(result.value).status).toBe("verified");
          expect(
            snesResult(result.value).canonical_banks.reduce(
              (sum, bank) => sum + bank.length,
              0,
            ),
          ).toBe(sizeBytes);
        } else {
          expect(result.ok).toBe(false);
          if (result.ok) throw new Error("unmapped tail attested");
          expect(result.error).toContain("canonical capacity");
          expect(coordinates.ok).toBe(false);
          if (coordinates.ok)
            throw new Error("unmapped tail accepted for execution");
          expect(coordinates.error).toContain("canonical capacity");
        }
      }
    },
  );
});
