import { describe, expect, it } from "vitest";

import { admitSnesRom } from "./snesRom.js";
import {
  SNES_COPIER_HEADER_BYTES,
  SNES_DECLARED_MAPPINGS,
  SNES_HIROM_TITLE_BASE,
  SNES_LOROM_TITLE_BASE,
  snesCartridgeImage,
  snesHeaderBase,
} from "../../tests/fixtures/snesCartridge.js";

// Synthetic cartridge bytes exercise the cartridge admission boundary only.
// The header criteria mirror the documented SNES internal-header layout
// (snes.nesdev.org ROM header) and the load-spec checks of the
// caller-installed ghidra-snes extension (joshleaves/ghidra-snes@d33ce5db,
// MIT): checksum complement, recognized mapping-mode nibble, declared size
// bounds, printable title, and whole-image checksum. They prove nothing
// about SnesRomLoader execution, which is qualified separately against the
// real provider (verify:ghidra:65816).

const readAt = (bytes: Buffer) => async (offset: number, length: number) => {
  if (offset < 0 || length < 0 || offset + length > bytes.length)
    throw new Error(`fixture read out of bounds: ${offset}+${length}`);
  return bytes.subarray(offset, offset + length);
};

const admit = (bytes: Buffer) =>
  admitSnesRom({ fileSize: bytes.length, readAt: readAt(bytes) });

describe("snes-rom cartridge admission", () => {
  it("admits an unambiguous synthetic LoROM cartridge with typed facts", async () => {
    const bytes = snesCartridgeImage();
    expect(await admit(bytes)).toMatchObject({
      ok: true,
      value: {
        headerOffset: snesHeaderBase(SNES_LOROM_TITLE_BASE),
        romOffset: 0,
        romSizeBytes: 0x10000,
        declaredRomSizeBytes: 0x10000,
        declaredMapping: "lorom",
        checksum: bytes.readUInt16LE(
          snesHeaderBase(SNES_LOROM_TITLE_BASE) + 0x1f,
        ),
      },
    });
  });

  it("admits a HiROM-declared header at the HiROM candidate offset", async () => {
    const bytes = snesCartridgeImage({
      headerBases: [SNES_HIROM_TITLE_BASE],
      mapperByte: 0x21,
    });
    expect(await admit(bytes)).toMatchObject({
      ok: true,
      value: {
        headerOffset: snesHeaderBase(SNES_HIROM_TITLE_BASE),
        declaredMapping: "hirom",
      },
    });
  });

  it("records the raw mapping-mode byte and its declared speed", async () => {
    const slow = await admit(snesCartridgeImage({ mapperByte: 0x20 }));
    expect(slow).toMatchObject({
      ok: true,
      value: { mappingModeByte: 0x20, declaredSpeed: "slow" },
    });
    const fastHirom = await admit(
      snesCartridgeImage({
        headerBases: [SNES_HIROM_TITLE_BASE],
        mapperByte: 0x31,
      }),
    );
    expect(fastHirom).toMatchObject({
      ok: true,
      value: { mappingModeByte: 0x31, declaredSpeed: "fast" },
    });
  });

  it("admits a copier-headered dump and records the ROM payload offset", async () => {
    const bytes = snesCartridgeImage({ copierHeader: true });
    expect(await admit(bytes)).toMatchObject({
      ok: true,
      value: {
        headerOffset:
          SNES_COPIER_HEADER_BYTES + snesHeaderBase(SNES_LOROM_TITLE_BASE),
        romOffset: SNES_COPIER_HEADER_BYTES,
        romSizeBytes: 0x10000,
      },
    });
  });

  it("recognizes the extension's other declared mapping modes", async () => {
    for (const [mapper, declared] of SNES_DECLARED_MAPPINGS) {
      const bytes = snesCartridgeImage({ mapperByte: mapper });
      expect(await admit(bytes)).toMatchObject({
        ok: true,
        value: { declaredMapping: declared },
      });
    }
  });

  it("admits a payload smaller than half the declared size without mirroring", async () => {
    // 96 KiB payload declaring 256 KiB: the documented mirror loop starts at
    // half the declared size, which is beyond the payload, so the checksum
    // covers the raw bytes only.
    const bytes = snesCartridgeImage({
      sizeBytes: 0x18000,
      romSizeExponent: 8,
    });
    expect(await admit(bytes)).toMatchObject({
      ok: true,
      value: { romSizeBytes: 0x18000, declaredRomSizeBytes: 0x40000 },
    });
  });

  it("admits a checksum mirrored up to a larger declared size", async () => {
    // 192 KiB payload declaring 256 KiB: the trailing 64 KiB mirrors the
    // payload's [0x20000,0x30000) range into the checksum.
    const bytes = snesCartridgeImage({
      sizeBytes: 0x30000,
      romSizeExponent: 8,
    });
    expect(await admit(bytes)).toMatchObject({
      ok: true,
      value: { romSizeBytes: 0x30000, declaredRomSizeBytes: 0x40000 },
    });
  });

  it("admits the 3 MiB SPC7110 double-checksum retail layout", async () => {
    const bytes = snesCartridgeImage({
      sizeBytes: 0x300000,
      romSizeExponent: 12,
      mapperByte: 0x2a,
    });
    expect(await admit(bytes)).toMatchObject({
      ok: true,
      value: { declaredMapping: "spc7110", romSizeBytes: 0x300000 },
    });
  });
});

describe("snes-rom cartridge admission refusals", () => {
  it("rejects an unrecognized mapping-mode nibble", async () => {
    const bytes = snesCartridgeImage({ mapperByte: 0x2f });
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: {
        reason: expect.stringContaining("No unambiguous"),
        constraint: "file_format_rejected",
      },
    });
  });

  it("rejects a broken checksum complement", async () => {
    const bytes = snesCartridgeImage({ breakComplement: true });
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: { constraint: "file_format_rejected" },
    });
  });

  it("rejects a declared ROM size smaller than the payload", async () => {
    const bytes = snesCartridgeImage({ romSizeExponent: 5 });
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: { constraint: "file_format_rejected" },
    });
  });

  it("rejects a non-printable internal-header title", async () => {
    const bytes = snesCartridgeImage({ title: "REA\u0085SYNTH" });
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: { constraint: "file_format_rejected" },
    });
  });

  it("rejects a checksum that does not match the image bytes", async () => {
    const bytes = snesCartridgeImage();
    bytes.writeUInt16LE(
      (bytes.readUInt16LE(snesHeaderBase(SNES_LOROM_TITLE_BASE) + 0x1f) + 1) &
        0xffff,
      snesHeaderBase(SNES_LOROM_TITLE_BASE) + 0x1f,
    );
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: { constraint: "file_format_rejected" },
    });
  });

  it("rejects two simultaneously valid internal headers as ambiguous", async () => {
    const bytes = snesCartridgeImage({
      headerBases: [SNES_LOROM_TITLE_BASE, SNES_HIROM_TITLE_BASE],
    });
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: {
        reason: expect.stringContaining("ambiguous"),
        constraint: "file_format_rejected",
      },
    });
  });

  it("rejects file sizes with an unsupported bank remainder", async () => {
    const bytes = Buffer.concat([
      snesCartridgeImage(),
      Buffer.alloc(0x100, 0xea),
    ]);
    expect(await admit(bytes)).toMatchObject({
      ok: false,
      error: {
        reason: expect.stringContaining("bank-aligned"),
        constraint: "file_format_rejected",
      },
    });
  });
});
