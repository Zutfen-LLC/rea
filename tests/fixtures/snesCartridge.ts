/**
 * Deterministic synthetic SNES cartridge images for hermetic tests.
 *
 * Header layout and checksum rules re-derive the documented SNES internal
 * header (snes.nesdev.org ROM header) and the load-spec checks of the
 * caller-installed ghidra-snes extension (joshleaves/ghidra-snes@d33ce5db):
 * a header's checksum word and its XOR-0xFFFF complement contribute a
 * constant 0x1FE byte sum, and the whole-image checksum mirror-expands the
 * payload to the declared cartridge size. Independently authored; building
 * these bytes proves nothing about SnesRomLoader execution, which is
 * qualified separately against the real provider (verify:ghidra:65816).
 */

/** $FFC0-relative title bases of the standard internal-header candidates. */
export const SNES_LOROM_TITLE_BASE = 0x7fc0;
export const SNES_HIROM_TITLE_BASE = 0xffc0;
export const SNES_HEADER_BYTES = 0x41; // $FFBF..$FFFF inclusive
export const SNES_COPIER_HEADER_BYTES = 0x200;

export const snesHeaderBase = (titleBase: number): number => titleBase - 1;

/** Mapping-mode nibbles the extension's load spec recognizes. */
export const SNES_DECLARED_MAPPINGS = [
  [0x20, "lorom"],
  [0x21, "hirom"],
  [0x22, "s-dd1"],
  [0x23, "sa-1"],
  [0x25, "exhirom"],
  [0x2a, "spc7110"],
] as const;

/** Optional field overrides applied to every written internal header. */
export interface SnesCartridgeHeaderOptions {
  readonly title?: string;
  readonly mapperByte?: number;
  readonly romSizeExponent?: number;
}

const writeSnesHeader = (
  image: Buffer,
  titleBase: number,
  options: SnesCartridgeHeaderOptions,
  sizeBytes: number,
): void => {
  const at = snesHeaderBase(titleBase);
  const title = options.title ?? "REA SYNTH SNES TEST";
  const exponent = options.romSizeExponent ?? Math.log2(sizeBytes / 1024) | 0;
  image.write(title.padEnd(21, " "), at + 1, 21, "latin1");
  image.writeUInt8(0x00, at + 0x00); // custom chip
  image.writeUInt8(options.mapperByte ?? 0x20, at + 0x16); // $FFD5 mapping mode
  image.writeUInt8(0x00, at + 0x17); // $FFD6 chipset
  image.writeUInt8(exponent, at + 0x18); // $FFD7 ROM size exponent
  image.writeUInt8(0x00, at + 0x19); // $FFD8 RAM size
  image.writeUInt8(0x01, at + 0x1a); // $FFD9 country
  image.writeUInt8(0x33, at + 0x1b); // $FFDA dev id
  image.writeUInt8(0x00, at + 0x1c); // $FFDB version
};

/** Mirror-expand a payload to its declared size, per the documented rule. */
const expandToDeclared = (
  image: Buffer,
  declaredRomSizeBytes: number,
): Buffer => {
  let expanded = image;
  while (expanded.length < declaredRomSizeBytes) {
    const mirrorStart = declaredRomSizeBytes >> 1;
    if (mirrorStart >= expanded.length) break;
    const mirrorLength = Math.min(
      declaredRomSizeBytes - expanded.length,
      expanded.length - mirrorStart,
    );
    expanded = Buffer.concat([
      expanded,
      expanded.subarray(mirrorStart, mirrorStart + mirrorLength),
    ]);
  }
  return expanded;
};

/** ROM-payload bytes placed before checksumming (65816 code, vectors). */
export interface SnesCartridgeCode {
  /** Payload-relative offset (after any copier prefix). */
  readonly offset: number;
  readonly bytes: Buffer;
}

/**
 * Build a synthetic cartridge image whose headers carry checksum words that
 * solve to a fixed point of the loader's whole-image (mirror-expanded, or
 * doubled for the 3 MiB SPC7110 retail layout) byte sum. Two passes converge
 * because the checksum/complement byte pair always adds 0x1FE per copy.
 */
export const snesCartridgeImage = (
  options: {
    readonly sizeBytes?: number;
    readonly headerBases?: readonly number[];
    readonly copierHeader?: boolean;
    readonly breakComplement?: boolean;
    readonly resetVector?: number;
    readonly code?: readonly SnesCartridgeCode[];
  } & SnesCartridgeHeaderOptions = {},
): Buffer => {
  const size = options.sizeBytes ?? 0x10000;
  const bases = options.headerBases ?? [SNES_LOROM_TITLE_BASE];
  const image = Buffer.alloc(size, 0xea);
  image.fill(0x00, 0, Math.min(size, 0x100));
  for (const chunk of options.code ?? []) chunk.bytes.copy(image, chunk.offset);
  if (options.resetVector !== undefined)
    for (const base of bases)
      image.writeUInt16LE(options.resetVector, snesHeaderBase(base) + 0x3d);
  for (const base of bases) writeSnesHeader(image, base, options, size);
  const exponent = options.romSizeExponent ?? Math.log2(size / 1024) | 0;
  const declared = 1024 * 2 ** exponent;
  const spc7110Double =
    (options.mapperByte ?? 0x20) % 16 === 0x0a &&
    size === 0x300000 &&
    declared > size;
  const checksums = () => bases.map((base) => snesHeaderBase(base) + 0x1f);
  for (let pass = 0; pass < 2; pass++) {
    for (const at of checksums()) {
      const expanded = expandToDeclared(image, declared);
      const checksum = spc7110Double
        ? (2 * byteSum(image)) & 0xffff
        : byteSum(expanded);
      image.writeUInt16LE(checksum ^ 0xffff, at - 2); // $FFDC complement
      image.writeUInt16LE(checksum, at); // $FFDE checksum
    }
  }
  if (options.breakComplement === true)
    for (const base of bases)
      image.writeUInt16LE(
        image.readUInt16LE(snesHeaderBase(base) + 0x1d) ^ 1,
        snesHeaderBase(base) + 0x1d,
      );
  return options.copierHeader === true
    ? Buffer.concat([Buffer.alloc(SNES_COPIER_HEADER_BYTES, 0xff), image])
    : image;
};

const byteSum = (bytes: Buffer): number => {
  let sum = 0;
  for (const value of bytes) sum = (sum + value) & 0xffff;
  return sum;
};
