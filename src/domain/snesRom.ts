import { err, ok, type Result } from "./result.js";

/**
 * Mapping-mode nibbles of the SNES internal header ($FFD5) that the
 * caller-installed ghidra-snes extension recognizes. Anything else leaves the
 * loader without a load specification, so admission refuses it too.
 */
const DECLARED_MAPPINGS = {
  0x0: "lorom",
  0x1: "hirom",
  0x2: "s-dd1",
  0x3: "sa-1",
  0x5: "exhirom",
  0xa: "spc7110",
} as const;

/** Mapping mode the internal header declares; not a verified memory mapping. */
export type SnesDeclaredMapping =
  (typeof DECLARED_MAPPINGS)[keyof typeof DECLARED_MAPPINGS];

/**
 * Speed the $FFD5 high-nibble FastROM bit declares (bit 4). A header
 * declaration only; the loader maps both speeds to the same canonical banks.
 */
export type SnesDeclaredSpeed = "slow" | "fast";

/** Header-declared speed from the raw $FFD5 mapping-mode byte. */
export const snesDeclaredSpeed = (
  mappingModeByte: number,
): SnesDeclaredSpeed => ((mappingModeByte & 0x10) !== 0 ? "fast" : "slow");

// Header candidates are the $FFBF bytes preceding the $FFC0 title at the
// standard LoROM, HiROM, and ExHiROM locations, shifted by any copier header.
const HEADER_CANDIDATES = [0x7fbf, 0xffbf, 0x40ffbf] as const;
const HEADER_BYTES = 0x41; // $FFBF..$FFFF inclusive
const TITLE_OFFSET = 0x01; // 21 printable bytes at $FFC0
const MAPPING_MODE_OFFSET = 0x16; // $FFD5
const ROM_SIZE_OFFSET = 0x18; // $FFD7
const CHECKSUM_COMPLEMENT_OFFSET = 0x1d; // $FFDC
const CHECKSUM_OFFSET = 0x1f; // $FFDE
const BANK_BYTES = 0x8000;
const COPIER_HEADER_BYTES = 0x200;
/** The loader's bound on a believable declared cartridge size (12 MiB). */
const MAX_DECLARED_ROM_BYTES = 0x00c0_0000;
/** SPC7110 retail dumps of 3 MiB checksum the raw ROM twice. */
const SPC7110_DOUBLE_CHECKSUM_BYTES = 0x0030_0000;

/**
 * Facts from the one admitted internal header. They are file declarations,
 * not established load semantics: no bank mapping and no entry point is
 * recorded until the loader itself establishes them.
 */
export interface SnesRomCartridge {
  /** Absolute file offset of the admitted $FFBF header byte. */
  readonly headerOffset: number;
  /** Copier/SMC prefix size; 0 for a clean bank-aligned dump. */
  readonly romOffset: number;
  /** ROM payload bytes after any copier prefix. */
  readonly romSizeBytes: number;
  /** Cartridge size declared at $FFD7 as 1024 << exponent. */
  readonly declaredRomSizeBytes: number;
  /** Mapping mode the $FFD5 byte declares. */
  readonly declaredMapping: SnesDeclaredMapping;
  /** Raw $FFD5 mapping-mode byte, carrying the declared FastROM speed bit. */
  readonly mappingModeByte: number;
  /** Speed the $FFD5 FastROM bit declares. */
  readonly declaredSpeed: SnesDeclaredSpeed;
  /** 16-bit checksum word carried by the admitted header. */
  readonly checksum: number;
}

/** Why a cartridge was refused; the target file itself failed the checks. */
export interface SnesRomAdmissionRejection {
  readonly reason: string;
  readonly constraint: "file_format_rejected";
}

interface HeaderCandidate {
  readonly headerOffset: number;
  readonly declaredRomSizeBytes: number;
  readonly declaredMapping: SnesDeclaredMapping;
  readonly mappingModeByte: number;
  readonly checksum: number;
}

/** Shared refusal for zero surviving candidates, cheap or checksum-filtered. */
const NO_VALID_HEADER_REASON =
  "No unambiguous SNES internal header passed the cartridge checks (checksum complement, mapping mode, declared ROM size, printable title, whole-image checksum)";

/**
 * Admit a SNES cartridge from its internal header, mirroring the load-spec
 * checks of the caller-installed ghidra-snes extension: file-size remainder,
 * checksum complement, recognized mapping mode, declared-size bounds,
 * printable title, and whole-image checksum. Exactly one candidate location
 * may pass; zero or several leave the cartridge metadata unusable or
 * ambiguous, and admission fails closed.
 */
export const admitSnesRom = async (input: {
  readonly fileSize: number;
  readonly readAt: (offset: number, length: number) => Promise<Buffer>;
}): Promise<Result<SnesRomCartridge, SnesRomAdmissionRejection>> => {
  const romOffset = input.fileSize % BANK_BYTES;
  if (romOffset !== 0 && romOffset !== COPIER_HEADER_BYTES)
    return err({
      reason: `SNES ROM file must be bank-aligned with an optional 0x200-byte copier header; file size ${input.fileSize} has remainder 0x${romOffset.toString(16)}`,
      constraint: "file_format_rejected",
    });
  const romSizeBytes = input.fileSize - romOffset;
  const candidates: HeaderCandidate[] = [];
  for (const base of HEADER_CANDIDATES) {
    const headerOffset = romOffset + base;
    if (headerOffset + HEADER_BYTES > input.fileSize) continue;
    const header = await input.readAt(headerOffset, HEADER_BYTES);
    if (header.length !== HEADER_BYTES)
      return err({
        reason: `SNES ROM header read at 0x${headerOffset.toString(16)} was truncated`,
        constraint: "file_format_rejected",
      });
    const candidate = parseHeaderCandidate(header, headerOffset, romSizeBytes);
    if (candidate !== undefined) candidates.push(candidate);
  }
  if (candidates.length === 0)
    return err({
      reason: NO_VALID_HEADER_REASON,
      constraint: "file_format_rejected",
    });
  const romImage = await input.readAt(romOffset, romSizeBytes);
  const valid = candidates.filter(
    (candidate) =>
      candidate.checksum ===
      snesImageChecksum(
        romImage,
        candidate.declaredRomSizeBytes,
        candidate.declaredMapping,
      ),
  );
  if (valid.length !== 1)
    return err({
      reason:
        valid.length === 0
          ? NO_VALID_HEADER_REASON
          : `Multiple valid SNES internal headers (at ${valid
              .map((candidate) => `0x${candidate.headerOffset.toString(16)}`)
              .join(", ")}) made the cartridge metadata ambiguous`,
      constraint: "file_format_rejected",
    });
  const admitted = valid[0]!;
  return ok({
    headerOffset: admitted.headerOffset,
    romOffset,
    romSizeBytes,
    declaredRomSizeBytes: admitted.declaredRomSizeBytes,
    declaredMapping: admitted.declaredMapping,
    mappingModeByte: admitted.mappingModeByte,
    declaredSpeed: snesDeclaredSpeed(admitted.mappingModeByte),
    checksum: admitted.checksum,
  });
};

const parseHeaderCandidate = (
  header: Buffer,
  headerOffset: number,
  romSizeBytes: number,
): HeaderCandidate | undefined => {
  const checksum = header.readUInt16LE(CHECKSUM_OFFSET);
  const complement = header.readUInt16LE(CHECKSUM_COMPLEMENT_OFFSET);
  if (((checksum ^ complement) & 0xffff) !== 0xffff) return undefined;
  const mappingModeByte = header[MAPPING_MODE_OFFSET]!;
  const declaredMapping = (
    DECLARED_MAPPINGS as Record<number, SnesDeclaredMapping | undefined>
  )[mappingModeByte & 0x0f];
  if (declaredMapping === undefined) return undefined;
  const declaredRomSizeBytes = 1024 * 2 ** header[ROM_SIZE_OFFSET]!;
  if (
    declaredRomSizeBytes < romSizeBytes ||
    declaredRomSizeBytes >= MAX_DECLARED_ROM_BYTES
  )
    return undefined;
  for (let index = 0; index < 21; index++) {
    const value = header[TITLE_OFFSET + index]!;
    if (value < 0x20 || value > 0x7e) return undefined;
  }
  return {
    headerOffset,
    declaredRomSizeBytes,
    declaredMapping,
    mappingModeByte,
    checksum,
  };
};

/**
 * Canonical SNES checksum of a ROM payload: standard mappings expand the
 * image to the declared size by mirroring, SPC7110 retail layouts follow the
 * observed repeat behavior instead. Mirrors the extension's checksum so
 * admission accepts exactly what its loader would accept.
 */
const snesImageChecksum = (
  image: Buffer,
  declaredRomSizeBytes: number,
  declaredMapping: SnesDeclaredMapping,
): number => {
  if (declaredMapping === "spc7110") {
    if (
      image.length === SPC7110_DOUBLE_CHECKSUM_BYTES &&
      declaredRomSizeBytes > image.length
    )
      return (2 * byteSum(image)) & 0xffff;
    return byteSum(image);
  }
  let expanded = image;
  const mappedBytes = Math.max(image.length, declaredRomSizeBytes);
  while (expanded.length < mappedBytes) {
    const mirrorStart = mappedBytes >> 1;
    if (mirrorStart >= expanded.length) break;
    const mirrorLength = Math.min(
      mappedBytes - expanded.length,
      expanded.length - mirrorStart,
    );
    expanded = Buffer.concat([
      expanded,
      expanded.subarray(mirrorStart, mirrorStart + mirrorLength),
    ]);
  }
  return byteSum(expanded);
};

const byteSum = (bytes: Buffer): number => {
  let sum = 0;
  for (const value of bytes) sum = (sum + value) & 0xffff;
  return sum;
};
