import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Real-provider qualification for the SNES SnesRomLoader execution lane
// (tracker: Zutfen-LLC/retro-reconstruction #23). Every fixture is a fully
// synthetic cartridge built below from independently authored 65816 opcode
// bytes; no commercial ROM is read, downloaded, or committed.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-65816.mjs");
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation with the ghidra-snes extension installed.",
  );
const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
await mkdir(join(root, "build"), { recursive: true });
const workspace = await mkdtemp(join(root, "build", "rea-65816-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const entrypoint = join(root, "scripts", "rea.mjs");
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-65816-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});

const byteSum = (bytes) => {
  let sum = 0;
  for (const value of bytes) sum = (sum + value) & 0xffff;
  return sum;
};
const expandToDeclared = (image, declared) => {
  let expanded = image;
  while (expanded.length < declared) {
    const mirrorStart = declared >> 1;
    if (mirrorStart >= expanded.length) break;
    const mirrorLength = Math.min(
      declared - expanded.length,
      expanded.length - mirrorStart,
    );
    expanded = Buffer.concat([
      expanded,
      expanded.subarray(mirrorStart, mirrorStart + mirrorLength),
    ]);
  }
  return expanded;
};
const cartridge = (input) => {
  const size = input.size ?? 0x10000;
  const titleBase = input.titleBase ?? 0x7fc0;
  const image = Buffer.alloc(size, 0xea);
  image.fill(0x00, 0, Math.min(size, 0x100));
  for (const chunk of input.code ?? []) chunk.bytes.copy(image, chunk.offset);
  if (input.resetVector !== undefined)
    image.writeUInt16LE(input.resetVector, titleBase - 1 + 0x3d);
  const at = titleBase - 1;
  image.write("REA SYNTH SNES TEST".padEnd(21, " "), at + 1, 21, "latin1");
  image.writeUInt8(input.mapperByte ?? 0x20, at + 0x16);
  image.writeUInt8(
    input.romSizeExponent ?? Math.log2(size / 1024) | 0,
    at + 0x18,
  );
  image.writeUInt8(0x01, at + 0x1a);
  image.writeUInt8(0x33, at + 0x1b);
  const declared =
    1024 * 2 ** (input.romSizeExponent ?? Math.log2(size / 1024) | 0);
  for (let pass = 0; pass < 2; pass++) {
    const checksum = byteSum(expandToDeclared(image, declared));
    image.writeUInt16LE(checksum ^ 0xffff, at + 0x1d);
    image.writeUInt16LE(checksum, at + 0x1f);
  }
  return image;
};

// Independently authored 65816 fixtures: a native-mode entry with M/X mode
// switches, 8/16-bit immediates, a far JSL, an absolute-long store, and a
// loop; the far bank holds an indexed subroutine ending in RTL.
const ENTRY_CODE = Buffer.from([
  0x78, // SEI
  0x18, // CLC
  0xfb, // XCE
  0xc2,
  0x10, // REP #$10 (16-bit index)
  0xe2,
  0x20, // SEP #$20 (8-bit A)
  0xa9,
  0x34, // LDA #$34 (8-bit immediate)
  0xc2,
  0x20, // REP #$20 (16-bit A)
  0xa9,
  0x56,
  0x78, // LDA #$7856 (16-bit immediate)
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
const FAR_CODE = Buffer.from([
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
  0xcd, // LDA #$cdab (16-bit immediate)
  0xe2,
  0x20, // SEP #$20 (8-bit A)
  0xa9,
  0xef, // LDA #$ef (8-bit immediate)
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

const loromBytes = cartridge({
  mapperByte: 0x20,
  resetVector: 0x8000,
  code: [
    { offset: 0x0000, bytes: ENTRY_CODE },
    { offset: 0x8000, bytes: FAR_CODE },
  ],
});
const hiromBytes = cartridge({
  size: 0x20000,
  titleBase: 0xffc0,
  mapperByte: 0x31,
  resetVector: 0x8000,
  code: [
    { offset: 0x8000, bytes: HIROM_ENTRY_CODE },
    { offset: 0x10000, bytes: HIROM_FAR_CODE },
  ],
});
const loromPath = join(workspace, "lorom.sfc");
const hiromPath = join(workspace, "fast-hirom.sfc");
await writeFile(loromPath, loromBytes);
await writeFile(hiromPath, hiromBytes);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  if (["open_binary", "binary_session", "close_binary"].includes(name))
    return requireMcpOperationResult(result, name);
  return result.structuredContent;
}

function evidence(value, digest, extra = {}) {
  const result = parseEvidence(value);
  assert.equal(result.subject.digest.sha256, digest);
  assert.equal(result.subject.architecture, "65816");
  assert.equal(result.subject.format, "snes-rom");
  for (const [key, expected] of Object.entries(extra))
    assert.deepEqual(result[key], expected, key);
  return result;
}

async function qualifyCartridge(path, bytes, expectations) {
  const digest = sha256(bytes);
  await call("open_binary", {
    path,
    format: "snes-rom",
    provider_id: "ghidra",
  });
  await call("binary_session");
  const image = evidence(await call("inspect_native_load_image"), digest);
  const result = image.normalized_result;
  assert.equal(result.status, "verified", JSON.stringify(result, null, 2));
  assert.equal(result.format, "snes-rom");
  assert.equal(result.language_id, "65816:LE:24:snes");
  assert.equal(result.compiler_spec_id, "default");
  assert.deepEqual(result.canonical_banks, expectations.banks);
  assert.deepEqual(result.mirror_banks, expectations.mirrors);
  assert.deepEqual(result.reset_vector, expectations.resetVector);
  assert.equal(result.declared_mapping, expectations.mapping);
  assert.equal(result.declared_speed, expectations.speed);
  assert.equal(result.mapping_mode_byte, expectations.mapperByte);
  const memory = evidence(
    await call("read_bytes", {
      address: expectations.entry,
      length: expectations.entryCode.length,
    }),
    digest,
  );
  assert.equal(
    memory.normalized_result.bytes_hex,
    expectations.entryCode.toString("hex"),
  );
  const procedures = evidence(await call("list_procedures"), digest);
  assert.ok(
    procedures.normalized_result.some(
      (procedure) => procedure.address === expectations.entry,
    ),
    JSON.stringify(procedures.normalized_result),
  );
  const immediateBitWidth = (instruction) => {
    for (const operand of instruction.normalized_result.operands)
      for (const component of operand.components)
        if (component.kind === "immediate") return component.bit_width;
    return null;
  };
  const narrow = evidence(
    await call("inspect_native_instruction", {
      address: expectations.modeProbe.narrow,
    }),
    digest,
  );
  assert.equal(narrow.normalized_result.status, "decoded");
  assert.equal(narrow.normalized_result.mnemonic.toUpperCase(), "LDA");
  assert.equal(narrow.normalized_result.length, 2);
  assert.equal(immediateBitWidth(narrow), 8);
  const wide = evidence(
    await call("inspect_native_instruction", {
      address: expectations.modeProbe.wide,
    }),
    digest,
  );
  assert.equal(wide.normalized_result.status, "decoded");
  assert.equal(wide.normalized_result.mnemonic.toUpperCase(), "LDA");
  assert.equal(wide.normalized_result.length, 3);
  assert.equal(immediateBitWidth(wide), 16);
  const callSite = evidence(
    await call("inspect_native_instruction", {
      address: expectations.modeProbe.farCall,
    }),
    digest,
  );
  assert.ok(
    callSite.normalized_result.references.some(
      (reference) =>
        reference.call && reference.target_address === expectations.farTarget,
    ),
    JSON.stringify(callSite.normalized_result),
  );
  await call("close_binary");
  return image;
}

let report;
try {
  await client.connect(transport);
  const loromImage = await qualifyCartridge(loromPath, loromBytes, {
    mapping: "lorom",
    speed: "slow",
    mapperByte: 0x20,
    entry: "0x808000",
    entryCode: ENTRY_CODE,
    banks: [
      {
        name: "bank_80_lorom",
        bank: "0x80",
        start: "0x808000",
        end: "0x80ffff",
        length: 0x8000,
        file_offset: 0,
        sha256: sha256(loromBytes.subarray(0, 0x8000)),
      },
      {
        name: "bank_81_lorom",
        bank: "0x81",
        start: "0x818000",
        end: "0x81ffff",
        length: 0x8000,
        file_offset: 0x8000,
        sha256: sha256(loromBytes.subarray(0x8000, 0x10000)),
      },
    ],
    mirrors: [
      {
        name: "bank_00_rom_mirror",
        start: "0x8000",
        end: "0xffff",
        length: 0x8000,
        canonical_start: "0x808000",
      },
    ],
    resetVector: {
      address: "0x80fffc",
      file_offset: 0x7ffc,
      value_hex: "0x8000",
      entry: "0x808000",
      entry_file_offset: 0,
    },
    modeProbe: { narrow: "0x808007", wide: "0x80800b", farCall: "0x80800e" },
    farTarget: "0x818000",
  });
  const hiromImage = await qualifyCartridge(hiromPath, hiromBytes, {
    mapping: "hirom",
    speed: "fast",
    mapperByte: 0x31,
    entry: "0xc08000",
    entryCode: HIROM_ENTRY_CODE,
    banks: [
      {
        name: "bank_c0_hirom",
        bank: "0xc0",
        start: "0xc00000",
        end: "0xc0ffff",
        length: 0x10000,
        file_offset: 0,
        sha256: sha256(hiromBytes.subarray(0, 0x10000)),
      },
      {
        name: "bank_c1_hirom",
        bank: "0xc1",
        start: "0xc10000",
        end: "0xc1ffff",
        length: 0x10000,
        file_offset: 0x10000,
        sha256: sha256(hiromBytes.subarray(0x10000, 0x20000)),
      },
    ],
    mirrors: [
      {
        name: "bank_00_rom_mirror",
        start: "0x8000",
        end: "0xffff",
        length: 0x8000,
        canonical_start: "0xc08000",
      },
    ],
    resetVector: {
      address: "0xc0fffc",
      file_offset: 0xfffc,
      value_hex: "0x8000",
      entry: "0xc08000",
      entry_file_offset: 0x8000,
    },
    modeProbe: { narrow: "0xc0800a", wide: "0xc08005", farCall: "0xc0800c" },
    farTarget: "0xc10000",
  });

  // Negative control: a corrupted mapper byte never reaches execution.
  const corruptMapper = Buffer.from(loromBytes);
  corruptMapper.writeUInt8(0x2f, 0x7fd5);
  const corruptMapperPath = join(workspace, "corrupt-mapper.sfc");
  await writeFile(corruptMapperPath, corruptMapper);
  const refusedMapper = await client.callTool(
    {
      name: "open_binary",
      arguments: { path: corruptMapperPath, format: "snes-rom" },
    },
    { timeout: 240000 },
  );
  assert.equal(refusedMapper.isError, true);
  assert.match(JSON.stringify(refusedMapper), /SNES internal header/u);

  // Negative control: a broken checksum complement is refused at admission.
  const brokenChecksum = Buffer.from(loromBytes);
  brokenChecksum.writeUInt16LE(brokenChecksum.readUInt16LE(0x7fdc) ^ 1, 0x7fdc);
  const brokenChecksumPath = join(workspace, "broken-checksum.sfc");
  await writeFile(brokenChecksumPath, brokenChecksum);
  const refusedChecksum = await client.callTool(
    {
      name: "open_binary",
      arguments: { path: brokenChecksumPath, format: "snes-rom" },
    },
    { timeout: 240000 },
  );
  assert.equal(refusedChecksum.isError, true);

  // Negative control: an sa-1 cartridge admits as a target but has no
  // qualified execution lane; analysis must refuse, not approximate.
  const sa1Bytes = cartridge({ mapperByte: 0x23, resetVector: 0x8000 });
  const sa1Path = join(workspace, "sa1.sfc");
  await writeFile(sa1Path, sa1Bytes);
  await call("open_binary", {
    path: sa1Path,
    format: "snes-rom",
    provider_id: "ghidra",
  });
  const sa1Refusal = await client.callTool(
    { name: "inspect_native_load_image", arguments: {} },
    { timeout: 240000 },
  );
  assert.equal(sa1Refusal.isError, true);
  assert.match(
    JSON.stringify(sa1Refusal),
    /no qualified SnesRomLoader execution lane/u,
  );
  await call("close_binary");

  // CLI/MCP parity for both cartridges through the same real provider.
  for (const [path, bytes, mcpImage] of [
    [loromPath, loromBytes, loromImage],
    [hiromPath, hiromBytes, hiromImage],
  ]) {
    const { stdout } = await exec(
      process.execPath,
      [
        entrypoint,
        "inspect-native-load-image",
        path,
        "--target-format",
        "snes-rom",
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    const cli = parseEvidence(JSON.parse(stdout));
    assert.deepEqual(cli.normalized_result, mcpImage.normalized_result);
    assert.equal(cli.analysis_profile.digest, mcpImage.analysis_profile.digest);
    assert.equal(cli.subject.digest.sha256, sha256(bytes));
    assert.equal(cli.subject.format, "snes-rom");
  }

  assert.deepEqual(await readFile(loromPath), loromBytes);
  assert.deepEqual(await readFile(hiromPath), hiromBytes);
  assert.deepEqual(await readdir(runtime), []);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-65816-snes",
    host: process.platform,
    provider: loromImage.provider,
    targets: [
      {
        mapping: "lorom",
        sha256: sha256(loromBytes),
        bytes: loromBytes.length,
        entry: "0x808000",
      },
      {
        mapping: "fast-hirom",
        sha256: sha256(hiromBytes),
        bytes: hiromBytes.length,
        entry: "0xc08000",
      },
    ],
    per_bank_mapping_attestation: true,
    reset_vector_entry_and_function: true,
    mode_dependent_decode_and_far_call_reference: true,
    negative_controls: [
      "corrupt-mapper-refused",
      "broken-checksum-refused",
      "sa-1-execution-refused",
    ],
    cli_mcp_load_image_parity: true,
    decompiler_claimed: false,
    source_unchanged: true,
    runtime_cleanup: "complete",
  };
} catch (cause) {
  if (stderr) process.stderr.write(stderr);
  throw cause;
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
  }
}
const verifierRun = await completeVerifierRun(run);
if (process.platform !== "win32") {
  assert.equal(verifierRun.process_lineage.status, "verified");
  assert.deepEqual(verifierRun.process_lineage.descendants, []);
}
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);
