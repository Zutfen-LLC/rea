import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  snesExtensionContents,
  writeSnesExtension,
} from "../../fixtures/ghidraSnesInstallation.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { silentLogger } from "../../../src/logger.js";
import type { BinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import { resolveGhidraAnalysisProfile } from "../../../src/ghidra/GhidraAnalysisProfile.js";
import { IdaProvider } from "../../../src/ida/IdaProvider.js";
import { HopperProvider } from "../../../src/hopper/HopperProvider.js";
import {
  snapshotBinding,
  snapshotMatchesProfile,
} from "../../../src/domain/analysisSnapshot.js";
import type { GhidraInstallationHost } from "../../../src/ghidra/GhidraInstallation.js";

const SNES_CONTENTS = snesExtensionContents("12.1.4");

const snesTarget = {
  kind: "executable",
  format: "snes-rom",
  architecture: "65816",
  availableArchitectures: ["65816"],
  path: "/caller/game.sfc",
  sha256: "a".repeat(64),
  cartridge: {
    headerOffset: 0x7fbf,
    romOffset: 0,
    romSizeBytes: 0x10000,
    declaredRomSizeBytes: 0x10000,
    declaredMapping: "lorom",
    mappingModeByte: 0x20,
    declaredSpeed: "slow",
    checksum: 0xbe56,
  },
} satisfies BinaryTarget;

const unsupportedMapperTarget = {
  ...snesTarget,
  path: "/caller/sa1.sfc",
  sha256: "c".repeat(64),
  cartridge: {
    ...snesTarget.cartridge,
    declaredMapping: "sa-1" as const,
    mappingModeByte: 0x23,
  },
} satisfies BinaryTarget;

const rawTarget = {
  kind: "executable",
  format: "raw-binary",
  architecture: "6502",
  availableArchitectures: ["6502"],
  path: "/caller/firmware.bin",
  sha256: "b".repeat(64),
  entryPoint: "0x8000",
  entryPointSource: "0x8000",
} satisfies BinaryTarget;

const host: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () => ({
    osArch: "amd64",
    osName: "Linux",
    version: "21.0.12",
    major: 21,
    home: "/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
};

async function snesInstallation(options?: {
  readonly properties?: string;
  readonly omit?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
}) {
  const directory = await createTestTempDirectory("rea-snes-admission-");
  const root = join(directory, "Ghidra", "Extensions", "ghidra-snes");
  const contents =
    options?.properties !== undefined
      ? { ...SNES_CONTENTS, "extension.properties": options.properties }
      : SNES_CONTENTS;
  await writeSnesExtension(
    root,
    contents,
    options?.omit === undefined ? {} : { omit: options.omit },
  );
  await mkdir(join(directory, "support"));
  const parsed = parseConfig({
    GHIDRA_INSTALL_DIR: directory,
    ...options?.env,
  });
  if (!parsed.ok) throw parsed.error;
  return {
    directory,
    root,
    config: parsed.value,
    provider: new GhidraProvider(parsed.value, silentLogger, {}, host),
  };
}

describe.skipIf(process.platform === "win32")(
  "SNES target admission and profile",
  () => {
    it("supports the typed snes-rom target for admission and profile resolution", async () => {
      const { provider } = await snesInstallation();
      expect(provider.inspectTargetSupport(snesTarget)).toMatchObject({
        status: "supported",
      });
    });

    it("commits a fail-closed profile with pinned language and extension identity", async () => {
      const { provider, root } = await snesInstallation();
      const resolved = await provider.resolveAnalysisProfile(snesTarget);
      if (!resolved.ok) throw resolved.error;
      const profile = resolved.value.profile;
      if (profile === null) throw new Error("Missing SNES profile");
      expect(profile.parameters).toMatchObject({
        target_kind: "executable",
        target_format: "snes-rom",
        architecture: "65816",
        available_architectures: ["65816"],
        loader: "SnesRomLoader",
        language_id: "65816:LE:24:snes",
        compiler_spec_id: "default",
        import_mode: "ephemeral-source-immutable",
        mapping_attestation: "per-bank-file-backed-snesromloader-v1",
        entry_resolution: "reset-vector-canonical-bank-v1",
        load_image_evidence: "independent-snes-bank-mapping-v1",
        snes_extension: {
          id: "ghidra-snes",
          root,
          ghidra_version: "12.1.4",
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/u) as string,
        },
        snes_cartridge: { ...snesTarget.cartridge },
      });
      expect(profile.parameters).not.toHaveProperty("entry_point");
    });

    it("resolves a deterministic profile identity for unchanged inputs", async () => {
      const { provider } = await snesInstallation();
      const first = await provider.resolveAnalysisProfile(snesTarget);
      if (!first.ok) throw first.error;
      const again = await provider.resolveAnalysisProfile(snesTarget);
      if (!again.ok) throw again.error;
      expect(again.value.profile?.digest).toBe(first.value.profile?.digest);
    });

    it("binds the profile identity to installed extension content", async () => {
      const { provider, root } = await snesInstallation();
      const before = await provider.resolveAnalysisProfile(snesTarget);
      if (!before.ok) throw before.error;
      await writeFile(
        join(root, "lib/ghidra-snes.jar"),
        "changed loader artifact",
      );
      const changed = await provider.resolveAnalysisProfile(snesTarget);
      if (!changed.ok) throw changed.error;
      expect(changed.value.profile?.digest).not.toBe(
        before.value.profile?.digest,
      );
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES admission fail-closed boundaries",
  () => {
    it("refuses admission when the extension is missing", async () => {
      const { provider, root } = await snesInstallation();
      await rm(root, { recursive: true });
      const resolved = await provider.resolveAnalysisProfile(snesTarget);
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Missing extension was accepted");
      expect(resolved.error.message).toContain("SNES_EXTENSION_UNAVAILABLE");
    });

    it("refuses an incompatible extension version stamp", async () => {
      const { provider } = await snesInstallation({
        properties: SNES_CONTENTS["extension.properties"]!.replace(
          "version=12.1.4",
          "version=12.0.4",
        ),
      });
      const resolved = await provider.resolveAnalysisProfile(snesTarget);
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Mismatched extension was accepted");
      expect(resolved.error.message).toContain(
        "does not match the selected Ghidra",
      );
    });

    it("refuses an incomplete extension installation", async () => {
      const { provider } = await snesInstallation({
        omit: ["data/languages/65816.sla"],
      });
      const resolved = await provider.resolveAnalysisProfile(snesTarget);
      expect(resolved.ok).toBe(false);
    });

    it("refuses a caller language override for the pinned SNES lane", async () => {
      const { provider } = await snesInstallation({
        env: { REA_GHIDRA_LANGUAGE_ID: "6502:LE:16:default" },
      });
      const resolved = await provider.resolveAnalysisProfile(snesTarget);
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Language override was accepted");
      expect(resolved.error.message).toContain("REA_GHIDRA_LANGUAGE_ID");
    });

    it("refuses profile resolution without a selected Ghidra installation", async () => {
      const resolved = await resolveGhidraAnalysisProfile(
        snesTarget,
        { id: "ghidra", name: "Ghidra", version: "12.1.4" },
        {
          status: "unavailable",
          installDir: null,
          analyzeHeadlessPath: null,
          applicationPropertiesPath: null,
          nativeDecompilerPath: null,
          javaCommand: "java",
          javaHome: null,
          javaVersion: null,
          providerVersion: null,
          platform: "linux",
          architecture: "x64",
          checks: [],
          rejection: { code: "runtime_missing", reason: "absent" },
        },
      );
      expect(resolved.ok).toBe(false);
    });

    it("refuses the execution lane for declared mappings outside lorom/hirom", async () => {
      const { provider } = await snesInstallation();
      const resolved = await provider.resolveAnalysisProfile(
        unsupportedMapperTarget,
      );
      if (!resolved.ok) throw resolved.error;
      const client = provider.createClient(
        unsupportedMapperTarget,
        resolved.value.profile ?? undefined,
      );
      const executed = await client.execute("read_bytes", {
        address: "0x808000",
        length: 1,
      });
      expect(executed.ok).toBe(false);
      if (executed.ok) throw new Error("Unsupported mapper was executed");
      expect(String(executed.error.diagnostics?.reason)).toContain("sa-1");
    });

    it("moves the lorom execution lane past the SNES admission gate", async () => {
      const { provider } = await snesInstallation();
      const resolved = await provider.resolveAnalysisProfile(snesTarget);
      if (!resolved.ok) throw resolved.error;
      const client = provider.createClient(
        snesTarget,
        resolved.value.profile ?? undefined,
      );
      const executed = await client.execute("read_bytes", {
        address: "0x808000",
        length: 1,
      });
      expect(executed.ok).toBe(false);
      if (executed.ok) throw new Error("SNES execution ran without Ghidra");
      // The refusal must now come from the unavailable fake installation,
      // not from a blanket SNES admission gate.
      expect(JSON.stringify(executed.error.diagnostics ?? {})).not.toContain(
        "not admitted yet",
      );
    });

    it("refuses cross-profile snapshot reuse between SNES and raw-binary lanes", async () => {
      const { provider } = await snesInstallation();
      const snes = await provider.resolveAnalysisProfile(snesTarget);
      if (!snes.ok) throw snes.error;
      const raw = await provider.resolveAnalysisProfile(rawTarget);
      if (!raw.ok) throw raw.error;
      const snesProfile = snes.value.profile;
      const rawProfile = raw.value.profile;
      if (snesProfile === null || rawProfile === null)
        throw new Error("Missing profiles");
      expect(
        snapshotMatchesProfile(snapshotBinding(rawProfile), snesProfile),
      ).toBe(false);
      expect(
        snapshotMatchesProfile(snapshotBinding(snesProfile), snesProfile),
      ).toBe(true);
    });

    it("keeps other providers from admitting snes-rom targets", async () => {
      const hopperConfig = parseConfig({
        HOPPER_LAUNCHER_PATH: process.execPath,
      });
      if (!hopperConfig.ok) throw hopperConfig.error;
      expect(
        new HopperProvider(
          hopperConfig.value,
          silentLogger,
          {},
          "linux",
        ).inspectTargetSupport(snesTarget),
      ).toMatchObject({
        status: "unsupported",
        code: "target_format_unsupported",
      });
      const idaDirectory = await createTestTempDirectory("rea-snes-ida-");
      const idaConfigPath = join(idaDirectory, "ida.json");
      await writeFile(idaConfigPath, JSON.stringify({ command: "fixture" }));
      const idaConfig = parseConfig({ REA_IDA_MCP_CONFIG: idaConfigPath });
      if (!idaConfig.ok) throw idaConfig.error;
      expect(
        new IdaProvider(idaConfig.value, {}, () => {
          throw new Error("IDA producer must not start for snes-rom");
        }).inspectTargetSupport(snesTarget),
      ).toMatchObject({
        status: "unsupported",
        code: "target_format_unsupported",
      });
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES admission keeps the raw-binary lane unchanged",
  () => {
    it("still resolves raw-binary profiles with their own language", async () => {
      const { provider } = await snesInstallation();
      const resolved = await provider.resolveAnalysisProfile(rawTarget);
      if (!resolved.ok) throw resolved.error;
      expect(resolved.value.profile?.parameters).toMatchObject({
        target_format: "raw-binary",
        architecture: "6502",
        language_id: "6502:LE:16:default",
        loader: "BinaryLoader",
        entry_point: "0x8000",
      });
    });
  },
);
