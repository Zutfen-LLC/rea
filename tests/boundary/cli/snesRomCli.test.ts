import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { snesCartridgeImage } from "../../fixtures/snesCartridge.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "rejects mixed raw-binary flags with target-format snes-rom",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-snes-cli-mixed-");
    const path = join(root, "game.sfc");
    await writeFile(path, snesCartridgeImage());
    const result = await cli.run({
      arguments: [
        "inspect",
        path,
        "--target-format",
        "snes-rom",
        "--architecture",
        "6502",
        "--entry-point",
        "0x8000",
        "--json",
      ],
      environment: {
        HOME: root,
        XDG_CONFIG_HOME: root,
        XDG_CACHE_HOME: root,
      },
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({
      code: "invalid_request",
      details: {
        reason: expect.stringContaining("apply only with format=raw-binary"),
      },
    });
  },
);

cliTest(
  "rejects a non-cartridge file before provider startup",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-snes-cli-invalid-");
    const path = join(root, "not-a-cartridge.sfc");
    // A valid LoROM image with its mapping-mode byte corrupted to an
    // unrecognized nibble mirrors the qualified negative control.
    const bytes = snesCartridgeImage({ mapperByte: 0x2f });
    await writeFile(path, bytes);
    const result = await cli.run({
      arguments: [
        "inspect",
        path,
        "--target-format",
        "snes-rom",
        "--provider",
        "ghidra",
        "--json",
      ],
      environment: {
        HOME: root,
        XDG_CONFIG_HOME: root,
        XDG_CACHE_HOME: root,
      },
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({
      code: "target_unavailable",
      details: {
        reason: expect.stringContaining("No unambiguous SNES internal header"),
      },
    });
  },
);

cliTest(
  "never reports successful analysis for a valid cartridge without Ghidra",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-snes-cli-open-");
    const path = join(root, "game.sfc");
    await writeFile(path, snesCartridgeImage());
    const result = await cli.run({
      arguments: [
        "inspect",
        path,
        "--target-format",
        "snes-rom",
        "--provider",
        "ghidra",
        "--json",
      ],
      environment: {
        HOME: root,
        XDG_CONFIG_HOME: root,
        XDG_CACHE_HOME: root,
        GHIDRA_INSTALL_DIR: "/nonexistent/ghidra",
      },
    });
    // Admission succeeds, but without an available installation no analysis
    // can run and nothing may report success for the not-yet-admitted lane.
    expect(result.exitCode).not.toBe(0);
    expect(JSON.stringify(result.json ?? {})).not.toContain('"ok": true');
  },
);
