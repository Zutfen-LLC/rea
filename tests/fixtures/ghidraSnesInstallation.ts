import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

/**
 * Synthetic ghidra-snes installation files shared by extension-identity and
 * admission/profile tests. Independently authored text exercising filesystem
 * and profile boundaries only; upstream facts (extension.properties declares
 * name=SNES Loader plus the Ghidra compatibility version, and the language is
 * 65816:LE:24:snes built from data/languages/65816.ldefs with 65816.sla,
 * 65816-snes.pspec and 65816.cspec) were verified against
 * joshleaves/ghidra-snes@d33ce5db.
 */
export const snesExtensionContents = (
  ghidraVersion: string,
): Record<string, string> => ({
  "Module.manifest":
    "MODULE NAME: Ghidra-SNES\nMODULE DEPENDENCIES:\n    Ghidra\n",
  "extension.properties": [
    "name=SNES Loader",
    "description=Loader for SNES ROMs with LoROM/HiROM mapping and WRAM blocks.",
    "author=red",
    "createdOn=2026-05-01",
    `version=${ghidraVersion}`,
    "",
  ].join("\n"),
  "data/languages/65816.ldefs": "synthetic language definition",
  "data/languages/65816.sla": "synthetic compiled processor",
  "data/languages/65816-snes.pspec": "synthetic processor specification",
  "data/languages/65816.cspec": "synthetic compiler specification",
  "lib/ghidra-snes.jar": "synthetic loader artifact",
});

/** Write a complete or deliberately incomplete synthetic installation. */
export const writeSnesExtension = async (
  root: string,
  contents: Readonly<Record<string, string>>,
  options?: {
    readonly omit?: readonly string[];
    readonly writeOrder?: readonly string[];
  },
): Promise<void> => {
  const order = options?.writeOrder ?? Object.keys(contents);
  for (const path of order) {
    if (options?.omit?.includes(path)) continue;
    const text = contents[path];
    if (text === undefined)
      throw new Error(`Unknown fixture component: ${path}`);
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
};
