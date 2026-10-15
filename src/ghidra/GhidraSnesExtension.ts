import { createHash } from "node:crypto";
import { lstat, opendir, realpath, stat } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import {
  openRegularFile,
  sameRegularFileState,
} from "../filesystem/RegularFile.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import { parseGhidraJavaProperties } from "./GhidraJavaProperties.js";

/**
 * Identity of a caller-installed ghidra-snes extension, following the
 * installed Allegrex extension precedent. This is content identity of the
 * inspected installation only; it does not establish that SnesRomLoader runs,
 * that REA admits SNES targets, or that the extension interoperates with any
 * particular Ghidra build beyond the caller-selected compatibility version.
 */
export const ghidraSnesExtensionSchema = z.strictObject({
  /** Stable REA identity; deliberately not the upstream `name` property. */
  id: z.literal("ghidra-snes"),
  /** Canonical absolute installed root; symlinks are refused. */
  root: z.string().refine(isAbsolute),
  /** Ghidra compatibility version the metadata was bound to. */
  ghidra_version: z.string().min(1),
  /** SHA-256 over the complete inspected installation. */
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type GhidraSnesExtension = z.infer<typeof ghidraSnesExtensionSchema>;

// Resource bounds for scanning a caller-installed extension, not target limits.
const MAX_ENTRIES = 1024;
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_DEPTH = 16;
const MAX_PROPERTIES_BYTES = 65536;
// Verified against the installed joshleaves/ghidra-snes@d33ce5db extension
// built for Ghidra 12.0.4: the source tree ships 65816.ldefs/.slaspec and
// 65816-snes.pspec/.cspec, while a usable installation additionally carries
// the compiled 65816.sla and lib/ghidra-snes.jar, whose inspected archive
// contains ghidra_snes/loader/SnesRomLoader.class. Require the installed path;
// artifact presence and content identity do not establish loader execution.
const REQUIRED = [
  "Module.manifest",
  "extension.properties",
  "data/languages/65816.ldefs",
  "data/languages/65816.sla",
  "data/languages/65816-snes.pspec",
  "data/languages/65816.cspec",
  "lib/ghidra-snes.jar",
] as const;
const UPSTREAM_NAME = "SNES Loader";

/** Read-only fingerprint of all installed files; no home scanning or installation. */
export const inspectGhidraSnesExtension = async (
  root: string,
  ghidraVersion: string,
  signal?: AbortSignal,
): Promise<GhidraSnesExtension> => {
  signal?.throwIfAborted();
  if (!isAbsolute(root))
    throw new Error(
      "The installed ghidra-snes directory must be a canonical non-symlink path.",
    );
  if (!(await stat(root).catch(() => null)))
    throw new Error(
      `No installed ghidra-snes extension at ${root}; install it under the selected Ghidra distribution. REA does not install it.`,
    );
  if ((await realpath(root)) !== root)
    throw new Error(
      "The installed ghidra-snes directory must be a canonical non-symlink path.",
    );
  const files: string[] = [];
  let entries = 1; // The root itself consumes one inventory entry.
  const visit = async (relative: string, depth: number): Promise<void> => {
    signal?.throwIfAborted();
    if (depth > MAX_DEPTH)
      throw new Error(
        "ghidra-snes extension directory nesting exceeds the inspection limit.",
      );
    const path = join(root, relative);
    const metadata = await lstat(path);
    if (metadata.isDirectory()) {
      const children: string[] = [];
      for await (const child of await opendir(path)) {
        signal?.throwIfAborted();
        if (++entries > MAX_ENTRIES)
          throw new Error(
            "ghidra-snes extension inventory exceeds the inspection limit.",
          );
        children.push(child.name);
      }
      children.sort();
      for (const child of children)
        await visit(
          relative === "" ? child : `${relative}/${child}`,
          depth + 1,
        );
    } else if (metadata.isFile()) {
      files.push(relative);
    } else
      throw new Error(
        `ghidra-snes extension entries must be regular files or directories: ${relative}`,
      );
  };
  await visit("", 0);
  for (const required of REQUIRED)
    if (!files.includes(required))
      throw new Error(`Missing installed ghidra-snes component: ${required}`);
  const hash = createHash("sha256");
  let bytesRead = 0;
  let properties = Buffer.alloc(0);
  for (const relative of files) {
    signal?.throwIfAborted();
    const path = join(root, relative);
    const handle = await openRegularFile(path, { symlinks: "reject", signal });
    try {
      const before = await handle.stat();
      if (
        !Number.isSafeInteger(before.size) ||
        before.size > MAX_BYTES - bytesRead
      )
        throw new Error(
          "ghidra-snes extension bytes exceed the inspection limit.",
        );
      if (
        relative === "extension.properties" &&
        before.size > MAX_PROPERTIES_BYTES
      )
        throw new Error(
          "ghidra-snes extension properties exceed the inspection limit.",
        );
      hash.update(JSON.stringify([relative, before.size]));
      const buffer = Buffer.alloc(Math.min(65536, before.size + 1));
      let offset = 0;
      const chunks: Buffer[] = [];
      while (offset < before.size) {
        signal?.throwIfAborted();
        const read = await handle.read(
          buffer,
          0,
          Math.min(buffer.length, before.size - offset),
          offset,
        );
        if (read.bytesRead === 0)
          throw new Error(`Truncated ghidra-snes component: ${relative}`);
        const chunk = buffer.subarray(0, read.bytesRead);
        hash.update(chunk);
        if (relative === "extension.properties")
          chunks.push(Buffer.from(chunk));
        offset += read.bytesRead;
      }
      if (
        !sameRegularFileState(before, await handle.stat()) ||
        !sameRegularFileState(before, await lstat(path))
      )
        throw new Error(
          `ghidra-snes component changed during inspection: ${relative}`,
        );
      bytesRead += before.size;
      if (relative === "extension.properties")
        properties = Buffer.concat(chunks);
    } finally {
      await handle.close();
    }
  }
  // The extension's version property declares its compatible Ghidra version,
  // not the extension release; content identity supplies the latter.
  const parsedProperties = parseGhidraJavaProperties(
    properties.toString("latin1"),
  );
  if (!parsedProperties.ok)
    throw new Error(
      `Invalid ghidra-snes extension properties: ${parsedProperties.error}`,
    );
  const property = (name: string): string | undefined =>
    parsedProperties.value.get(name);
  if (
    property("name") !== UPSTREAM_NAME ||
    property("version") !== ghidraVersion
  )
    throw new Error(
      `ghidra-snes extension metadata does not match the selected Ghidra ${ghidraVersion}; install or rebuild a compatible extension.`,
    );
  signal?.throwIfAborted();
  return {
    id: "ghidra-snes",
    root,
    ghidra_version: ghidraVersion,
    sha256: hash.digest("hex"),
  };
};

/**
 * Resolve the ghidra-snes prerequisite from one caller-selected installation.
 * Independent of target admission and provider launch: it never scans user
 * home directories or the system for extensions, and it executes nothing.
 */
export const resolveGhidraSnesExtension = async (
  installation: GhidraInstallationInspection,
  signal?: AbortSignal,
): Promise<Result<GhidraSnesExtension, AnalysisError>> => {
  if (signal?.aborted)
    return err(new AnalysisCancelledError("resolve_analysis_profile"));
  try {
    if (installation.status !== "available")
      throw new Error(
        "Inspecting the ghidra-snes extension requires a selected, available Ghidra installation.",
      );
    const root = join(
      await realpath(installation.installDir),
      "Ghidra",
      "Extensions",
      "ghidra-snes",
    );
    return ok(
      await inspectGhidraSnesExtension(
        root,
        installation.providerVersion,
        signal,
      ),
    );
  } catch (cause: unknown) {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("resolve_analysis_profile"));
    const reason = `SNES_EXTENSION_UNAVAILABLE: ${cause instanceof Error ? cause.message : String(cause)} Use a compatible caller-installed ghidra-snes under GHIDRA_INSTALL_DIR/Ghidra/Extensions; REA does not install it.`;
    return err(
      new AnalysisCapabilityUnavailableError(
        "ghidra",
        "resolve_analysis_profile",
        reason,
        { cause, userMessage: reason },
      ),
    );
  }
};
