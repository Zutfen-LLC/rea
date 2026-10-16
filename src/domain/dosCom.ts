import { z } from "zod";
import { err, ok, type Result } from "./result.js";

/**
 * Caller-selected executable interpretation for formats without identifying
 * file magic: headerless blobs (dos-com, raw-binary) and SNES cartridges,
 * whose internal header is only found through explicit selection.
 */
export const executableFormatHintSchema = z.enum([
  "dos-com",
  "raw-binary",
  "snes-rom",
]);
/** Explicitly selected executable interpretation; see {@link executableFormatHintSchema}. */
export type ExecutableFormatHint = z.infer<typeof executableFormatHintSchema>;

/** Validate the single 64 KiB COM segment, excluding its 256-byte PSP prefix. */
export const validateDosComLength = (length: number): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1 && length <= 0xff00
    ? ok(null)
    : err(
        "DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)",
      );
