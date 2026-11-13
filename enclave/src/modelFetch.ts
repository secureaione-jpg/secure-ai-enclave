/**
 * Our own name model, fetched from the parent at boot and checked by hash
 * (2026-11-13).
 *
 * ── Why it is not in the image any more ──
 *
 * The image is rebuilt by anyone who wants to check PCR0: same source, same
 * build, same hash (README, "Verifying the enclave"). That needs every byte of
 * the image to be public, and the model's weights are not — so a model inside
 * the image made the whole image impossible to rebuild from outside.
 *
 * What the image carries instead is the model's fingerprint:
 * names-model.sha256, committed and public, copied to /app. At boot each
 * listed file is asked for from the parent, over vsock like the config, and
 * written to the enclave's own memory only if its SHA-256 is the one listed.
 * A parent that sends anything else — another model, a changed file, nothing
 * at all — gets an enclave with no name stage, which refuses to start
 * (server.ts). So the weights stay private, and which weights run is still
 * fixed by PCR0: change the model and the list changes, and with it the hash.
 *
 * The parent sees the weights, as it did when they were in the image it
 * built. It never sees a message.
 */
import { createHash } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { get } from "node:http";
import { dirname, join, normalize } from "node:path";

/** The loopback port enclave-init.sh forwards to the parent's model
 *  responder. Matched in scripts/enclave-init.sh and scripts/parent-up.sh;
 *  change one, change all three, as with the config port. */
export const MODEL_PORT = 8448;

export type ModelFile = { sha256: string; path: string };

/** The files and hashes in names-model.sha256: `<hash>  <path>` per line,
 *  comments and blank lines skipped. A path that climbs out of the model
 *  folder is refused rather than followed. */
export function modelList(text: string): ModelFile[] {
  const out: ModelFile[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(line);
    if (!m) throw new Error(`names-model.sha256: unreadable line "${line}"`);
    const path = normalize(m[2]);
    if (path.startsWith("..") || path.startsWith("/")) throw new Error(`names-model.sha256: path outside the model: ${m[2]}`);
    out.push({ sha256: m[1], path });
  }
  return out;
}

/** One file from the parent into `dest`, hashed on the way. Throws, leaving
 *  nothing behind, unless the bytes hash to `sha256`. */
function fetchFile(port: number, file: ModelFile, dest: string): Promise<void> {
  return new Promise((ok, fail) => {
    const target = join(dest, file.path);
    mkdirSync(dirname(target), { recursive: true });
    const req = get({ host: "127.0.0.1", port, path: "/" + file.path, timeout: 60_000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return fail(new Error(`${file.path}: the parent answered ${res.statusCode}`));
      }
      const hash = createHash("sha256");
      const out = createWriteStream(target);
      res.on("data", (chunk: Buffer) => hash.update(chunk));
      res.pipe(out);
      out.on("finish", () => {
        const got = hash.digest("hex");
        if (got === file.sha256) return ok();
        rmSync(target, { force: true });
        fail(new Error(`${file.path}: hash ${got} is not the one in names-model.sha256`));
      });
      res.on("error", fail);
      out.on("error", fail);
    });
    req.on("timeout", () => req.destroy(new Error(`${file.path}: no answer from the parent`)));
    req.on("error", fail);
  });
}

/**
 * Fetch every file in `listFile` into `dest`. Returns how many were fetched:
 * 0 when the list names none (an image built for the two Xenova taggers).
 * Throws on the first file that does not arrive or does not match, after
 * removing what had arrived, so a half-fetched model is never loaded.
 *
 * Retried like the config: the parent's responder and the enclave come up in
 * whatever order they manage.
 */
export async function fetchOwnModel(listFile: string, dest: string, port = MODEL_PORT, waits = [0, 1000, 2000, 4000]): Promise<number> {
  if (!existsSync(listFile)) return 0;
  const files = modelList(readFileSync(listFile, "utf8"));
  if (!files.length) return 0;
  let last: unknown = null;
  for (const wait of waits) {
    if (wait) await new Promise((r) => setTimeout(r, wait));
    try {
      for (const f of files) await fetchFile(port, f, dest);
      return files.length;
    } catch (err) {
      last = err;
      rmSync(dest, { recursive: true, force: true });
    }
  }
  throw last instanceof Error ? last : new Error(String(last));
}
