import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { fetchOwnModel, modelList } from "./modelFetch";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const FILES: Record<string, string> = { "config.json": '{"a":1}', "onnx/model_quantized.onnx": "weights" };

let server: Server | null = null;
afterEach(() => { server?.close(); server = null; });

/** A parent's model responder serving `files`, on a free port. */
async function parent(files: Record<string, string>): Promise<number> {
  server = createServer((req, res) => {
    const body = files[(req.url ?? "/").slice(1)];
    if (body === undefined) { res.writeHead(404).end(); return; }
    res.writeHead(200, { "content-length": Buffer.byteLength(body) }).end(body);
  });
  await new Promise<void>((ok) => server!.listen(0, "127.0.0.1", ok));
  return (server!.address() as { port: number }).port;
}

function list(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "sai-model-"));
  const path = join(dir, "names-model.sha256");
  writeFileSync(path, "# comment\n" + Object.entries(files).map(([p, b]) => `${sha(b)}  ${p}`).join("\n") + "\n");
  return path;
}

describe("the name model fetched at boot", () => {
  it("reads the hash list, skipping comments, refusing paths out of the folder", () => {
    expect(modelList(`# x\n${"a".repeat(64)}  config.json\n\n`)).toEqual([{ sha256: "a".repeat(64), path: "config.json" }]);
    expect(() => modelList(`${"a".repeat(64)}  ../etc/passwd`)).toThrow(/outside/);
  });

  it("writes every listed file when each matches its hash", async () => {
    const port = await parent(FILES);
    const dest = mkdtempSync(join(tmpdir(), "sai-dest-"));
    expect(await fetchOwnModel(list(FILES), dest, port, [0])).toBe(2);
    expect(readFileSync(join(dest, "onnx/model_quantized.onnx"), "utf8")).toBe("weights");
  });

  it("refuses a file the parent changed, and leaves nothing behind", async () => {
    const port = await parent({ ...FILES, "onnx/model_quantized.onnx": "other weights" });
    const dest = mkdtempSync(join(tmpdir(), "sai-dest-"));
    await expect(fetchOwnModel(list(FILES), dest, port, [0])).rejects.toThrow(/not the one/);
    expect(existsSync(join(dest, "config.json"))).toBe(false);
  });

  it("fetches nothing for an image built for the Xenova taggers", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sai-model-"));
    writeFileSync(join(dir, "l"), "# no model\n");
    expect(await fetchOwnModel(join(dir, "l"), join(dir, "d"), 1, [0])).toBe(0);
  });
});
