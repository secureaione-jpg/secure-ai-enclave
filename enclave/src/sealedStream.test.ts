import { describe, it, expect, vi } from "vitest";

import { sealStream, parseSealedFrames } from "./sealedStream";
import { newSessionKey, SealedStreamReader, type SealedChunk } from "../../lib/sealedEnvelope";

/**
 * The reply leaving the enclave.
 *
 * By the time text reaches sealStream it has been redacted, sent to the
 * provider, and had the real names put back — so this is the one point on the
 * path where the finished answer exists in the clear, and the last chance to
 * get its ending right.
 *
 * The ending is what these tests are mostly about. A reader cannot distinguish
 * a finished answer from a relay that stopped: both are bytes that cease to
 * arrive. The only difference is a piece that says it is the last, and it must
 * be written when the source completed and never otherwise. Emitting it in a
 * `finally` would look like careful cleanup and would turn every truncation
 * into a clean, wrong ending.
 */

/** A source that yields the given pieces, then completes. */
function source(pieces: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const p of pieces) controller.enqueue(encoder.encode(p));
      controller.close();
    },
  });
}

/** A source that yields some pieces and then fails, as a dropped provider
 *  connection does. */
function failingSource(pieces: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const p of pieces) controller.enqueue(encoder.encode(p));
      controller.error(new Error("connection reset"));
    },
  });
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let out = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}

describe("sealing a reply", () => {
  it("the client reads back exactly what the enclave restored", async () => {
    const session = await newSessionKey();
    const text = await collect(sealStream(source(["Good ", "morning, ", "Herbert."]), session));

    const reader = new SealedStreamReader(session);
    let out = "";
    for (const chunk of parseSealedFrames(text) as SealedChunk[]) out += await reader.open(chunk);
    reader.finish();

    expect(out).toBe("Good morning, Herbert.");
  });

  it("the frames carry none of the reply in the clear", async () => {
    /* What the Worker and the parent EC2 instance see. If the answer is
       readable here, everything upstream of this was decoration. */
    const session = await newSessionKey();
    const text = await collect(sealStream(source(["Your address is 14 Elm Row"]), session));

    expect(text).not.toContain("Elm");
    expect(text).not.toContain("address");
    expect(text).toContain("data: ");
  });

  it("ends with a piece that says it is the end", async () => {
    const session = await newSessionKey();
    const frames = parseSealedFrames(
      await collect(sealStream(source(["one", "two"]), session)),
    ) as SealedChunk[];

    expect(frames.at(-1)?.final).toBe(true);
    expect(frames.filter((f) => f.final).length).toBe(1);
    expect(frames.map((f) => f.i)).toEqual(frames.map((_, i) => i));
  });

  it("writes no ending when the provider connection breaks", async () => {
    /* The case the whole design exists for. Two pieces of a real answer
       arrived and the rest never will; the reader must refuse rather than
       present a sentence that stops mid-thought as the complete reply. */
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    const session = await newSessionKey();

    const stream = sealStream(failingSource(["The balance is ", "£4"]), session);
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let text = "";
    let failed = false;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
      }
    } catch {
      failed = true;
    }
    warn.mockRestore();

    expect(failed).toBe(true);
    const frames = parseSealedFrames(text) as SealedChunk[];
    expect(frames.some((f) => f.final)).toBe(false);

    // And the client-side reader agrees: what arrived is not an answer.
    const client = new SealedStreamReader(session);
    for (const f of frames) await client.open(f);
    expect(() => client.finish()).toThrow(/without a final piece/);
  });

  it("says nothing about why it failed", async () => {
    /* The failure happened while handling the reply, so the error is the one
       place a fragment of it could escape. "connection reset" must not travel;
       neither must anything else specific. */
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    const session = await newSessionKey();
    const stream = sealStream(failingSource(["secret"]), session);
    const reader = stream.getReader();

    let message = "";
    try {
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
    } catch (err) {
      message = (err as Error).message;
    }
    warn.mockRestore();

    expect(message).toBe("stream_failed");
  });

  it("an empty reply is still a complete one", async () => {
    /* A model can answer with nothing. Without a final piece here the client
       would treat a legitimate empty answer as a truncated stream and show an
       error for a request that worked. */
    const session = await newSessionKey();
    const frames = parseSealedFrames(await collect(sealStream(source([]), session))) as SealedChunk[];

    expect(frames.length).toBe(1);
    expect(frames[0].final).toBe(true);

    const client = new SealedStreamReader(session);
    expect(await client.open(frames[0])).toBe("");
    expect(() => client.finish()).not.toThrow();
  });

  it("a character split across two reads is not split in the output", async () => {
    /* Bytes arrive where the network divides them, not where characters end.
       Decoding each read on its own turns a pound sign delivered in two halves
       into two replacement characters -- in the reply, permanently, because
       this is the last point the text is readable. */
    const session = await newSessionKey();
    const pound = new TextEncoder().encode("£12.50");
    const split = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(pound.subarray(0, 1)); // first byte of £
        controller.enqueue(pound.subarray(1));
        controller.close();
      },
    });

    const frames = parseSealedFrames(await collect(sealStream(split, session))) as SealedChunk[];
    const client = new SealedStreamReader(session);
    let out = "";
    for (const f of frames) out += await client.open(f);
    client.finish();

    expect(out).toBe("£12.50");
    expect(out).not.toContain("�");
  });

  it("spends no frame on a read that decoded to nothing", async () => {
    /* The other half of the same problem: the first read above produces no
       text at all. Sealing it would make the number of pieces depend on where
       the network happened to break, which is not something a reader should be
       able to observe. */
    const session = await newSessionKey();
    const pound = new TextEncoder().encode("£");
    const split = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(pound.subarray(0, 1));
        controller.enqueue(pound.subarray(1));
        controller.close();
      },
    });

    const frames = parseSealedFrames(await collect(sealStream(split, session))) as SealedChunk[];
    // One piece of text, one ending. Not three.
    expect(frames.length).toBe(2);
  });
});

describe("the frame format", () => {
  it("ignores anything that is not a data line", async () => {
    /* SSE allows comments and other fields; a client that parses by splitting
       on newlines will meet them eventually. */
    const parsed = parseSealedFrames(
      ': keep-alive\n\ndata: {"i":0,"final":true,"c":"x"}\n\nevent: ping\n\n',
    );
    expect(parsed).toEqual([{ i: 0, final: true, c: "x" }]);
  });
});
