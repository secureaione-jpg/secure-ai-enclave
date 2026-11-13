import { sealChunk } from "../../lib/sealedEnvelope.js";

/**
 * The reply, sealed on its way out.
 *
 * This is the last step of the path the file header of server.ts calls "the
 * next piece": the enclave redacts, calls the provider, puts the real names
 * back with restoreStream, and then — here — encrypts each piece to the session
 * key the client wrapped in its request. The Worker relays frames it cannot
 * read.
 *
 * The restored text exists in this process, briefly, and that is the point:
 * this is the only place between the two ends where it does. It never reaches
 * the parent EC2 instance, the tunnel, or the Worker.
 *
 * ── Ending the stream honestly ──
 *
 * A sealed stream needs a piece that says it is the last one, because a reader
 * cannot tell a finished answer from a relay that stopped — both look like
 * bytes ceasing to arrive. So the ending is only emitted when the source
 * actually completed. If the provider connection breaks, or the enclave is
 * torn down, no final piece is written and the reader's finish() throws rather
 * than presenting half an answer as whole.
 *
 * Which means: never emit the final piece in a `finally`. The temptation is
 * strong — it looks like tidy resource handling — and it converts every
 * truncation into a clean, wrong ending.
 */
export function sealStream(
  plain: ReadableStream<Uint8Array>,
  session: CryptoKey,
): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let index = 0;

  /** One SSE frame carrying one sealed piece. */
  const frame = async (text: string, final: boolean): Promise<Uint8Array> => {
    const sealed = await sealChunk(session, index, text, final);
    index += 1;
    return encoder.encode(`data: ${JSON.stringify(sealed)}\n\n`);
  };

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = plain.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          const text = decoder.decode(value, { stream: true });
          // A decode can legitimately produce nothing — a multi-byte character
          // split across two reads. Sealing an empty piece would spend a frame
          // to say nothing, and would make the piece count depend on where the
          // network happened to break the bytes.
          if (text) controller.enqueue(await frame(text, false));
        }

        // Anything the decoder was holding, then the ending. Reached only when
        // the source completed on its own.
        const rest = decoder.decode();
        if (rest) controller.enqueue(await frame(rest, false));
        controller.enqueue(await frame("", true));
        controller.close();
      } catch (err) {
        /* No final piece. The client's reader will refuse the stream, which is
           the correct outcome: it received part of an answer and must not
           display it as the whole one. The error itself is not forwarded — it
           was raised while handling text this service exists to keep, and an
           error string is the usual way one escapes into a log. */
        console.error("[enclave] sealed stream failed:", err instanceof Error ? err.name : "unknown");
        controller.error(new Error("stream_failed"));
      } finally {
        reader.releaseLock();
      }
    },
  });
}

/**
 * Read frames written by sealStream back into sealed pieces.
 *
 * Here rather than in the client so both ends of the framing are written and
 * tested together; the clients each need their own copy in their own language,
 * and this is the reference for what they must agree with.
 */
export function parseSealedFrames(text: string): unknown[] {
  const out: unknown[] = [];
  for (const block of text.split("\n\n")) {
    const line = block.trim();
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload) continue;
    out.push(JSON.parse(payload));
  }
  return out;
}
