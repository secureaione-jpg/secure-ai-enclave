import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  openSealedChat,
  runSealedChat,
  assemble,
  ChatError,
  type ChatRequest,
} from "./sealedChat";
import { parseSealedFrames } from "./sealedStream";
import { sealRequest, SealedStreamReader, type SealedChunk } from "../../lib/sealedEnvelope";

/**
 * The sealed path, end to end.
 *
 * What this is for: today the Worker holds the provider key, so it makes the
 * call, so it must have the message in the clear to put in the call. Moving the
 * key into the enclave breaks that chain. These tests are about whether the
 * chain is actually broken — not whether the happy path works, but whether
 * anything still leaks when it does.
 *
 * The provider is faked rather than called. What matters is the bytes handed to
 * it and the bytes handed back, and both are inspected directly.
 */

/** The enclave's boot keypair, as attest.ts holds it: only the unwrap. */
async function enclaveKeys() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const unwrap = async (ct: Uint8Array) => {
    const b = new ArrayBuffer(ct.byteLength);
    new Uint8Array(b).set(ct);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, pair.privateKey, b));
  };
  return { spki, unwrap };
}

const request = (over: Partial<ChatRequest> = {}): ChatRequest => ({
  provider: "anthropic",
  path: "/v1/messages",
  body: { model: "claude-opus-5", max_tokens: 1024, stream: true },
  messages: [{ role: "user", content: "my name is Herbert Perryman" }],
  system: "You are helpful.",
  ...over,
});

/** What the provider was sent, captured. */
let sent: { path: string; headers: Record<string, string>; body: string } | null = null;

/** Anthropic-shaped SSE, since that is what restoreStream will be parsing. */
function providerSSE(pieces: string[]): string {
  const frames = pieces.map(
    (t) =>
      `event: content_block_delta\ndata: ${JSON.stringify({
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: t },
      })}\n\n`,
  );
  return frames.join("");
}

function mockProvider(sse: string, status = 200) {
  return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    sent = {
      path: new URL(String(url)).pathname,
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: String(init?.body ?? ""),
    };
    const encoder = new TextEncoder();
    return new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(encoder.encode(sse));
          c.close();
        },
      }),
      { status, headers: { "content-type": "text/event-stream" } },
    );
  });
}

const KEYS = { anthropicKey: "sk-ant-test", openaiKey: "sk-oai-test" };

let realFetch: typeof globalThis.fetch;
beforeEach(() => {
  sent = null;
  realFetch = globalThis.fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("opening a sealed request", () => {
  it("yields the request and the key the answer must be sealed under", async () => {
    const { spki, unwrap } = await enclaveKeys();
    const { envelope, session } = await sealRequest(spki, JSON.stringify(request()));

    const opened = await openSealedChat(envelope, unwrap);
    expect(opened.request.provider).toBe("anthropic");
    expect(opened.request.messages[0].content).toBe("my name is Herbert Perryman");

    /* The same key both ends, which is what lets the client read the reply.
       Compared by using it rather than by exporting it: openRequest imports
       the session non-extractable, which is right -- a key that cannot be
       exported cannot be logged, returned in an error, or written to disk by
       some later convenience. The first version of this test exported both
       and failed, which is the check working. */
    const probe = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(12) },
      opened.session,
      new TextEncoder().encode("same key?"),
    );
    const mine = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(12) },
      session,
      probe,
    );
    expect(new TextDecoder().decode(mine)).toBe("same key?");
  });

  it("says only that it cannot open it", async () => {
    /* The distinctions available here — a wrapped key that will not unwrap, a
       body whose tag fails — are the ones somebody probing this endpoint would
       most like reported back. */
    const real = await enclaveKeys();
    const impostor = await enclaveKeys();
    const { envelope } = await sealRequest(impostor.spki, JSON.stringify(request()));

    await expect(openSealedChat(envelope, real.unwrap)).rejects.toThrow("cannot_open");
  });

  it("refuses a provider it cannot authenticate to", async () => {
    const { spki, unwrap } = await enclaveKeys();
    const { envelope } = await sealRequest(
      spki,
      JSON.stringify(request({ provider: "gemini" as never })),
    );
    await expect(openSealedChat(envelope, unwrap)).rejects.toThrow("unknown_provider");
  });

  it("refuses a path that could name a host", async () => {
    /* The outbound allowlist already fixes the host, so this is belt and
       braces — but a path beginning // is a path that becomes a host again in
       something downstream, and the check costs one regex. */
    const { spki, unwrap } = await enclaveKeys();
    for (const path of ["//evil.example/v1/messages", "https://evil.example/x", "v1/messages"]) {
      const { envelope } = await sealRequest(spki, JSON.stringify(request({ path })));
      await expect(openSealedChat(envelope, unwrap)).rejects.toThrow("invalid_path");
    }
  });

  it("refuses the characters that make a request line mean something else", async () => {
    /* This is the list that widening the check for Gemini put at risk, so it
       is written out rather than sampled. A CR or LF ends the request line and
       starts a header; a backslash is a slash to some parsers and not to this
       one, so the path checked would not be the path sent; a # truncates it
       for whoever reads it next; a space splits it. "?x=1?y=2" is here because
       one query string is a query string and two is somebody probing. */
    const { spki, unwrap } = await enclaveKeys();
    for (const path of [
      "/v1/messages\r\nX-Injected: 1",
      "/v1/messages\nX-Injected: 1",
      "/v1\\messages",
      "/v1/messages#fragment",
      "/v1/messages HTTP/1.1",
      "/v1/messages?x=1?y=2",
      "/v1/messages?user@evil.example",
      "/v1/models/a:b?alt=sse&x=/etc",
    ]) {
      const { envelope } = await sealRequest(spki, JSON.stringify(request({ path })));
      await expect(openSealedChat(envelope, unwrap)).rejects.toThrow("invalid_path");
    }
  });

  it("accepts the route Gemini actually uses", async () => {
    /* The reason the check was widened at all. A colon inside a segment and a
       query string are both new, and both are safe only because the leading
       slash is still mandatory — "/v1beta/...:x" cannot be read as a scheme,
       where "https:..." could. */
    const { spki, unwrap } = await enclaveKeys();
    const path = "/v1beta/models/gemini-3.7-flash:streamGenerateContent?alt=sse";
    const { envelope } = await sealRequest(
      spki,
      JSON.stringify(request({ provider: "google", path })),
    );
    const { request: opened } = await openSealedChat(envelope, unwrap);
    expect(opened.path).toBe(path);
  });

  it("refuses a request with no conversation in it", async () => {
    const { spki, unwrap } = await enclaveKeys();
    const { envelope } = await sealRequest(spki, JSON.stringify(request({ messages: [] })));
    await expect(openSealedChat(envelope, unwrap)).rejects.toThrow("no_messages");
  });
});

describe("what the provider is sent", () => {
  it("gets the redacted conversation and the key, never the real names", async () => {
    globalThis.fetch = mockProvider(providerSSE(["Hello ", "Desmond."])) as never;
    const { spki, unwrap } = await enclaveKeys();
    const req = request();
    const { envelope } = await sealRequest(spki, JSON.stringify(req));
    const opened = await openSealedChat(envelope, unwrap);

    await runSealedChat(
      opened.request,
      {
        body: assemble(req.provider, req.body, [{ role: "user", content: "my name is Desmond Halloran" }], "You are helpful."),
        redaction: { "Desmond Halloran": "Herbert Perryman" },
      },
      opened.session,
      KEYS,
    );

    expect(sent).not.toBeNull();
    expect(sent!.body).not.toContain("Herbert");
    expect(sent!.body).toContain("Desmond");
    expect(sent!.headers["x-api-key"]).toBe("sk-ant-test");
    expect(sent!.headers["anthropic-version"]).toBe("2023-06-01");
    expect(sent!.path).toBe("/v1/messages");
  });

  it("keeps the caller's model and parameters untouched", async () => {
    /* The division of labour: the caller decides everything about the model,
       this decides nothing. A body rewritten here is a second provider table
       to drift from the first. */
    globalThis.fetch = mockProvider(providerSSE(["ok"])) as never;
    const { spki, unwrap } = await enclaveKeys();
    const req = request({ body: { model: "claude-opus-5", max_tokens: 77, temperature: 0.3, stream: true } });
    const { envelope } = await sealRequest(spki, JSON.stringify(req));
    const opened = await openSealedChat(envelope, unwrap);

    await runSealedChat(
      opened.request,
      { body: assemble(req.provider, req.body, req.messages, "sys"), redaction: {} },
      opened.session,
      KEYS,
    );

    const body = JSON.parse(sent!.body);
    expect(body.model).toBe("claude-opus-5");
    expect(body.max_tokens).toBe(77);
    expect(body.temperature).toBe(0.3);
  });

  it("refuses rather than falling back when there is no key", async () => {
    /* The failure that would undo the whole thing: a sealed request that
       quietly becomes an unsealed one because a key was missing. */
    globalThis.fetch = mockProvider(providerSSE(["x"])) as never;
    const { spki, unwrap } = await enclaveKeys();
    const { envelope } = await sealRequest(spki, JSON.stringify(request()));
    const opened = await openSealedChat(envelope, unwrap);

    await expect(
      runSealedChat(opened.request, { body: {}, redaction: {} }, opened.session, {}),
    ).rejects.toThrow("provider_key_missing");
    expect(sent).toBeNull();
  });

  it("does not forward the provider's own error text", async () => {
    /* Provider errors routinely quote the request back. The redacted copy
       still carries the conversation's shape, and a 400 body is a place it
       would travel to the caller. */
    globalThis.fetch = mockProvider("", 400) as never;
    const { spki, unwrap } = await enclaveKeys();
    const { envelope } = await sealRequest(spki, JSON.stringify(request()));
    const opened = await openSealedChat(envelope, unwrap);

    await expect(
      runSealedChat(opened.request, { body: {}, redaction: {} }, opened.session, KEYS),
    ).rejects.toThrow("provider_error");
  });

  it("passes a rate limit through as one", async () => {
    globalThis.fetch = mockProvider("", 429) as never;
    const { spki, unwrap } = await enclaveKeys();
    const { envelope } = await sealRequest(spki, JSON.stringify(request()));
    const opened = await openSealedChat(envelope, unwrap);

    await runSealedChat(opened.request, { body: {}, redaction: {} }, opened.session, KEYS).catch(
      (err) => expect((err as ChatError).status).toBe(429),
    );
  });
});

describe("what comes back", () => {
  async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
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

  it("the client reads the answer with the real name back in it", async () => {
    /* The round trip. The provider only ever saw "Desmond"; the reader only
       ever sees "Herbert"; and the frames in between carry neither. */
    globalThis.fetch = mockProvider(providerSSE(["Good morning, ", "Desmond", "."])) as never;
    const { spki, unwrap } = await enclaveKeys();
    const req = request();
    const { envelope, session: clientSession } = await sealRequest(spki, JSON.stringify(req));
    const opened = await openSealedChat(envelope, unwrap);

    const stream = await runSealedChat(
      opened.request,
      {
        body: assemble(req.provider, req.body, req.messages, "sys"),
        redaction: { Desmond: "Herbert" },
      },
      opened.session,
      KEYS,
    );

    const wire = await readAll(stream);
    expect(wire).not.toContain("Herbert");
    expect(wire).not.toContain("Desmond");
    expect(wire).not.toContain("morning");

    const reader = new SealedStreamReader(clientSession);
    let text = "";
    for (const chunk of parseSealedFrames(wire) as SealedChunk[]) text += await reader.open(chunk);
    reader.finish();

    /* What the client gets back is the provider's own SSE, with the real
       values put back into it -- not extracted prose. That is deliberate and
       matches what the Worker forwards today, so the clients' existing
       stream parsing is unchanged; the only new step is unsealing first.
       Asserted on the text inside the frames rather than on the framing. */
    expect(text).toContain("Good morning, ");
    expect(text).toContain("Herbert");
    expect(text).not.toContain("Desmond");
    expect(text).toContain("content_block_delta");
  });

  it("puts a name back that arrived split across two frames", async () => {
    /* restoreStream holds back text that could still be the head of a
       stand-in. Worth a test here as well as in redaction.ts, because this is
       the path where getting it wrong is permanent: the sealed pieces are the
       last form the text takes. */
    globalThis.fetch = mockProvider(providerSSE(["Hello Des", "mond, how are you"])) as never;
    const { spki, unwrap } = await enclaveKeys();
    const req = request();
    const { envelope, session: clientSession } = await sealRequest(spki, JSON.stringify(req));
    const opened = await openSealedChat(envelope, unwrap);

    const stream = await runSealedChat(
      opened.request,
      { body: {}, redaction: { Desmond: "Herbert" } },
      opened.session,
      KEYS,
    );

    const reader = new SealedStreamReader(clientSession);
    let text = "";
    for (const chunk of parseSealedFrames(await readAll(stream)) as SealedChunk[]) {
      text += await reader.open(chunk);
    }
    reader.finish();

    expect(text).toContain("Herbert");
    expect(text).not.toContain("Desmond");
    expect(text).not.toContain("Des,");
  });
});

describe("assembling the provider body", () => {
  it("anthropic takes the system prompt in its own field", () => {
    const out = assemble("anthropic", { model: "m" }, [{ role: "user", content: "hi" }], "be brief");
    expect(out.system).toBe("be brief");
    expect((out.messages as unknown[]).length).toBe(1);
  });

  it("openai takes it as the first message", () => {
    const out = assemble("openai", { model: "m" }, [{ role: "user", content: "hi" }], "be brief");
    expect(out.system).toBeUndefined();
    expect(out.messages).toEqual([
      { role: "system", content: "be brief" },
      { role: "user", content: "hi" },
    ]);
  });

  it("google renames everything and takes the system prompt in its own field", () => {
    const out = assemble(
      "google",
      { generationConfig: { maxOutputTokens: 10 } },
      [
        { role: "user", content: "hi" },
        { role: "assistant", content: "hello" },
      ],
      "be brief",
    );
    expect(out.messages).toBeUndefined();
    expect(out.contents).toEqual([
      { role: "user", parts: [{ text: "hi" }] },
      /* "model", not "assistant" — Gemini rejects the OpenAI spelling, and a
         conversation whose second turn is refused is a conversation that only
         breaks once somebody sends a follow-up. */
      { role: "model", parts: [{ text: "hello" }] },
    ]);
    expect(out.systemInstruction).toEqual({ parts: [{ text: "be brief" }] });
    expect(out.generationConfig).toEqual({ maxOutputTokens: 10 });
  });

  it("google carries an attached image as inline data, and drops a remote one", () => {
    /* The drop is the deliberate half. Gemini would fetch a remote URL itself,
       and a fetch made by the provider is outbound traffic this enclave did
       not make and its allowlist never saw. */
    const out = assemble(
      "google",
      {},
      [
        {
          role: "user",
          content: [
            { type: "text", text: "what is this" },
            { type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } },
            { type: "image_url", image_url: { url: "https://evil.example/track.png" } },
          ],
        },
      ],
      "",
    );
    const parts = (out.contents as Array<{ parts: unknown[] }>)[0].parts;
    expect(parts).toEqual([
      { text: "what is this" },
      { inlineData: { mimeType: "image/png", data: "AAAA" } },
      { text: "" },
    ]);
    expect(JSON.stringify(out)).not.toContain("evil.example");
  });

  it("leaves the system prompt out when there is not one", () => {
    /* An empty system field is not the same as no system field: Anthropic
       rejects an empty string, and OpenAI would spend a message on nothing. */
    expect(assemble("anthropic", {}, [{ role: "user", content: "hi" }], "").system).toBeUndefined();
    expect(assemble("openai", {}, [{ role: "user", content: "hi" }], "").messages).toEqual([
      { role: "user", content: "hi" },
    ]);
  });
});

import { capOutput } from "./sealedChat";

describe("capOutput: an answer held to what was paid for", () => {
  it("lowers Anthropic's max_tokens, and sets one when there is none", () => {
    expect(capOutput("anthropic", { model: "m", max_tokens: 64000 }, 4096)).toEqual({ model: "m", max_tokens: 4096 });
    expect(capOutput("anthropic", { model: "m" }, 4096)).toEqual({ model: "m", max_tokens: 4096 });
  });

  it("keeps a smaller limit the caller asked for", () => {
    expect(capOutput("anthropic", { max_tokens: 500 }, 4096)).toEqual({ max_tokens: 500 });
  });

  it("caps OpenAI under max_completion_tokens, folding the old max_tokens in", () => {
    expect(capOutput("openai", { model: "m", max_tokens: 99999 }, 4096)).toEqual({ model: "m", max_completion_tokens: 4096 });
    expect(capOutput("openai", { max_completion_tokens: 100000 }, 4096)).toEqual({ max_completion_tokens: 4096 });
  });

  it("caps Gemini inside generationConfig, keeping its other settings", () => {
    expect(capOutput("google", { generationConfig: { maxOutputTokens: 65536, temperature: 0.2 } }, 4096))
      .toEqual({ generationConfig: { maxOutputTokens: 4096, temperature: 0.2 } });
  });

  it("does nothing without a cap", () => {
    const body = { max_tokens: 64000 };
    expect(capOutput("anthropic", body, 0)).toBe(body);
  });
});
