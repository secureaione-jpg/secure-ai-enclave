import {
  restoreStream,
  type RedactionMap,
  type RequestMessage,
} from "../../cloudflare-worker/redaction.js";
import { openRequest, type SealedRequest } from "../../lib/sealedEnvelope.js";
import { upstreamStream, type UPSTREAMS } from "./outbound.js";
import { sealStream } from "./sealedStream.js";

/**
 * The sealed path: a request only this enclave can open, an answer only the
 * client can read.
 *
 * ── What moved, and what did not ──
 *
 * The division of labour is deliberate and narrow. The caller still decides
 * everything about the model — which one, what parameters, how the messages are
 * shaped — and hands over a provider request it has already formed. This file
 * adds exactly two things the caller cannot do for itself: it redacts the
 * message content, and it holds the provider key.
 *
 * That is the whole reason the Worker could not stop seeing plaintext before
 * now. It held the key, so it had to make the call, so it had to have the
 * message in the clear to put in the call. Moving the key in here is what
 * breaks that chain, and it is the price of the property — the parent's
 * root-only config file now holds two more secrets. Named plainly in config.ts
 * rather than glossed.
 *
 * Keeping model decisions out means there is no second copy of the provider
 * table to drift from the first. The one thing this file knows about a provider
 * is how it wants to be authenticated.
 *
 * ── What the Worker still does ──
 *
 * Everything that does not need the message: deciding who is asking, whether
 * they may, what it costs, and what to write down. None of that reads content,
 * and all of it survives the change untouched.
 */

/** The providers this can authenticate to, and how. Not a model catalogue —
 *  the caller names the path and the body. */
const AUTH: Record<string, { upstream: keyof typeof UPSTREAMS; headers: (key: string) => Record<string, string> }> = {
  anthropic: {
    upstream: "anthropic",
    headers: (key) => ({
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    }),
  },
  openai: {
    upstream: "openai",
    headers: (key) => ({
      Authorization: `Bearer ${key}`,
      "content-type": "application/json",
    }),
  },
  /* Google's own documentation reaches for ?key= in the query string, and that
     is the one form this cannot use. The path is the single field the caller
     supplies, so it is validated, logged on failure, and generally handled as
     untrusted — putting a live provider key inside it would run the key
     through all of that. x-goog-api-key is the same credential in a header the
     caller never touches. */
  google: {
    upstream: "google",
    headers: (key) => ({
      "x-goog-api-key": key,
      "content-type": "application/json",
    }),
  },
};

/** What the client seals. */
export type ChatRequest = {
  provider: keyof typeof AUTH;
  /** The provider path, e.g. /v1/messages. Chosen by the caller; never built
   *  from anything in the message. */
  path: string;
  /**
   * The provider request minus the conversation: model, temperature, tools,
   * stream, whatever else the caller decided. Passed through untouched.
   */
  body: Record<string, unknown>;
  /**
   * The conversation, in one shape regardless of provider.
   *
   * Separate from `body` so redaction has a single input to work on. The
   * alternative — reaching into a provider-shaped body to find the text — is
   * how a redactor comes to have opinions about three request formats and
   * misses the one it was not updated for. Here the shape is ours, and only
   * putting it back is provider-specific.
   *
   * RequestMessage rather than a narrower {role, content: string}: content can
   * be an array of parts, which is how a document or a picture travels. A type
   * that says string compiles, and then silently excludes every message with an
   * attachment from the sealed path.
   */
  messages: RequestMessage[];
  system?: string;
  /** Passed through to the redaction pipeline, same as /redact takes them. */
  profile?: unknown;
  redaction?: unknown;
  allow?: unknown;
  strictRedaction?: boolean;
};

/**
 * One message in Gemini's shape.
 *
 * Google is the reason the comment above this function used to say "two lines
 * each" and no longer does. Anthropic and OpenAI disagree only about where the
 * system prompt goes; Google disagrees about everything — the field is
 * `contents` not `messages`, the turns are `parts` not `content`, the model's
 * own role is spelled `model`, and an image arrives as `inlineData` rather
 * than a data URL. So it gets a converter instead of a branch.
 *
 * This mirrors `toGemini` in the Worker deliberately. Two copies is a real
 * cost, and the alternative is worse than it looks: the Worker's version takes
 * a whole payload and returns a Response, so sharing it would mean dragging
 * fetch and CORS into a process whose entire argument is that it can only
 * reach an allowlisted host.
 */
function toGeminiContent(m: RequestMessage): Record<string, unknown> {
  const role = m.role === "assistant" ? "model" : "user";
  if (typeof m.content === "string") return { role, parts: [{ text: m.content }] };

  const parts = m.content.map((part) => {
    if (part.type === "text") return { text: part.text };
    if (part.type === "image") {
      return { inlineData: { mimeType: part.source.media_type, data: part.source.data } };
    }
    const match = part.image_url.url.match(/^data:([^;]+);base64,(.+)$/);
    /* A remote image URL is dropped rather than forwarded. Gemini would fetch
       it, and a fetch by the provider is a request this enclave did not make
       and cannot see — the one shape of outbound traffic the allowlist exists
       to prevent. An empty part is a worse answer; a silent exfiltration
       channel is a broken promise. */
    return match ? { inlineData: { mimeType: match[1], data: match[2] } } : { text: "" };
  });
  return { role, parts };
}

/**
 * Put the redacted conversation back into the body the provider expects.
 *
 * The only provider-shaped knowledge in this file. Anthropic carries the system
 * prompt in its own field; OpenAI carries it as the first message; Google
 * carries it in `systemInstruction` and renames everything else besides.
 */
export function assemble(
  provider: keyof typeof AUTH,
  body: Record<string, unknown>,
  messages: RequestMessage[],
  system: string,
): Record<string, unknown> {
  if (provider === "anthropic") {
    const out: Record<string, unknown> = { ...body, messages };
    if (system) out.system = system;
    return out;
  }
  if (provider === "google") {
    const out: Record<string, unknown> = { ...body, contents: messages.map(toGeminiContent) };
    if (system) out.systemInstruction = { parts: [{ text: system }] };
    return out;
  }
  return {
    ...body,
    messages: system ? [{ role: "system", content: system }, ...messages] : messages,
  };
}

export type ChatKeys = { anthropicKey?: string; openaiKey?: string; googleKey?: string };

/**
 * Redaction, supplied by the caller rather than done here, because the pipeline
 * lives in server.ts with the name stage it needs. This takes the finished map
 * and the already-redacted body.
 */
export type Redacted = {
  body: Record<string, unknown>;
  /** fake → real. Used to put the answer back the way the reader expects, and
   *  never leaves this process. */
  redaction: RedactionMap;
};

export class ChatError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Open a sealed chat request.
 *
 * Split from `runSealedChat` so the redaction pipeline can run between the two
 * — the caller opens, redacts, then runs. The session key travels between them
 * because the answer must be sealed under the key from *this* request and no
 * other.
 */
export async function openSealedChat(
  envelope: SealedRequest,
  unwrap: (ciphertext: Uint8Array) => Promise<Uint8Array>,
): Promise<{ request: ChatRequest; session: CryptoKey }> {
  let opened;
  try {
    opened = await openRequest(envelope, unwrap);
  } catch {
    /* Deliberately unspecific. The distinctions available here — a wrapped key
       that will not unwrap, a body whose tag does not check — are exactly the
       distinctions an attacker probing the endpoint would like reported back.
       There is one answer: this is not for us. */
    throw new ChatError(400, "cannot_open");
  }

  let request: ChatRequest;
  try {
    request = JSON.parse(opened.body) as ChatRequest;
  } catch {
    throw new ChatError(400, "invalid_request");
  }

  if (!request?.provider || !AUTH[request.provider]) {
    throw new ChatError(400, "unknown_provider");
  }
  /* A path from the request, checked. It names a route on a host the outbound
     allowlist has already fixed, so the worst case is a different endpoint at
     the same provider rather than a different provider — but a path that can
     begin with // is a path that becomes a host again in anything that later
     joins it to an origin, and the check costs one line.

     Written first as a single character-class regex, which allowed exactly
     that: "//evil.example/v1/messages" starts with a slash and contains only
     permitted characters. The leading-slash rule and the no-second-slash rule
     are different rules and one pattern quietly conflated them.

     Gemini is why there is a query half at all. Its route is
     /v1beta/models/<model>:streamGenerateContent?alt=sse — a colon inside a
     segment and a query string, both of which the original pattern refused.
     Widening a check that guards the one caller-supplied field is worth
     spelling out, so:

       · The colon is safe only because the leading slash is mandatory. A
         string beginning "https:" would be a scheme to anything that joins it
         to an origin; one beginning "/v1beta/...:foo" cannot be.
       · The two halves are matched separately rather than by adding characters
         to one class. That is the lesson from the // bug — a single widened
         class would also accept "?" inside the path and "/" inside the query,
         and neither belongs there.
       · What stays excluded is the point. No space, no CR or LF (this path is
         written straight into a request line, where a newline is header
         injection), no backslash (parsers that fold it to "/" would see a
         different path than this check did), no "#" (a fragment truncates the
         path for whoever reads it next), and no "@" or ":" in the query, which
         is where userinfo would hide.

     A caller can therefore set query parameters on a host it was already able
     to reach. For Google that means it could append its own ?key= — which
     wins it nothing, since ours goes in a header and the header is added after
     this, by us. */
  const [routePath, ...rest] = String(request.path ?? "").split("?");
  const query = rest.join("?");
  if (
    typeof request.path !== "string" ||
    !request.path.startsWith("/") ||
    request.path.startsWith("//") ||
    rest.length > 1 ||
    !/^\/[A-Za-z0-9/_.:-]*$/.test(routePath) ||
    (rest.length === 1 && !/^[A-Za-z0-9_.=&%-]*$/.test(query))
  ) {
    throw new ChatError(400, "invalid_path");
  }
  if (!request.body || typeof request.body !== "object") {
    throw new ChatError(400, "invalid_body");
  }
  if (!Array.isArray(request.messages) || request.messages.length === 0) {
    throw new ChatError(400, "no_messages");
  }

  return { request, session: opened.session };
}

/**
 * Hold an answer to a length somebody has paid for (2026-10-07).
 *
 * A sealed request from an API key is priced before it is opened — the size
 * of the envelope plus a fixed answer, since the token counts are inside —
 * and the client chooses the provider body, max_tokens included. Without
 * this, a hand-built request could ask for sixty thousand tokens and pay for
 * four. The Worker says what was paid for in X-Output-Cap; this lowers the
 * body's own limit to it, and sets one where the body named none. Lowered
 * only: a smaller limit the caller asked for is theirs to keep.
 *
 * The apps' sealed path sends no cap and is unchanged.
 */
export function capOutput(provider: string, body: Record<string, unknown>, cap: number): Record<string, unknown> {
  if (!Number.isFinite(cap) || cap <= 0) return body;
  const lower = (v: unknown) => (typeof v === "number" && v > 0 ? Math.min(v, cap) : cap);
  if (provider === "google") {
    const config = (body.generationConfig && typeof body.generationConfig === "object" ? body.generationConfig : {}) as Record<string, unknown>;
    return { ...body, generationConfig: { ...config, maxOutputTokens: lower(config.maxOutputTokens) } };
  }
  if (provider === "openai") {
    const { max_tokens, ...rest } = body;
    return { ...rest, max_completion_tokens: lower(body.max_completion_tokens ?? max_tokens) };
  }
  return { ...body, max_tokens: lower(body.max_tokens) };
}

/**
 * Call the provider with the redacted body, put the real values back, and seal
 * the answer to the client's session key.
 *
 * The restored text exists only inside this process and only for as long as it
 * takes to seal each piece.
 */
export async function runSealedChat(
  request: ChatRequest,
  redacted: Redacted,
  session: CryptoKey,
  keys: ChatKeys,
): Promise<ReadableStream<Uint8Array>> {
  const auth = AUTH[request.provider];
  /* A table rather than a ternary, which is not tidying: the ternary read
     "anthropic, or else openai", so adding a third provider would have handed
     Google's requests the OpenAI key and got back a 401 that says nothing
     about why. */
  const key = {
    anthropic: keys.anthropicKey,
    openai: keys.openaiKey,
    google: keys.googleKey,
  }[request.provider];

  /* No key, no call — and no falling back to handing the redacted messages
     to the caller instead. A sealed request that quietly becomes an unsealed
     one is the failure this endpoint exists to prevent. */
  if (!key) throw new ChatError(503, "provider_key_missing");

  const upstream = await upstreamStream(auth.upstream, request.path, {
    method: "POST",
    headers: auth.headers(key),
    body: JSON.stringify(redacted.body),
  });

  if (!upstream.ok || !upstream.body) {
    /* The provider's own error text is not forwarded. It routinely quotes the
       request back — the offending message, the field it disliked — and that
       request has real values in it only in the caller's copy, but the
       redacted one still carries the conversation's shape. The status is
       enough for a caller to retry or give up. */
    throw new ChatError(upstream.status === 429 ? 429 : 502, "provider_error");
  }

  const contentType = upstream.headers.get("content-type") ?? "";
  const restored = restoreStream(
    upstream.body,
    redacted.redaction,
    request.provider as never,
    contentType,
  );

  return sealStream(restored, session);
}
