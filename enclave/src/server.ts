import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";

import {
  addNameRedactions,
  addOrganisationRedactions,
  addMedicalRedactions,
  findMedical,
  addStructuredRedactions,
  buildRedactionMap,
  parseAllowList,
  addNumberRedactions,
  detectPersonalNames,
  parseRedactionMap,
  redactionFingerprint,
  messagesText,
  redactMessages,
  redactText,
  type RequestMessage,
// The .js is required and is not a typo: this compiles to a real ES module
// and Node will not resolve an extensionless specifier at runtime. The local
// imports below already carry it; this one did not, and the enclave died on
// boot with ERR_MODULE_NOT_FOUND — which looks like a missing file rather than
// a missing four characters. TypeScript maps the .js back to the .ts source.
} from "../../cloudflare-worker/redaction.js";
import { attest, decryptToEnclave, enclavePublicKey } from "./attest.js";
import { openSealedChat, runSealedChat, assemble, capOutput, ChatError } from "./sealedChat.js";
import { loadConfig } from "./config.js";
import { nameModelIn, OWN_NAME_MODEL } from "./localNameModel.js";
import { fetchOwnModel } from "./modelFetch.js";
import { localNumberModel } from "./localNumberModel.js";

/**
 * The enclave service.
 *
 * One job: take a message, strip the identifying values out of it, and say what
 * it replaced them with. It holds nothing between requests. The real↔fake map
 * exists for the length of one call and leaves with the response, which is how
 * the Worker already works — there is no store here to compromise because
 * there is nothing worth storing.
 *
 * It speaks plain HTTP on loopback and knows nothing about vsock. socat does
 * that translation at both ends (see scripts/), which keeps the AF_VSOCK
 * plumbing out of the trusted computing base and, incidentally, makes this
 * runnable on a laptop with no changes at all.
 *
 * ── What it deliberately does not do yet ──
 *
 * Call the provider. The prototype stops at redaction and hands the redacted
 * messages back, because that is the step whose correctness is worth proving
 * first and the step the Worker can adopt without any client change. Forwarding
 * belongs here eventually — the pinned outbound path in outbound.ts already
 * exists for it — but a forwarding enclave whose redaction is unverified is the
 * wrong thing to build first.
 *
 * ── The thing this does not yet fix ──
 *
 * The parent still sees plaintext, because the Worker still sends it. Until the
 * client encrypts to the key in the attestation document, this is a correctness
 * exercise rather than a privacy one. That is the next piece, and the README
 * says so rather than letting a demo imply otherwise.
 */

const PORT = Number(process.env.PORT ?? 8000);
const HOST = process.env.HOST ?? "127.0.0.1";

/**
 * The name stage, and why a missing one stops the process.
 *
 * detectPersonalNames treats "no model configured" as decided-with-no-names.
 * In the Worker that is defensible: it is a deployment that chose not to run
 * the stage, the structured stages still ran, and a message should not fail
 * because of a binding somebody left out.
 *
 * Here it is not defensible at all. This process exists to make one promise,
 * and an enclave with no name stage keeps every other person's name in the
 * message — the colleague, the client, the landlord — while answering
 * `namesDecided: true`, which reads as "checked, nothing found". A caller
 * using strictRedaction to refuse rather than leak would sail straight past
 * it. That is the worst kind of wrong: silent, and confidently reported.
 *
 * So a misconfigured enclave refuses to start. ALLOW_NO_NAME_STAGE exists for
 * the structured-stages-only case, and it has to be typed out on purpose.
 */
/* Awaited before anything binds a port, because the answer decides whether
   this process should be running at all. `nitro-cli run-enclave` passes no
   environment, so in here these come from the parent over vsock — see
   config.ts, which is mostly an explanation of why that is necessary. */
const config = await loadConfig();
/* Both judgement stages answer here (v23): names by two small models in the
   image (localNameModel.ts), numbers by rules on the words around them
   (localNumberModel.ts). Nothing about a message leaves the enclave to be
   judged, and api.cloudflare.com is gone from the parent's allowlist. */
// An EIF carries no environment, so the default is where the Dockerfile puts
// them: /app/models, three levels up from /app/dist/enclave/src/server.js.
const MODEL_DIR = process.env.MODEL_DIR ?? new URL("../../../models/", import.meta.url).pathname;
/* Our own model when the image carries one (models/names), the two Xenova
   taggers otherwise: see whichNameModel. Logged and reported on /health, so a
   rebuilt image says which one it is running without anybody reading PCR0. */
/* Our own model is not in the image (modelFetch.ts): the image carries its
   hashes, and the files come from the parent, each checked against them.
   One that does not arrive or does not match leaves no name stage, and the
   check below refuses to start. Only in an enclave: on a laptop MODEL_DIR
   already holds whatever model is being worked on. */
if (process.env.ENCLAVE === "1") {
  const LIST = process.env.NAMES_MODEL_LIST ?? new URL("../../../names-model.sha256", import.meta.url).pathname;
  try {
    const n = await fetchOwnModel(LIST, MODEL_DIR + OWN_NAME_MODEL);
    if (n) console.log(`[enclave] our own name model: ${n} files from the parent, every hash as listed`);
  } catch (err) {
    console.error("[enclave] our own name model did not arrive intact:", (err as Error)?.message ?? err);
  }
}
const loaded = await nameModelIn(MODEL_DIR).catch((err) => {
  console.error("[enclave] local name models did not load:", (err as Error)?.message ?? err);
  return null;
});
const nameModel = loaded?.model ?? null;
if (loaded) console.log(`[enclave] name stage: ${loaded.which === "own" ? "our own model (models/names)" : "the two Xenova taggers"}`);
const numberModel = localNumberModel;

if (!nameModel && !config.allowNoNameStage) {
  console.error(
    "[enclave] refusing to start: no name stage.\n" +
      "  The name models in the image did not load (see the line above). Set\n" +
      "  ALLOW_NO_NAME_STAGE=1 to run the structured stages only. Without it,\n" +
      "  other people's names reach the provider in the clear and every reply\n" +
      "  still says namesDecided: true.",
  );
  process.exit(1);
}

/** A ceiling on one request. The enclave has a fixed memory allocation and no
 *  swap, so an unbounded body is not a slow request — it is the process dying
 *  and taking every in-flight request with it. */
const MAX_BODY_BYTES = 512_000;

type RedactRequest = {
  messages?: RequestMessage[];
  /** The system prompt the caller will actually send. Included because aliases
   *  are collision-checked against it, and because it gets redacted too. */
  system?: string;
  /** The caller's own identifying values, sent per request, never stored. */
  profile?: unknown;
  /** The map from earlier turns, so one person keeps one alias in a thread. */
  redaction?: unknown;
  /** Terms the person said may be sent as written. The Worker forwards it
   *  so both machines redact identically — see AllowList in redaction.ts. */
  allow?: unknown;
  /** Refuse rather than send when the name stage could not reach a verdict. */
  strictRedaction?: boolean;
  /** Ask the model about the numbers the patterns could not place. Sent by
   *  the Worker when its NUMBER_STAGE is on. */
  numberStage?: boolean;
  /** Read all of the text for names rather than only its tail. Set by the
   *  document API, which is one call with no earlier turn behind it; absent
   *  for chat, where the tail is right because earlier names are already in
   *  the map being carried forward. */
  scanAll?: boolean;
  /** How long the latest user message is, so the name stage reads all of
   *  it rather than only its last window. */
  newChars?: number;
  /** Hide organisations as well as people. Off unless the caller asked.
   *  "all": public bodies (courts, ministries, states) too. */
  hideOrganisations?: boolean | "all";
  /** Medical mode: what HIPAA's Safe Harbor lists beyond the usual —
   *  dates but their year, ages over 89, towns, places of care, every web
   *  and IP address. See redactionMedical.ts. */
  medical?: boolean;
};

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error("Body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

/**
 * The redaction pipeline, once.
 *
 * Lifted out of handleRedact when /chat arrived, because two endpoints running
 * two copies of these three stages is the failure mode this whole file is
 * careful about elsewhere: they agree on the day they are written and diverge
 * quietly afterwards, and the divergence is a name reaching a provider on one
 * path and not the other.
 *
 * Returns `refused` rather than throwing, because refusing is a legitimate
 * outcome with its own status, not an error.
 */
async function runRedaction(parsed: RedactRequest): Promise<
  | { refused: true; reason: string }
  | {
      refused: false;
      messages: NonNullable<RedactRequest["messages"]>;
      system: string;
      redaction: Awaited<ReturnType<typeof addNameRedactions>>;
      decided: boolean;
      found: number;
    }
> {
  const messages = Array.isArray(parsed.messages) ? parsed.messages : [];
  const system = typeof parsed.system === "string" ? parsed.system : "";
  // Text parts too: a message sent as a list of parts (any message with a
  // picture, and every OpenAI-style client) is otherwise read as empty.
  const conversationText = messagesText(messages);

  /**
   * Two texts, and the difference is load-bearing.
   *
   * `userText` is where identifiers are looked for — only what the user
   * actually wrote. `haystack` is what a candidate alias is checked against for
   * collisions, and it includes the system prompt. Using one text for both is
   * the mistake it looks like: search the system prompt too and an example
   * address inside a formatting guide gets aliased out from under the model;
   * collision-check without it and an alias can land on a word the system
   * prompt already uses.
   *
   * The Worker builds these the same way. They are the same two lines because
   * they have to be — this file existing at all is only safe while the two
   * agree, and this is the part a second implementation gets wrong.
   */
  const userText = conversationText;
  const haystack = [system, conversationText].join("\n");

  // Stage 1 then stage 2: the caller's own values, then anything structured
  // enough to recognise on sight — cards that pass Luhn, IBANs that pass
  // mod-97, cued SSNs, phone numbers, addresses.
  const allow = parseAllowList(parsed.allow);
  const structured = await addStructuredRedactions(
    await buildRedactionMap(parsed.profile, parseRedactionMap(parsed.redaction), haystack, allow),
    userText,
    haystack,
    allow,
  );

  // Stage 3 last, and only over what the cheap stages did not already cover.
  // It is the one stage that can call a model, so it is the one that can add
  // latency and the one that can fail to reach a verdict.
  const detection = await detectPersonalNames(userText, nameModel, {
    scanAll: parsed.scanAll === true,
    newChars: typeof parsed.newChars === "number" && parsed.newChars > 0 ? parsed.newChars : undefined,
    organisations: parsed.hideOrganisations === "all" ? "all" : parsed.hideOrganisations === true,
    places: parsed.medical === true,
  });

  // Undecided is not "no names". Under strict redaction the honest answer is
  // to refuse, because the alternative is a message whose names reach the
  // provider in the clear while every status code still says 200.
  if (parsed.strictRedaction === true && !detection.decided) {
    return { refused: true, reason: "The name check could not reach a verdict." };
  }

  let named = await addOrganisationRedactions(
    await addNameRedactions(structured, detection.names, haystack, allow),
    detection.organisations ?? [],
    haystack,
    allow,
  );
  // After names, so a name already taken is not taken again as a town.
  if (parsed.medical === true) {
    const medical = [...findMedical(userText), ...(detection.places ?? []).map((value) => ({ kind: "place" as const, value }))];
    named = await addMedicalRedactions(named, medical, haystack, allow);
  }
  let redaction = named;
  if (parsed.numberStage === true) {
    const numbers = await addNumberRedactions(named, userText, numberModel, haystack, allow, {
      scanAll: parsed.scanAll === true,
    });
    // Strict redaction covers the number stage too: undecided refuses.
    if (parsed.strictRedaction === true && !numbers.decided) {
      return { refused: true, reason: "The number check could not reach a verdict." };
    }
    redaction = numbers.redaction;
  }

  const redacted = redactMessages(messages, redaction);
  // The system prompt goes through the same map. It can carry the caller's
  // memory and project context, which is exactly the kind of text a real name
  // ends up in.
  const redactedSystem = system ? redactText(system, redaction) : "";

  return {
    refused: false,
    messages: redacted,
    system: redactedSystem,
    redaction,
    decided: detection.decided,
    found: detection.names.length,
  };
}

/**
 * The names in a piece of text, and nothing else: the words read off a
 * picture, which the device covers before the picture is sent. The same name
 * stage /redact runs, here so the words of an enclave customer's photo are
 * read where their messages are — never by the Worker. Only names that are in
 * the text come back; nothing is kept.
 */
async function handleNames(body: string, res: ServerResponse): Promise<void> {
  let parsed: { text?: unknown };
  try {
    parsed = JSON.parse(body) as { text?: unknown };
  } catch {
    return send(res, 400, { error: "invalid_json" });
  }
  const text = typeof parsed.text === "string" ? parsed.text.slice(0, 8000) : "";
  if (!text.trim()) return send(res, 200, { names: [], decided: true });
  const detection = await detectPersonalNames(text, nameModel, { scanAll: true });
  return send(res, 200, {
    names: detection.names.filter((n) => text.includes(n)),
    decided: detection.decided,
  });
}

async function handleRedact(body: string, res: ServerResponse): Promise<void> {
  let parsed: RedactRequest;
  try {
    parsed = JSON.parse(body) as RedactRequest;
  } catch {
    return send(res, 400, { error: "invalid_json" });
  }
  if (!Array.isArray(parsed.messages) || parsed.messages.length === 0) {
    return send(res, 400, { error: "no_messages" });
  }

  const result = await runRedaction(parsed);
  if (result.refused) {
    return send(res, 503, { error: "redaction_unavailable", reason: result.reason });
  }

  send(res, 200, {
    messages: result.messages,
    system: result.system,
    /** fake → real. The caller returns it to its client and sends it back next
     *  turn; nothing here remembers it. */
    redaction: result.redaction,
    namesDecided: result.decided,
    namesFound: result.found,
    /** Said only when medical mode ran, so a Worker asking for it can tell
     *  this enclave from one that predates it and ignored the field. */
    ...(parsed.medical === true ? { medical: true } : {}),
  });
}

/**
 * The sealed path.
 *
 * A request only this enclave can open, redacted here, sent to the provider
 * from here, and answered in pieces only the client can read. The parent
 * instance and the Worker relay bytes and learn nothing from them.
 *
 * /redact stays exactly as it was. It is the unsealed path the Worker uses
 * today, and it will keep working while the clients move over — a flag day
 * across four apps is not a plan.
 */
async function handleChat(body: string, res: ServerResponse, numberStage: boolean, outputCap = 0): Promise<void> {
  let envelope;
  try {
    envelope = JSON.parse(body);
  } catch {
    return send(res, 400, { error: "invalid_json" });
  }

  let opened;
  try {
    opened = await openSealedChat(envelope, decryptToEnclave);
  } catch (err) {
    const status = err instanceof ChatError ? err.status : 400;
    return send(res, status, { error: err instanceof ChatError ? err.message : "cannot_open" });
  }

  const { request, session } = opened;

  const result = await runRedaction({
    messages: request.messages,
    system: request.system,
    profile: request.profile,
    redaction: request.redaction,
    allow: request.allow,
    strictRedaction: request.strictRedaction,
    numberStage,
  } as RedactRequest);

  if (result.refused) {
    return send(res, 503, { error: "redaction_unavailable", reason: result.reason });
  }

  let stream: ReadableStream<Uint8Array>;
  try {
    stream = await runSealedChat(
      request,
      {
        // The answer length an API key paid for, when the Worker says one.
        body: assemble(request.provider, outputCap > 0 ? capOutput(request.provider, request.body, outputCap) : request.body, result.messages, result.system),
        redaction: result.redaction,
      },
      session,
      { anthropicKey: config.anthropicKey, openaiKey: config.openaiKey, googleKey: config.googleKey },
    );
  } catch (err) {
    const status = err instanceof ChatError ? err.status : 502;
    return send(res, status, { error: err instanceof ChatError ? err.message : "provider_error" });
  }

  /* Headers before the first piece, so a client can start reading. The
     redaction map is not among them: the enclave has already put the real
     values back, so the client has nothing to undo and nothing that would let
     a relay reverse what it saw. */
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    Connection: "keep-alive",
  });

  const reader = stream.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      res.write(value);
    }
    res.end();
  } catch {
    /* The sealed stream errored, which means no final piece was written. Ending
       the response here is right and safe: the client's reader refuses a stream
       with no ending, so a truncated answer cannot be shown as a whole one. */
    res.end();
  }
}

/** Whether the caller is the Worker: see EnclaveConfig.workerSecret. */
function fromWorker(req: IncomingMessage): boolean {
  const expected = config.workerSecret;
  if (!expected) return true;
  const given = req.headers["x-enclave-secret"];
  if (typeof given !== "string") return false;
  const a = Buffer.from(given), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
if (!config.workerSecret) console.warn("[enclave] no workerSecret in config: /chat, /redact and /names answer anybody");

const server = createServer(async (req, res) => {
  try {
    // The three that do work, and spend: the Worker's alone. Health, the
    // attestation and the public key stay public; a client reads them.
    if (req.method === "POST" && (req.url === "/redact" || req.url === "/names" || req.url === "/chat") && !fromWorker(req)) {
      return send(res, 401, { error: "unauthorized" });
    }
    if (req.method === "GET" && req.url === "/health") {
      /* Which redaction build this image is running. The stages are deployed
         twice -- into the Worker, and into this image -- and until this line
         existed nothing anywhere said whether the two matched. See
         redactionBuild.ts for the afternoon that cost. */
      return send(res, 200, {
        ok: true,
        nameStage: nameModel ? "local" : "absent",
        nameModel: loaded?.which ?? "none",
        numberStage: "local",
        redaction: await redactionFingerprint(),
      });
    }

    if (req.method === "GET" && req.url?.startsWith("/attestation")) {
      // The nonce is the caller's and is what stops a document being replayed.
      // Absent, we still answer — an unattested reply is honest about itself —
      // but a verifier should be sending one.
      const nonce = new URL(req.url, "http://enclave").searchParams.get("nonce") ?? "";
      return send(res, 200, await attest(nonce));
    }

    if (req.method === "GET" && req.url === "/public-key") {
      return send(res, 200, { publicKey: enclavePublicKey() });
    }

    if (req.method === "POST" && req.url === "/redact") {
      return await handleRedact(await readBody(req), res);
    }

    if (req.method === "POST" && req.url === "/names") {
      return await handleNames(await readBody(req), res);
    }

    if (req.method === "POST" && req.url === "/chat") {
      /* Whether to run the number stage, from the Worker, outside the sealed
         envelope because the Worker cannot write inside it. A relay that
         dropped the header could only turn the stage off, which it can
         already do more simply by dropping the request. */
      return await handleChat(await readBody(req), res, req.headers["x-number-stage"] === "on", Number(req.headers["x-output-cap"] ?? 0));
    }

    send(res, 404, { error: "not_found" });
  } catch (err) {
    // Never echo the error's message: it was produced while handling a body
    // that may contain exactly the values this service exists to hide, and an
    // error string is the classic way one escapes into a log.
    console.error("[enclave] request failed:", err instanceof Error ? err.name : "unknown");
    send(res, 500, { error: "internal" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[enclave] listening on ${HOST}:${PORT}`);
  console.log(
    `[enclave] name stage: ${nameModel ? "local models" : "ABSENT — structured stages only, names are NOT redacted"}`,
  );
});
