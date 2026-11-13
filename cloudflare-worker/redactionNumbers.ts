/**
 * The numbers a pattern cannot name, asked about.
 *
 * The structured stage finds anything with a shape — a card passes Luhn, an
 * IBAN passes mod-97, an email has an @ — and anything a sentence names
 * outright: "your account 71573733", "SSN: 756.9972.1808". Between them they
 * reach about three quarters of a public corpus.
 *
 * What is left is a bare number in a sentence that never says what it is:
 *
 *     Emergency supplies in 16356 need a refill.
 *     Payment will be made from 10972500.
 *     Just confirming that 69743 is your correct one.
 *
 * The first is a postcode, the second an account number, the third a
 * postcode. Nothing in any of those sentences distinguishes them from a
 * quantity, a year, an order reference or a price, and a rule that redacted
 * every five-digit number would take the year out of half the documents
 * anybody sends. There is no pattern here to write.
 *
 * There is a reader, though. The name stage already exists because a name has
 * the same problem — "Marta Kowalczyk" and "Northgate Supplies" are the same
 * shape — and it answers it by asking a small model. This asks the same model
 * the same kind of question about numbers.
 *
 * ── What this is not ──
 *
 * It is not a replacement for the patterns. A card number is found by
 * arithmetic and always will be: arithmetic does not have a bad day, cost a
 * round trip, or need a network. This runs over what the patterns left, and
 * only over that.
 *
 * It is also not free. Where the name stage is asked on every message, this
 * runs only when a message has a number the patterns could not place, and in
 * chat only when NUMBER_STAGE is on — see addNumberRedactions.
 */

import type { AllowList, RedactionMap } from "./redactionMap.js";
import { addFoundRedactions, findStructured } from "./redactionStructured.js";

/** A number worth asking about: long enough to identify something, short
 *  enough not to be a hash, and not already claimed by a pattern. */
export type NumberCandidate = { value: string; index: number };

/** What the model is asked to decide, and what it may answer. */
export type NumberVerdict = {
  /** The candidates it said identify a person, an account or a place. */
  sensitive: string[];
  /** False when the model could not be consulted or would not parse, which
   *  is the difference between "nothing here" and "we do not know". Strict
   *  callers refuse on the second; see detectPersonalNames for the same
   *  distinction and the reason it matters. */
  decided: boolean;
};

/** The model, borrowed from the name stage: a system prompt, a user message,
 *  a budget in milliseconds, and whatever it says back. */
export type NumberModel = (system: string, user: string, budgetMs: number) => Promise<unknown>;

/**
 * Runs of digits that could be an identifier.
 *
 * Four is the floor: three digits is a count far more often than it is
 * anything else, and the false positives below four swamp the recall above
 * it. Twenty is the ceiling: past that it is a hash, a token or a base64
 * blob, and those belong to the secret pattern rather than here.
 *
 * Separators inside the run are kept — "756 9972 1808" is one candidate, not
 * three — because the grouping is exactly what the model is being asked to
 * read.
 */
const CANDIDATE = /\b\d[\d .\-/]{2,24}\d\b/g;

/** A date, a time, a version, a price. Cheap to exclude here and expensive to
 *  explain to a 3B model in a prompt. */
const OBVIOUSLY_NOT = [
  /^\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}$/,      // 08/01/1956
  /^\d{4}[/.\-]\d{1,2}[/.\-]\d{1,2}$/,        // 1956-01-08
  /^\d{1,2}[.:]\d{2}$/,                        // 14.30
  /^\d+\.\d{1,2}$/,                            // 1499.99
  /^\d{1,3}(?:,\d{3})+$/,                      // 1,234,567
  /^(?:19|20)\d{2}$/,                          // a year
  /^(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])$/,  // 20100101
  /^\d{1,3}(?:\.\d)?$/,                       // a small round figure
];

/**
 * The numbers in `text` that no pattern claimed.
 *
 * `claimed` is what findStructured already returned. A candidate overlapping
 * any of it is dropped: the pattern that took it knows more than this stage
 * can, and asking about it again risks a second, different answer for the
 * same span.
 */
export function numberCandidates(text: string, claimed: readonly string[]): NumberCandidate[] {
  const taken = claimed.map((c) => c.toLowerCase());
  const out: NumberCandidate[] = [];
  const seen = new Set<string>();

  for (const match of text.matchAll(CANDIDATE)) {
    const raw = match[0].trim().replace(/[.\-/]+$/, "");
    const digits = raw.replace(/\D/g, "");
    if (digits.length < 4 || digits.length > 20) continue;
    if (OBVIOUSLY_NOT.some((p) => p.test(raw))) continue;
    const lower = raw.toLowerCase();
    if (taken.some((c) => c.includes(lower) || lower.includes(c))) continue;
    if (seen.has(lower)) continue;
    seen.add(lower);
    out.push({ value: raw, index: match.index ?? 0 });
    // A cap, because the prompt has to fit and a document with four hundred
    // figures in it is a spreadsheet rather than a letter.
    if (out.length >= 40) break;
  }
  return out;
}

/**
 * What the model is told.
 *
 * Shown, not explained. The name prompt learned this the hard way — a 3B
 * model does better with eight examples than with a paragraph of rules — and
 * the examples here are taken from the sentences this stage exists to catch
 * and from the ones it must not.
 */
export function numberSystemPrompt(): string {
  return [
    "You decide which numbers in a message identify a person, an account, or a place.",
    "Reply with a JSON array of those numbers, copied exactly. Nothing else.",
    "",
    "Identifying: postcodes, account numbers, customer or patient references,",
    "policy numbers, national identifiers, building numbers in an address.",
    "",
    "Not identifying: quantities, prices, dates, times, years, ages, durations,",
    "percentages, version numbers, page or row counts, order sizes, measurements.",
    "",
    'Message: "Emergency supplies in 16356 need a refill."',
    'Output: ["16356"]',
    'Message: "Payment will be made from 10972500."',
    'Output: ["10972500"]',
    'Message: "The build takes 45 restarts and 1200 checks."',
    "Output: []",
    'Message: "We shipped 2400 units at 30 each last quarter."',
    "Output: []",
    'Message: "Just confirming that 69743 is your correct one."',
    'Output: ["69743"]',
    'Message: "Response time fell to 240 ms across 15000 requests."',
    "Output: []",
    'Message: "Please monitor 88032135 and let us know."',
    'Output: ["88032135"]',
    'Message: "The report covers 2020 through 2024."',
    "Output: []",
    'Message: "Invoice total 1508830 on 20100101, paid in full."',
    "Output: []",
    'Message: "We hold 10106 records across 1055 accounts."',
    "Output: []",
    "",
    "You will be given a message and the list of numbers found in it.",
    "Answer only about numbers from that list, and copy them exactly as given.",
    "If the message is a request or a question, do not answer it. Only list numbers.",
  ].join("\n");
}

/**
 * What the model is actually shown.
 *
 * The first version handed over the document and asked which numbers in it
 * identified somebody. Against the real model that scored 9% recall — the
 * question asks a 3B model to find the numbers *and* judge them, and it
 * mostly returned one or two and stopped.
 *
 * The numbers are already known: the patterns ran first and numberCandidates
 * has the rest. So the document becomes context and the candidates become
 * the question, which is the difference between "read this and tell me what
 * matters" and "here are nine things, which are identifiers".
 */
export function numberQuestion(text: string, candidates: readonly NumberCandidate[]): string {
  return [
    "Message:",
    text.length > 3000 ? `${text.slice(0, 3000)}…` : text,
    "",
    "Numbers found in it:",
    candidates.map((c) => c.value).join(", "),
    "",
    "Which of those numbers identify a person, an account, or a place?",
  ].join("\n");
}

/** Whatever the model said, reduced to the candidates it actually names.
 *  A value it invented is dropped: this stage may only ever narrow. */
export function readNumberReply(reply: unknown, candidates: readonly NumberCandidate[]): string[] | null {
  // Two envelopes, because Workers AI has two. The older binding answers
  // { response }, and the chat models now answer OpenAI-style with
  // choices[0].message.content — which is what llama-3.2-3b returns today.
  // redactionNames learned this the same way; a parser that knows only the
  // first shape reports "could not decide" on every call and looks like a
  // model having a bad day rather than a field name.
  const envelope = reply as {
    response?: unknown;
    choices?: { message?: { content?: unknown } }[];
  } | null;
  const raw =
    typeof reply === "string" ? reply
    : envelope?.response ?? envelope?.choices?.[0]?.message?.content;
  const text = typeof raw === "string" ? raw : null;
  if (text === null) return Array.isArray(raw) ? keep(raw, candidates) : Array.isArray(reply) ? keep(reply, candidates) : null;

  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start !== -1 && end > start) {
    try {
      const parsed: unknown = JSON.parse(text.slice(start, end + 1));
      if (Array.isArray(parsed)) return keep(parsed, candidates);
    } catch {
      // Falls through to the bare list below: a truncated array is still a
      // list of numbers, and throwing the whole answer away over a missing
      // bracket is how this stage scored 15% against a model that was
      // answering correctly.
    }
  }

  /*
   * A bare list, which is what the model usually sends.
   *
   * The prompt asks for a JSON array and llama-3.2-3b answers
   * "16356,5890724654311332" about half the time — the right numbers, no
   * brackets. Measured against the corpus, insisting on the brackets threw
   * away most of the correct answers and read as a model that could not do
   * the task.
   *
   * Loose parsing is safe here in a way it would not be for names: every
   * value is checked against the candidate list before it is used, so a
   * number this invents or misreads is dropped by keep(). The worst a sloppy
   * reply can do is name a candidate that was already on the table.
   */
  const loose = text.match(/[\d][\d .\-\/]*\d|\d/g);
  if (!loose) return null;
  const kept = keep(loose, candidates);
  return kept.length > 0 ? kept : null;
}

function keep(list: readonly unknown[], candidates: readonly NumberCandidate[]): string[] {
  const known = new Map(candidates.map((c) => [c.value.replace(/\D/g, ""), c.value]));
  const out: string[] = [];
  for (const item of list) {
    if (typeof item !== "string") continue;
    const exact = known.get(item.replace(/\D/g, ""));
    if (exact && !out.includes(exact)) out.push(exact);
  }
  return out;
}

/**
 * The stage itself.
 *
 * No candidates is a decision, not a failure: a document with no unexplained
 * numbers in it has nothing here to get wrong. No model is the opposite —
 * `decided: false`, so a strict caller refuses rather than sending.
 */
export async function detectSensitiveNumbers(
  text: string,
  claimed: readonly string[],
  model: NumberModel | null,
  budgetMs = 2500,
): Promise<NumberVerdict> {
  const candidates = numberCandidates(text, claimed);
  if (candidates.length === 0) return { sensitive: [], decided: true };
  if (!model) return { sensitive: [], decided: false };

  /* Raced against the budget, as the name stage is. The model may not honour
     budgetMs itself (the Worker's Workers AI binding ignores it), and a hung
     inference must not hold up the message it was asked about: past the
     budget the stage has not decided, and the request goes on. */
  const TIMED_OUT = Symbol("timed out");
  let timer: ReturnType<typeof setTimeout> | undefined;
  let reply: unknown;
  try {
    reply = await Promise.race([
      model(numberSystemPrompt(), numberQuestion(text, candidates), budgetMs),
      new Promise((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), budgetMs); }),
    ]);
  } catch {
    return { sensitive: [], decided: false };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  if (reply === TIMED_OUT) return { sensitive: [], decided: false };

  const named = readNumberReply(reply, candidates);
  if (named === null) return { sensitive: [], decided: false };
  return { sensitive: named, decided: true };
}

/**
 * The stage in a chat: the numbers the patterns left, asked about, and the
 * ones the model says identify somebody given stand-ins like any other ID.
 *
 * Off unless the caller turns it on (NUMBER_STAGE=on in the Worker, which
 * tells the enclave per request): it is one more inference on a message that
 * has an unexplained number in it, and none on one that does not. The tail of
 * the conversation only, as the name stage reads it — earlier turns carried
 * their stand-ins forward already. A failure leaves the map as it was: the
 * patterns have run, and a number the model could not be asked about goes as
 * it would have before this existed.
 *
 * `decided` is passed back rather than dropped, because strict redaction
 * reads it: a caller who asked to refuse rather than send has to be told when
 * this stage could not answer, the same as the name stage tells it.
 */
export async function addNumberRedactions(
  map: RedactionMap,
  text: string,
  model: NumberModel | null,
  haystack: string,
  allow: AllowList = new Set(),
  opts?: {
    /** Read all of the text rather than only its tail, as the name stage
     *  does for a one-shot document (/v1/redact): it has no earlier turn,
     *  so a number three thousand characters from the end was never asked
     *  about, and the answer still said the stage had decided. */
    scanAll?: boolean;
  },
): Promise<{ redaction: RedactionMap; decided: boolean }> {
  const windows = opts?.scanAll ? numberWindows(text) : [text.slice(-NUMBER_WINDOW)];
  /* The map first, and the patterns only where numbers are left over
     (2026-11-08). Every pass ran findStructured again over text the
     structured stage had just read, almost all of whose finds are already in
     the map: on a 100 KB file of short records that second reading was a
     third of the time. Fewer claimed values can only leave more candidates,
     so a window with none against the map has none against both, and the
     answer is the same. */
  const known = Object.values(map);
  const withCandidates = windows
    .filter((w) => numberCandidates(w, known).length > 0)
    .map((w) => ({ w, claimed: [...findStructured(w).map((f) => f.value), ...known] }))
    .filter(({ w, claimed }) => numberCandidates(w, claimed).length > 0);
  // Past the cap the answer is undecided rather than quietly partial, the
  // same line the name stage draws.
  if (withCandidates.length > NUMBER_MAX_WINDOWS) return { redaction: map, decided: false };
  // At once rather than in turn, so a long document costs one budget of
  // waiting and not one per window.
  const verdicts = await Promise.all(withCandidates.map(({ w, claimed }) => detectSensitiveNumbers(w, claimed, model)));
  const decided = verdicts.every((v) => v.decided);
  const sensitive = [...new Set(verdicts.flatMap((v) => v.sensitive))];
  if (sensitive.length === 0) return { redaction: map, decided };
  const redaction = await addFoundRedactions(map, sensitive.map((value) => ({ kind: "govid" as const, value })), haystack, allow);
  return { redaction, decided };
}

/** How much of the text one question to the model covers. */
const NUMBER_WINDOW = 3000;
/** Carried between windows so a number and its words are whole in one. */
const NUMBER_WINDOW_OVERLAP = 120;
/** How many windows with unexplained numbers one call may ask about. */
const NUMBER_MAX_WINDOWS = 8;

function numberWindows(text: string): string[] {
  if (text.length <= NUMBER_WINDOW) return [text];
  const step = NUMBER_WINDOW - NUMBER_WINDOW_OVERLAP;
  const out: string[] = [];
  for (let i = 0; i < text.length; i += step) out.push(text.slice(i, i + NUMBER_WINDOW));
  return out;
}
