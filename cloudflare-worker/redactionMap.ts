/**
 * PII redaction, part one: the map.
 *
 * The shapes redaction has to understand, the pools the stand-ins are drawn
 * from, the allow list, and stage one — the values on the caller's own
 * profile, each given a fake to travel under. The other stages
 * (redactionStructured, redactionNames) add to the map this builds, and
 * redactionRestore applies it and takes it back out. redaction.ts re-exports
 * the lot, so callers import from one place as they always did.
 *
 * Split from one 2,000-line file on 2026-09-20. Nothing here changed but the
 * seams; the reasoning that was in the old header is now over the part it
 * belongs to.
 */

/**
 * The shapes redaction has to understand, defined here rather than in
 * worker.ts because the enclave needs them too and importing them from a
 * Cloudflare entrypoint to run inside AWS would be an odd dependency to
 * explain.
 */
export type Provider = "openai" | "anthropic" | "google";

export type ContentPart =
  | { type: "text"; text: string }
  | { type: "image_url"; image_url: { url: string } }
  | { type: "image"; source: { type: "base64"; media_type: string; data: string } };

export interface RequestMessage {
  role: string;
  content: string | ContentPart[];
}

/** base64url, for the redaction map that rides back on a response header —
 *  and, in the Worker, for reading JWTs. */
export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** SHA-256 as lowercase hex. Web Crypto, so it is the same function in a
 *  Worker, in Node and inside an enclave. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * A way to ask a model something. The one dependency this module cannot
 * satisfy itself.
 *
 * Returns the provider's raw envelope, whatever shape it came in — the parsing
 * below already handles the three Workers AI has used, and an implementation
 * that normalises before returning would be second-guessing it.
 *
 * Throwing or returning null both mean "could not tell", which is not the same
 * as finding no names. That distinction is what NameDetection.decided carries,
 * and it is the difference between a message with no names in it and a message
 * whose names are about to reach a provider in the clear.
 */
export type NameModel = (system: string, user: string, budgetMs: number) => Promise<unknown>;

// ============================================================
// PII redaction
// ============================================================

/**
 * Stage 1: the user's own name, email and phone number.
 *
 * The values arrive on `body.profile`, sent by the client with each request,
 * and are never written down here. The alternative — looking the profile up
 * from the uid — would mean a server-side table joining identity to the
 * requests that identity made, which is exactly the thing the product promises
 * does not exist. Sent per request, a real value lives only as long as the
 * request does.
 *
 * Realistic fake values, not [REDACTED]: a model reasons well about "Marcus
 * Whitfield" and badly about a placeholder, so the answer that comes back is
 * still an answer about a person. The fake→real map goes back to the client on
 * X-Redaction-Map and returns on the next turn, which is how one person keeps
 * one alias across a conversation without the Worker storing state.
 *
 * Order matters and is load-bearing: redaction happens BEFORE the cache key is
 * computed and before the R2 capture is teed off, restoration happens as the
 * last thing before the bytes reach the client. That way the cache and the
 * exchange log only ever hold aliases, and two users asking the same question
 * under different real names share one cached answer, each restoring it
 * through their own map.
 */

export const FAKE_FIRST = [
  "Marcus", "Naomi", "Curtis", "Priya", "Devon", "Ingrid", "Rafael", "Colette",
  "Theo", "Marisol", "Grant", "Yusuf", "Elena", "Damon", "Rosalind", "Adrian",
  "Farah", "Nolan", "Beatrix", "Emmett", "Solveig", "Julian", "Anika", "Desmond",
  "Lorna", "Casimir", "Tessa", "Gideon", "Noor", "Warren", "Sylvie", "Malik",
];

export const FAKE_LAST = [
  "Whitfield", "Okonkwo", "Barrera", "Lindqvist", "Ashworth", "Nakamura",
  "Delacroix", "Fontaine", "Hargrove", "Vasquez", "Ellingham", "Rahimi",
  "Sorensen", "Calloway", "Marchetti", "Bhattacharya", "Ferreira", "Radcliffe",
  "Nakashima", "Oyelaran", "Stillwell", "Kowalczyk", "Amberly", "Duarte",
  "Fairbanks", "Novotny", "Sinclair", "Aguilar", "Thornbury", "Mireles",
  "Halloran", "Petrov",
];

export const FAKE_EMAIL_DOMAINS = ["gmail.com", "outlook.com", "proton.me", "icloud.com"];
export const FAKE_AREA_CODES = ["212", "312", "415", "503", "617", "702", "813", "919"];

/** How many values one request can hide. Past it the rest go out as written,
 *  so this is set by what a request can afford, not by what a chat needs.
 *
 *  It was 64, shared with the ceiling below, and a court judgment on the Text
 *  Anonymization Benchmark (2026-10-05) names more people, places and numbers
 *  than that: everything after the sixty-fourth went to the model. Measured
 *  on 200,000 characters, the most /v1/redact accepts: 4,096 values are
 *  replaced in 1.3 s and restored in 0.4 s; 256 take 20 ms and 45 ms. A
 *  message, which is short, costs nothing either way. */
export const MAX_REDACTION_ENTRIES = 4096;

/** Ceilings on a client-supplied map. It is the client's own data, so this is
 *  not a trust boundary so much as a bound on what a buggy or hostile client
 *  can make this Worker do: a huge map means a long replace loop on every
 *  streamed chunk. A conversation's map past this is re-minted, not leaked —
 *  pickFake gives the same value the same stand-in — and the header that
 *  carries it back to the client holds about sixty anyway (redactionHeader). */
export const MAX_CARRIED_ENTRIES = 256;
export const MAX_REDACTION_VALUE_LENGTH = 200;

/** What follows a Chinese surname used on its own: 李老师, 王经理, 陈先生.
 *  The name finder reads a surname there, and the swap takes a one-character
 *  surname only there, so 李 is never taken out of 李子 (redactionRestore). 总
 *  only before what closes a form of address, not 总是, 总结, 总共. */
export const ZH_TITLE = String.raw`(?:总经理|總經理|副总|副總|总裁|總裁|董事长|董事長|老师|老師|先生|女士|小姐|太太|夫人|经理|經理|总监|總監|主任|主管|医生|醫生|大夫|护士|護士|律师|律師|教授|博士|校长|校長|院长|院長|局长|局長|处长|處長|科长|科長|部长|部長|老板|老闆|师傅|師傅|阿姨|叔叔|大爷|大爺|大妈|大媽|同学|同學|会计|會計|秘书|秘書|助理|书记|書記|(?:总|總)(?=[，。！？、,.!?：:\s]|说|說|让|讓|您|你|好|吗|嗎|呢|的|和|跟|在|也|$))`;

/** fake → real. Kept in this direction because that is the direction the hot
 *  path needs: restoration runs over every chunk of every response, redaction
 *  runs once per request. */
export type RedactionMap = Record<string, string>;

/**
 * Words the person has told us to leave alone.
 *
 * The detector is good and it is not perfect, and it is wrong in two
 * directions rather than one. A miss is answered by the never-send list, which
 * adds a term the detector did not find. This answers the other half: a term
 * it found that was never personal in the first place — a company that shares
 * a surname, a product, a street that is also a name — swapped out of every
 * message until the answers stopped making sense.
 *
 * Exact matches only, case-insensitive. Deliberately not substring: allowing
 * "Chen" must not also allow "Sarah Chen", because the two are different
 * facts about a person and only one of them was agreed to. The cost is that
 * somebody who wants both has to say both, which is the safe direction for
 * this particular mistake to run in.
 */
export type AllowList = Set<string>;

/** Normalises whatever arrived over the wire into a set that can be checked.
 *  Hostile or malformed input becomes an empty set rather than an error: an
 *  unreadable allow list must fail towards redacting, never away from it. */
export function parseAllowList(raw: unknown): AllowList {
  if (!Array.isArray(raw)) return new Set();
  const out = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    const term = entry.trim().toLowerCase();
    // One character is a stray selection, and honouring it would exempt a
    // letter that appears inside half the values on the page.
    if (term.length < 2 || term.length > 200) continue;
    out.add(term);
    if (out.size >= 200) break;
  }
  return out;
}

/** Whether this value is one the person said may go as written. */
export function isAllowed(value: string, allow: AllowList): boolean {
  return allow.size > 0 && allow.has(value.trim().toLowerCase());
}

/**
 * A real value is substituted into a provider's SSE stream on the way back,
 * and that stream is JSON. A value carrying a quote, a backslash or a control
 * character would be spliced in unescaped and break the frame the client is
 * parsing, so such values are simply not redacted — a name that renders
 * correctly matters less than a response that parses.
 */
export function isSubstitutable(value: string): boolean {
  return value.length > 0
    && value.length <= MAX_REDACTION_VALUE_LENGTH
    && !/["\\]/.test(value)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

export function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Reads the map the client sent back from the previous turn, dropping
 *  anything malformed rather than rejecting the request — a bad map should
 *  cost the user their aliasing, not their message. */
export function parseRedactionMap(raw: unknown): RedactionMap {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: RedactionMap = {};
  for (const [fake, real] of Object.entries(raw as Record<string, unknown>)) {
    if (Object.keys(out).length >= MAX_CARRIED_ENTRIES) break;
    if (typeof real !== "string") continue;
    if (!isSubstitutable(fake) || !isSubstitutable(real)) continue;
    out[fake] = real;
  }
  return out;
}

/**
 * Picks a fake value that is stable for a given real value, unused in this
 * conversation, and — the part that is easy to miss — absent from the text
 * being sent. If the user happens to write about a real Marcus Whitfield and
 * we alias them to that same name, restoration afterwards would rewrite the
 * real Marcus into the user. Probing past a collision costs nothing here and
 * removes that whole class of corruption.
 */
/* The haystack in lower case, kept for the next call. pickFake runs once per
   value with the same haystack, and lowering 200,000 characters four thousand
   times was most of four seconds. */
let lastHaystack = "";
let lastLowered = "";
let lastIncludes = new Map<string, boolean>();
export function lowered(haystack: string): string {
  if (haystack !== lastHaystack) {
    lastHaystack = haystack;
    lastLowered = haystack.toLowerCase();
    lastIncludes = new Map();
  }
  return lastLowered;
}
/* Whether a candidate stand-in is already in the haystack, remembered for it.
   The stand-in lists are a few hundred strings, tried again for every value:
   a 3,000-row export searched 170,000 characters for the same names tens of
   thousands of times (2026-10-08). */
function inHaystack(haystack: string, candidate: string): boolean {
  const lower = lowered(haystack);
  const key = candidate.toLowerCase();
  let hit = lastIncludes.get(key);
  if (hit === undefined) {
    hit = lower.includes(key);
    lastIncludes.set(key, hit);
  }
  return hit;
}

/*
 * A secret mixed into every stand-in, drawn once per process and never sent
 * anywhere.
 *
 * Stand-ins used to be a plain hash of the value. Anyone holding this code
 * who saw only the redacted text (the model provider, say) could hash a list
 * of likely names, towns or numbers, see which landed on "Megan Ross", and
 * narrow her back to a handful of real people. With a salt they cannot
 * compute, the stand-in says nothing about the value.
 *
 * Per process, not per request: within one Worker isolate or one enclave the
 * same value still gets the same stand-in, and across them the map the client
 * sends back keeps a conversation consistent, as it always has. Drawn on
 * first use because Workers refuse random numbers at global scope.
 */
let standInSalt = "";
/** Tests only: set the salt, to show that it decides the stand-ins. */
export function setStandInSaltForTests(value: string): void {
  standInSalt = value;
}
function salt(): string {
  if (!standInSalt) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    standInSalt = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  return standInSalt;
}

export async function pickFake(
  seed: string,
  taken: Set<string>,
  haystack: string,
  build: (i: number, hex: string) => string,
  /** Refuse a stand-in that shares a word with the value. For names,
   *  organisations and places. */
  avoidOwnWords = false,
  /** How many candidates to try before a placeholder. 0 when the caller
   *  knows its whole space is taken. */
  tries = 1024,
): Promise<string | null> {
  const hex = await sha256Hex(`${salt()}\u0000${seed.toLowerCase()}`);
  /*
   * Enough attempts to reach the whole of a builder's candidate space.
   *
   * This was sixty-four, which was a number rather than a decision: the name
   * builder's space is a thirty-two by thirty-two grid, and stopping at
   * sixty-four meant most of it was never tried. Running out is not a soft
   * failure here — the caller has nothing to substitute and sends the real
   * value — so the loop has to be at least as large as what the builder can
   * produce. Each attempt is a string and two lookups; the hash, which is the
   * only real cost, is computed once above.
   */
  // In any case: restoreText puts back the all-small and all-capital forms of
  // a stand-in too, so a stand-in "Grant" in a message that says "grant"
  // would turn the person's own word into somebody's name on the way back.
  lowered(haystack);
  // Nor a word of the value it stands in for. "Marta Kowalczyk" drew "Nolan
  // Kowalczyk" — the stand-in lists hold common surnames, hers among them —
  // and her surname went to the model inside her own stand-in. Found once
  // stand-ins were salted and a test met a salt that drew it (2026-10-08);
  // before, it happened silently to whichever names hashed onto their own.
  // Words only, for names, organisations and places: an IPv4 stand-in keeps
  // its range ("10.") and a link its scheme on purpose.
  const own = new Set(avoidOwnWords ? seed.toLowerCase().split("|")[0].split(/[^\p{L}]+/u).filter((w) => w.length >= 2) : []);
  for (let i = 0; i < tries; i++) {
    const candidate = build(i, hex);
    if (taken.has(candidate)) continue;
    if (inHaystack(haystack, candidate)) continue;
    if (own.size && candidate.toLowerCase().split(/[^\p{L}\p{N}]+/u).some((w) => own.has(w))) continue;
    return candidate;
  }
  /* Every candidate taken or already in the text. Returning nothing sent the
     real value, so a document with enough people in it to use up the grid
     leaked the rest by name. A plain placeholder is a worse stand-in and a
     far better outcome: the model reads that something was hidden, and the
     reply restores it like any other. */
  // Counted on from the last one this set of stand-ins took, not from one
  // each time: past the grid, a list of five thousand names counted up
  // through every placeholder already used for each new one.
  for (let n = nextPlaceholder.get(taken) ?? 1; ; n++) {
    const placeholder = `[hidden ${n}]`;
    if (!taken.has(placeholder) && !inHaystack(haystack, placeholder)) {
      nextPlaceholder.set(taken, n + 1);
      return placeholder;
    }
  }
}
const nextPlaceholder = new WeakMap<Set<string>, number>();

/**
 * Extends `existing` with aliases for any profile value it does not already
 * cover. Existing entries are never re-minted: that is what keeps one person
 * pointing at one alias for the length of a conversation.
 */
export async function buildRedactionMap(
  profile: unknown,
  existing: RedactionMap,
  haystack: string,
  /**
   * Values the person has said may be sent as written. See AllowList.
   *
   * It applies to their own profile too, and that is the point of putting it
   * here rather than only on the later stages: somebody whose own first name
   * is also an ordinary word gets it swapped out of every message they write,
   * and "stop hiding my own name" is a request they are entitled to make.
   *
   * What it deliberately cannot override is `existing` — the never-send map
   * that arrived with the request. A term in both lists is a person saying
   * hide this and send this about the same word, and hide wins: it is the
   * instruction with a consequence if we get it wrong.
   */
  allow: AllowList = new Set(),
): Promise<RedactionMap> {
  if (!profile || typeof profile !== "object") return existing;
  const { name, email, phone } = profile as { name?: unknown; email?: unknown; phone?: unknown };

  const map: RedactionMap = { ...existing };
  const taken = new Set(Object.keys(map));
  const covered = new Set(Object.values(map).map((v) => v.toLowerCase()));

  const add = (fake: string, real: string) => {
    map[fake] = real;
    taken.add(fake);
    covered.add(real.toLowerCase());
  };
  const wanted = (real: unknown): real is string =>
    typeof real === "string"
    && isSubstitutable(real.trim())
    && real.trim().length >= 3
    && !covered.has(real.trim().toLowerCase())
    && !isAllowed(real, allow)
    && Object.keys(map).length < MAX_REDACTION_ENTRIES;

  let fakeFirst = "";
  let fakeLast = "";

  if (wanted(name)) {
    const real = name.trim();
    const parts = real.split(/\s+/).filter((p) => p.length >= 3);
    const first = await pickFake(real, taken, haystack, (i, hex) =>
      FAKE_FIRST[(parseInt(hex.slice(0, 6), 16) + i) % FAKE_FIRST.length], true);
    const last = await pickFake(`${real}|last`, taken, haystack, (i, hex) =>
      FAKE_LAST[(parseInt(hex.slice(6, 12), 16) + i) % FAKE_LAST.length], true);
    if (first && last) {
      fakeFirst = first;
      fakeLast = last;
      if (parts.length >= 2) {
        // The full name first — the apply loop runs longest-real-first, so
        // "Herbert Perryman" is consumed before "Herbert" can match inside it.
        //
        // Each part is checked against the allow list on its own, because a
        // person can reasonably allow one and not the other: a surname that is
        // also a company, a first name that is also a common word. `wanted`
        // above only cleared the whole string.
        add(`${first} ${last}`, real);
        if (!isAllowed(parts[0], allow)) add(first, parts[0]);
        if (!isAllowed(parts[parts.length - 1], allow)) add(last, parts[parts.length - 1]);
      } else {
        add(first, real);
      }
    }
  }

  if (wanted(email)) {
    const real = email.trim();
    const fake = await pickFake(real, taken, haystack, (i, hex) => {
      const local = fakeFirst && fakeLast
        ? `${fakeFirst}.${fakeLast}`.toLowerCase()
        : `user${hex.slice(0, 4)}`;
      const domain = FAKE_EMAIL_DOMAINS[(parseInt(hex.slice(12, 16), 16) + i) % FAKE_EMAIL_DOMAINS.length];
      return `${local}${i === 0 ? "" : i}@${domain}`;
    });
    if (fake) add(fake, real);
  }

  if (wanted(phone)) {
    const real = phone.trim();
    const fake = await pickFake(real, taken, haystack, (i, hex) => {
      const area = FAKE_AREA_CODES[(parseInt(hex.slice(16, 20), 16) + i) % FAKE_AREA_CODES.length];
      const mid = String((parseInt(hex.slice(20, 26), 16) + i) % 900 + 100);
      const end = String(parseInt(hex.slice(26, 32), 16) % 9000 + 1000);
      return `(${area}) ${mid}-${end}`;
    });
    if (fake) add(fake, real);
  }

  return map;
}
