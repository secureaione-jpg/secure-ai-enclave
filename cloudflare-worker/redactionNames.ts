/**
 * PII redaction, part three: the names of people the user knows.
 *
 * A name has no shape, so this stage asks a model — through the one injected
 * call, NameModel — with a prompt and a reply parser that are tuned rather
 * than obvious, and a cue-based fallback for when the model is slow or
 * absent. The word lists keep everyday capitalised words out of the map.
 */

import { FAKE_FIRST, FAKE_LAST, MAX_REDACTION_ENTRIES, isAllowed, isSubstitutable, pickFake } from "./redactionMap.js";
import { standInFirstsFor } from "./redactionNameGender.js";
import type { AllowList, NameModel, RedactionMap } from "./redactionMap.js";
import {
  COMMON_CAPITALISED, isAcronym, isDateWords, isCommonLowercaseWord, isEverydayPhrase, isNotAPerson, isTownNamingAPerson,
  isCaseName, isCoordinatedName, isFamousPersonHere, isMonthAsName, isOrdinaryWordHere, isPetName, isPlainlyNotAName, isSentenceFragment, isSpeciesName, isTechnicalTerm, isWordOfAnUncasedScript, mightContainNames, namesFromCues,
} from "./redactionNameWords.js";
import { isBareTitle, isForeignCommonWords, isGreetingHere, isNounCompound, withoutGreeting, withoutTitle } from "./redactionNameWordsIntl.js";
import { placesFrom } from "./redactionMedical.js";

/**
 * Stage 3: the names of people the user knows.
 *
 * Stages 1 and 2 only catch what has a shape — a profile field, an address, a
 * run of digits. A name has no shape. "Sarah is my landlord" leaks exactly as
 * much as a phone number and matches no pattern at all, so this is the stage
 * that needs a model.
 *
 * The model is Workers AI, which runs inside Cloudflare. Sending the text to a
 * third-party model to work out what to hide from third-party models would
 * defeat the entire feature, so this is not a preference — it is the only
 * placement that is coherent.
 *
 * Three constraints shape everything below, and they pull against each other:
 *
 *   Latency. This sits in front of every message, and a redaction pass the
 *   user can feel is one they will turn off. So it does not run at all unless
 *   a cheap local scan finds something plausibly a name, and it is raced
 *   against a timeout — a slow inference is abandoned and the request goes on
 *   without stage 3, which costs coverage on one message rather than making
 *   the product feel broken.
 *
 *   Over-redaction. Renaming Abraham Lincoln does not protect anybody; it
 *   produces an answer about the wrong person and the user cannot tell why.
 *   Cloudflare has no NER model, only text generation, so the distinction has
 *   to be drawn in the prompt: private individuals yes, public and historical
 *   figures no. A small model is genuinely capable of that judgement, and it
 *   is the right judgement to be asking for — the question is not "is this a
 *   name" but "is this a name that identifies our user's life".
 *
 *   Trust. Whatever comes back is text produced by a model from text the user
 *   controls, which makes it untrusted input twice over. Nothing is aliased
 *   unless it appears verbatim in what the user actually wrote.
 */

/** Small and fast on purpose — this is a front-of-request cost. */

/** Abandoned past this. Coverage on one message is worth less than every
 *  message feeling slow. */
const NER_TIMEOUT_MS = 1100;

/**
 * A second, shorter go when the first produced nothing usable.
 *
 * Only on failure — a timeout, an unreachable model, or output that will not
 * parse. An empty array is a real answer ("no names here") and is the common
 * case, so retrying it would double the bill and the latency of most messages
 * to re-learn what we already know.
 *
 * Shorter than the first because the point is to survive a slow cold start,
 * not to wait twice. Worst case is 1800ms against the 1200ms this replaced,
 * and only on the messages that were already going to fail open.
 */
const NER_RETRY_TIMEOUT_MS = 700;

/**
 * The same two clocks for a caller reading a whole document (scanAll): no
 * chat to keep quick, and a caller that asked to be told when a name was not
 * checked would rather wait a few seconds than be told so.
 *
 * Measured against the live API, 2026-09-28: at six requests at once the model
 * queued past 1100ms, both tries timed out, and 84 of 100 documents came back
 * with names_decided false. One at a time, none did.
 */
const NER_ONESHOT_TIMEOUT_MS = 4000;
const NER_ONESHOT_RETRY_MS = 2500;

/** How much text the model reads at once.
 *
 *  For a chat, only the tail is scanned: names introduced earlier are already
 *  in the map and stay there, so re-scanning the whole history would grow the
 *  cost of a long conversation without adding anything.
 *
 *  That reasoning is about a conversation, and it was being applied to every
 *  caller. A one-shot call — /v1/redact on a document, or an agent action —
 *  has no earlier turn and no prior map, so "already in the map" is false and
 *  a name three thousand characters from the end was simply never read. It
 *  came back unredacted with names_decided true. Those callers pass
 *  scanAll and get every window. */
const NER_MAX_CHARS = 2000;

/** Carried between windows so a name lying across a boundary is whole in one
 *  of them. Long enough for any name and its cue. */
const NER_WINDOW_OVERLAP = 120;

/** How many windows may reach the model in one call.
 *
 *  /v1/redact accepts 200,000 characters, which is a hundred windows and a
 *  hundred inferences if every one of them looks name-shaped. The gate below
 *  means most windows of an ordinary document never get that far, and this
 *  bounds what happens when they do: past it the answer is reported as
 *  undecided rather than quietly partial, which is the distinction this
 *  whole file exists to keep.
 *
 *  It was 8 until 2026-10-07, about 15,000 characters of name-bearing text:
 *  a long contract or judgment had every name after page eight left
 *  unread. A window takes about 0.6 s on two CPUs (TAB's longest document,
 *  measured), so 64 of them would not fit the Worker's 30 s wait for the
 *  enclave either; the clock below is what actually bounds a document, and
 *  this only bounds the worst case. */
const NER_MAX_WINDOWS = 64;

/** How many windows one chat turn may read. A pasted thread of twenty
 *  thousand characters is ten windows and about as many seconds; past this
 *  the rest is reported as undecided, as a document is. */
const NER_MAX_CHAT_WINDOWS = 8;

/** A document stops starting new windows once this much time has gone.
 *  The Worker abandons the enclave at 30 s; a window started just before
 *  the budget can take both tries (4 s + 2.5 s), which still lands inside.
 *  What is left unread is reported as undecided, as before. */
const NER_ONESHOT_BUDGET_MS = 18_000;

/** How many names one window may contribute.
 *
 *  It bounds the alias map, which is the thing that has to stay consistent
 *  for the life of a conversation. Reaching it used to end the loop and
 *  return sixteen names as though they were all of them — a document with
 *  twenty people in it had four of them redacted by nobody and the answer
 *  said the name check had decided. The cap stays; what changes is that
 *  hitting it is now reported, the same as any other half-finished read.
 *
 *  Sixteen was too few for a document. A court judgment lists its bench in
 *  one paragraph — "Mr R. Ryssdal, President, Mr F. Matscher, Mrs E. Palm…"
 *  — and on the Text Anonymization Benchmark (2026-10-05) 8 of 122 windows
 *  held more than sixteen people, up to 31; everyone after the sixteenth
 *  went out as written. The map's own ceiling (MAX_REDACTION_ENTRIES) still
 *  bounds the whole, so this one only has to stop a window flooding it. */
const NER_MAX_NAMES = 32;

/** The text, in overlapping windows, oldest first. */
function nameWindows(text: string): string[] {
  if (text.length <= NER_MAX_CHARS) return [text];
  const step = NER_MAX_CHARS - NER_WINDOW_OVERLAP;
  const out: string[] = [];
  for (let i = 0; i < text.length; i += step) out.push(text.slice(i, i + NER_MAX_CHARS));
  return out;
}

/**
 * Asks Workers AI which names in the text belong to private individuals.
 *
 * Returns only names that appear verbatim in `text`. The model is being fed
 * user-controlled text, so everything it hands back is treated as a suggestion
 * to be checked, never as an instruction and never as a value in its own
 * right — a "name" that is not actually present is a hallucination, and
 * aliasing it would rewrite something the user never wrote.
 */
/**
 * What the name stage concluded, as distinct from what it found.
 *
 * "No names" and "could not tell" are the same empty array and mean opposite
 * things: one is a message with nothing to redact, the other is a message
 * whose names are about to reach the provider in the clear. Every caller that
 * cares about the promise has to be able to tell them apart, so the outcome is
 * returned rather than inferred from the length of the list.
 */
export type NameDetection = {
  names: string[];
  /** False only when the model could not be consulted or would not parse. */
  decided: boolean;
  /** Companies and other organisations, when the caller asked for them
   *  (opts.organisations) and the model tags them. The enclave's two NER
   *  models do; Workers AI does not, and leaves this empty. */
  organisations?: string[];
  /** Places the model tagged, when the caller asked (opts.places, medical
   *  mode): towns and the like, states and countries already left out. */
  places?: string[];
};

/* Articles a tagger takes into an organisation: "la Commission", "the BBC". */
const ORG_ARTICLES = new Set([
  "the", "la", "le", "les", "l'", "l’", "el", "los", "las", "il", "lo", "gli", "i", "der", "die", "das", "des", "dem", "den",
  "o", "a", "os", "as", "do", "da", "dos", "das", "del", "de", "du", "una", "un", "une", "ein", "eine",
]);

/* Words of a public body, in the six languages of the field suites. A court,
   a ministry, the Commission or a directive identifies nobody, the same
   reason a president's name is left as written; the private ones (a
   company, a firm, a small charity) are what this setting is for. MAPA
   validation, 2026-10-06: "la Commission", "the Council", "la High Court",
   "la Directiva", "Parlement européen" were most of what it hid. */
const PUBLIC_BODY_WORDS = new Set([
  // en
  "court", "courts", "tribunal", "commission", "council", "parliament", "government", "ministry", "minister", "department",
  "directive", "regulation", "union", "assembly", "senate", "congress", "agency", "authority", "ombudsman", "state", "states",
  "republic", "kingdom", "police", "constabulary", "prosecutor", "registry", "bench", "chamber", "treaty",
  // fr
  "cour", "conseil", "parlement", "gouvernement", "ministère", "directive", "règlement", "république", "royaume", "assemblée",
  "sénat", "parquet", "greffe", "chambre", "traité", "autorité", "agence", "préfecture", "mairie",
  // de
  "gericht", "gerichtshof", "kommission", "rat", "parlament", "regierung", "ministerium", "richtlinie", "verordnung", "bund",
  "bundesrepublik", "republik", "königreich", "behörde", "amt", "staatsanwaltschaft", "kammer", "senat", "landtag", "bundestag",
  "bundesrat", "vertrag", "union",
  // es
  "corte", "tribunal", "comisión", "consejo", "parlamento", "gobierno", "ministerio", "directiva", "reglamento", "república",
  "reino", "fiscalía", "audiencia", "juzgado", "sala", "cámara", "tratado", "agencia", "autoridad", "unión", "derecho",
  // it
  "corte", "tribunale", "commissione", "consiglio", "parlamento", "governo", "ministero", "direttiva", "regolamento",
  "repubblica", "regno", "procura", "camera", "trattato", "agenzia", "autorità", "unione",
  // pt
  "tribunal", "comissão", "conselho", "parlamento", "governo", "ministério", "diretiva", "regulamento", "república", "reino",
  "câmara", "tratado", "agência", "autoridade", "união", "supremo",
  // A state, a community of states, a committee or a section of a court, in all six.
  "estado", "estados", "stato", "stati", "état", "états", "staat", "staaten", "ministro", "administración", "administração",
  "community", "communauté", "gemeinschaft", "comunidad", "comunità", "comunidade", "committee", "comité", "comitato",
  "ausschuss", "section", "sección", "secção", "sezione", "garda",
  // Offices of state and the forces, and the law itself: "Home Office", "the
  // Board", "Newcastle upon Tyne Justices", "Constitutional Law", "Rules of
  // Court" (TAB validation, 2026-10-06).
  "office", "board", "directorate", "army", "navy", "municipality", "secretary", "justices", "nations", "law", "laws",
  "rules", "act", "code", "convention", "constitution",
  "european", "europäische", "europäischen", "européen", "européenne", "europeo", "europea", "europeu", "europeia",
]);

/* A team, a role or a document's title, which a tagger reads as an
   organisation: "Incident Response Team", "Data Protection Officer", "Lint
   Report", "Mortgage Deed", "Financial Services Application Form" (Gretel
   and Nemotron practice rows, 2026-10-06). None is a company's name. */
const NOT_AN_ORG_WORDS = new Set([
  "team", "officer", "unit", "division", "desk", "resources", "report", "form", "contract", "document", "deed", "agreement",
  "application", "receipt", "policy", "plan", "manual", "guide", "requirements", "mortgagor", "mortgagee", "licensor", "licensee",
]);

/* A word a tagger's span ends on that no name ends on: "Rules of", "SENTENZA DEL". */
const ORG_TRAILING = new Set(["of", "and", "the", "for", "de", "del", "della", "des", "der", "di", "da", "do", "du", "e", "et", "und", "y"]);

/* Bodies known by their letters. Not every short acronym: "BBC" is a company. */
const PUBLIC_BODY_ACRONYMS = new Set([
  "EU", "UE", "EG", "CE", "EC", "EEC", "CEE", "EWG", "UN", "ONU", "UNO", "WTO", "OMC", "TFEU", "TFUE", "TEU", "TUE", "AEUV",
  "EUV", "ECHR", "CEDH", "EMRK", "EGMR", "TEDH", "CEDU", "ECJ", "CJEU", "CJUE", "EuGH", "TJUE", "NATO", "OTAN", "OECD",
  "OCDE", "IMF", "FMI", "WHO", "OMS", "UNESCO", "ECB", "BCE", "EZB", "EIB", "BEI", "EP", "PE", "GATT", "UNHCR", "HCR",
  // The Official Journal, which every judgment cites: OJ, JO, ABl., GU, DO.
  "OJ", "JO", "ABl", "GU", "DO", "GURI", "BOE",
]);

/** Not an organisation at all: a team, a role, a document's title. Never
 *  hidden, whatever the setting. */
function isNotAnOrg(org: string): boolean {
  return org.split(/\s+/).some((w) => NOT_AN_ORG_WORDS.has(w.toLowerCase().replace(/[.,;:()]/g, "")));
}

/** Which organisations the caller asked to hide. true: companies and other
 *  private bodies. "all": public bodies too (courts, ministries, states),
 *  for a document anonymised in full, as a court publishing a judgment
 *  does. The Text Anonymization Benchmark marks them all. */
export type OrganisationSetting = boolean | "all";

/** A public body (a court, a ministry, an EU institution, a statute), or
 *  no organisation at all (a team, a role, a document's title). Either way,
 *  not hidden by the organisations setting. */
export function isPublicBody(org: string): boolean {
  if (PUBLIC_BODY_ACRONYMS.has(org)) return true;
  // A company says so, whatever else it is called: "Union Bank plc".
  if (/(?:^|\s)(?:Ltd|Limited|Inc|plc|PLC|LLC|LLP|Corp|GmbH|AG|SA|S\.A\.|SL|SpA|Srl|SARL|SAS|BV|NV|Lda|KG|Co\.?)$/.test(org)) return false;
  return org.split(/\s+/).some((w) => {
    const lower = w.toLowerCase().replace(/[.,;:()]/g, "");
    if (PUBLIC_BODY_WORDS.has(lower) || PUBLIC_BODY_ACRONYMS.has(w) || NOT_AN_ORG_WORDS.has(lower)) return true;
    // German declines them: "des Rates", "des Europäischen Parlaments".
    if (/^\p{Lu}/u.test(w) && /e?s$/.test(lower) && PUBLIC_BODY_WORDS.has(lower.replace(/e?s$/, ""))) return true;
    // German writes its bodies as one word: "Bundesverwaltungsgericht".
    return lower.length > 8 && /(?:gerichts?|gerichtshofs?|ministeriums?|regierung|kommission|behörden?|parlaments?|gemeinschaft|ausschuss(?:es)?|gesetzgeber)$/.test(lower);
  });
}

/** The organisations a model reply carries beside its people, checked the
 *  way a name is: verbatim in the text, not an everyday word or a date, and
 *  safe to splice back into a stream. */
export function organisationsFrom(raw: unknown, text: string, setting: OrganisationSetting = true): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const candidate of raw) {
    if (typeof candidate !== "string") continue;
    // Less a leading article, which the tagger took and the name does not
    // need: "la High Court" is "High Court", and "la" alone is nothing.
    const words = candidate.trim().split(/\s+/);
    while (words.length && ORG_ARTICLES.has(words[0].toLowerCase())) words.shift();
    while (words.length && ORG_TRAILING.has(words[words.length - 1].toLowerCase())) words.pop();
    const org = words.join(" ");
    if (org.length < 2 || !text.includes(org)) continue;
    // An organisation is a proper name: "sentencia", "reparto" and "una" are not.
    if (!/^[\p{Lu}\d]/u.test(org)) continue;
    if (setting === "all" ? isNotAnOrg(org) : isPublicBody(org)) continue;
    // One word is held to what a one-word name is: not an ordinary word of
    // this text or of the languages the models read ("Sentencia",
    // "Klägerin", "En", "General").
    if (!/\s/.test(org) && (isForeignCommonWords(org) || isOrdinaryWordHere(org, text) || isNotAPerson(org) || isSentenceFragment(org))) continue;
    // Nor a dictionary word with a capital ("Criminal", "Storage", "Prime"),
    // nor a German noun made from a verb or an adjective ("Notwendigkeit",
    // "Interimsüberprüfung"). A brand that is a word ("Shell") is passed
    // over too; it is a public name, and hiding it is what this costs.
    if (!/\s/.test(org) && (isCommonLowercaseWord(org.toLowerCase()) || /\p{Ll}(?:ungen|ung|keit|heit|keiten|heiten)$/u.test(org))) continue;
    if (COMMON_CAPITALISED.has(org) || isDateWords(org) || isCommonLowercaseWord(org)) continue;
    if (!isSubstitutable(org) || out.includes(org)) continue;
    out.push(org);
    if (out.length >= NER_MAX_NAMES) break;
  }
  return out;
}

export async function detectPersonalNames(
  text: string,
  model: NameModel | null,
  opts?: {
    /** Read all of the text rather than only its tail. For callers with no
     *  earlier turn to have caught the rest — a document, an agent action. */
    scanAll?: boolean;
    /** Also return the organisations the model tagged. Off by default:
     *  a company name is usually what the question is about. "all" keeps
     *  public bodies too. */
    organisations?: OrganisationSetting;
    /** Also return the places the model tagged (medical mode). */
    places?: boolean;
    /** How many characters at the end of the text are this turn's — the
     *  latest message. A chat reads the tail window because earlier turns'
     *  names are already in the map; that is false for the earlier part of
     *  a long message pasted this turn, whose names were never read (leak
     *  hunt, 2026-11-14). Every window of the latest message is read. */
    newChars?: number;
  },
): Promise<NameDetection> {
  /*
   * No model at all is a deployment without one, and it must not block an
   * ordinary message — the structured stages still ran, and every caller that
   * does not ask about `decided` is unaffected by what this returns.
   *
   * But it is not a decision, and it used to claim to be one. The single
   * caller that reads this field is strict redaction, whose whole purpose is
   * to refuse rather than send when the name stage could not answer — and
   * "there is no name stage" is the strongest possible version of could not
   * answer. Reporting it as decided-with-no-names meant a request that had
   * explicitly asked to be refused sailed through instead, with every name in
   * it, and was told the check had run. The enclave's own server already
   * refuses on exactly this ground; the Worker now agrees with it.
   */
  // Found first and merged into every path below, including the ones that
  // never reach the model. A name the sentence introduced by hand is not
  // contingent on an inference succeeding.
  // Never a title by itself, which a cue can leave behind: "Mr" out of "our
  // agent Mr. Hasan" (realistic5, 2026-10-31).
  // Nor an ordinary word: "Saya, Norazlina", "olen Tuomas" and "אני דנה" took
  // the word in front, and nothing after the model reads what a cue found.
  const cued = namesFromCues(text).filter((n) => !isBareTitle(n) && !isForeignCommonWords(n) && !isWordOfAnUncasedScript(n, text));
  const withCues =(names: string[]) => [...cued, ...names.filter((n) => !cued.includes(n))];

  if (!model) return { names: cued, decided: false };

  /* One window for a chat — the tail, as before — or all of them for a
     caller that has no earlier turn. The gate drops the windows with
     nothing name-shaped in them, which is what stops an ordinary document
     paying for inference on every page. */
  const fresh = Math.min(text.length, Math.max(NER_MAX_CHARS, (opts?.newChars ?? 0) + NER_WINDOW_OVERLAP));
  const candidates = (opts?.scanAll ? nameWindows(text) : nameWindows(text.slice(-fresh)))
    .filter((w) => mightContainNames(w));

  // The gate said there is nothing name-shaped here. That is a decision, not a
  // failure: it is exactly what stops most messages paying for inference.
  if (candidates.length === 0) return { names: cued, decided: true };

  // Worked examples, not just rules. Measured against a bench of sixteen
  // messages, the rules-only version of this prompt scored 3/16 — it returned
  // [] for "Draft a note to Sarah Chen", which is the single most obvious case
  // there is. The same rules with six worked examples score 13/16. A 3B model
  // does not reliably generalise a description of a task; it copies a shape.
  //
  // The last line matters more than it looks: without it the model answers the
  // user's message instead of extracting from it — writing the haiku it was
  // asked for. That failure is harmless here (unparseable output redacts
  // nothing) but it is the difference between a stage that works and one that
  // silently does nothing on imperative messages.
  const system = [
    "You find personal names in a message and return them as JSON.",
    "",
    "Rules:",
    "- Output ONLY a JSON array of strings. Nothing else.",
    "- Include ordinary people: friends, family, colleagues, clients, neighbours, a landlord, a doctor.",
    "- Exclude anyone famous: politicians, historical figures, scientists, authors, musicians, athletes, celebrities, fictional characters.",
    "- Exclude anything that is not a person: companies, restaurants, brands, products, cities, towns, countries, streets, days, months.",
    "- Exclude technology: hardware, software, protocols, services and security terms, however they are capitalised.",
    "- Exclude food, dishes, animals and everyday objects, however they are capitalised.",
    "- Exclude the names of pets and animals.",
    "- Copy each name exactly as written in the message.",
    "",
    "Examples:",
    'Message: "Draft a note to Sarah Chen about the deposit."',
    'Output: ["Sarah Chen"]',
    'Message: "When did Abraham Lincoln give the Gettysburg Address?"',
    "Output: []",
    'Message: "Summarise the theory of relativity by Albert Einstein."',
    "Output: []",
    'Message: "Tell my neighbour Tom Bradley to move his car"',
    'Output: ["Tom Bradley"]',
    'Message: "Book a table at Nobu for Friday."',
    "Output: []",
    'Message: "Compare Apple and Microsoft revenue."',
    "Output: []",
    // Seen live on 2026-09-20. A user asking how their own data is protected
    // had "Secure Enclave" and "an aws" returned as people, and was answered
    // about two strangers — the one conversation where a stand-in destroys
    // the product's credibility rather than merely the sentence.
    'Message: "Do you run on an aws Nitro Enclave or the Secure Enclave?"',
    "Output: []",
    // Reported from testing. A food phrase came back as a person and was
    // swapped for somebody's name, so the sentence the user typed stopped
    // being the sentence they got an answer about. The guard list below
    // catches this pair as well; a 3B model is shown the shape, not told it.
    'Message: "What is the best way to cook a Hot Dog?"',
    "Output: []",
    // Seen live on 2026-09-15: "my dog is called Biscuit" sent the provider a
    // dog called Damon. A pet's name identifies nobody.
    'Message: "Remember that my dog is called Biscuit."',
    "Output: []",
    // A city sitting next to an address is the case that failed in production:
    // "London" came back as a person and was replaced with a first name. The
    // rule above already said places; a 3B model needs it shown, not stated.
    'Message: "I live at 42 Maple Street, London SW1A 1AA."',
    "Output: []",
    'Message: "what is the capital of france"',
    "Output: []",
    // Self-introduction. Every other example here is a name in the third
    // person, and the model treated a first-person one as a different task.
    // Matched literally by the cue pass as well, since this is the sentence
    // that must not depend on a 3B model having a good day.
    'Message: "My name is Marta Kowalczyk. Greet me by name."',
    'Output: ["Marta Kowalczyk"]',
    "",
    "If the message is a request or a question, do not answer it. Only list names.",
  ].join("\n");

  /**
   * One go at the model. Returns null when it could not be consulted or would
   * not parse — which is the case the retry above exists for — and an array
   * when it answered, including the empty array that means "no names".
   */
  /* Set when a window had more names than it may return. Not an error and
     not a failure to answer — the model answered, and the answer was
     trimmed — but it does mean the names that came back are not all of
     them, which is what a caller reading `decided` is asking about. */
  let capped = false;
  const orgsFound: string[] = [];
  const placesFound: string[] = [];

  const attempt = async (excerpt: string, budgetMs: number): Promise<string[] | null> => {
    try {
      const result = await Promise.race([
        model(system, excerpt, budgetMs),
        new Promise((resolve) => setTimeout(() => resolve(null), budgetMs)),
      ]) as { response?: unknown; choices?: { message?: { content?: unknown } }[] } | null;

      // Three shapes, and getting this wrong is silent. Workers AI's original
      // envelope is { response }, the chat models now answer OpenAI-style with
      // { choices: [{ message: { content } }] }, and — the one that cost real
      // time here — when the model's output is valid JSON the platform hands
      // it back already parsed, so `response` is an *array*, not a string.
      // Code that insists on a string discards every correct answer, and the
      // only symptom is a stage that runs, bills for its inference, and finds
      // nothing.
      const raw = result?.response ?? result?.choices?.[0]?.message?.content;
      if (opts?.organisations) {
        for (const o of organisationsFrom((result as { organisations?: unknown } | null)?.organisations, text, opts.organisations)) {
          if (!orgsFound.includes(o)) orgsFound.push(o);
        }
      }
      if (opts?.places) {
        for (const p of placesFrom((result as { places?: unknown } | null)?.places, text)) {
          if (!placesFound.includes(p)) placesFound.push(p);
        }
      }

      let parsed: unknown;
      if (Array.isArray(raw)) {
        parsed = raw;
      } else if (typeof raw === "string") {
        // Asked for bare JSON and usually obliges, but a small model wrapping
        // it in a sentence or a code fence is common enough to survive rather
        // than fail the whole stage over.
        const begin = raw.indexOf("[");
        const close = raw.lastIndexOf("]");
        if (begin === -1 || close <= begin) return null;
        parsed = JSON.parse(raw.slice(begin, close + 1));
      } else {
        // Timed out, or an envelope with nothing in it.
        return null;
      }
      if (!Array.isArray(parsed)) return null;

      const names: string[] = [];
      // A queue, not the array: a name the text breaks over a line comes
      // back as its two halves, each a candidate of its own.
      const queue: unknown[] = [...parsed];
      for (let q = 0; q < queue.length; q += 1) {
        const candidate = queue[q];
        if (typeof candidate !== "string") continue;
        // Less a greeting or a title the tagger read as part of it: "Hallo
        // Makeswaran", "Mr. Zilke Eades", "chan ゆきか".
        const asked = withoutTitle(withoutGreeting(candidate.trim()));
        // Present verbatim, or it did not come from the user. Verbatim as
        // written: a model tidies "Sarah  Chen" to one space and "sarah
        // chen" to capitals, and the value taken is the text's own form, so
        // the swap finds it (leak hunt, 2026-11-14). A name broken over a
        // line is two values, each on its own line.
        const name = locateName(asked, text);
        if (name === null) continue;
        if (/[\r\n]/.test(name)) {
          queue.push(...name.split(/\r?\n/).map((part) => part.trim()).filter((part) => part.length >= 2));
          continue;
        }
        // A month or a word the lists call ordinary, written as a person:
        // "ask April if she can", "Grace and Will".
        const rescued = isMonthAsName(name, text) || isCoordinatedName(name, text, queue);
        // Nor a title the model returned by itself: "Sra." out of "Estimada
        // Sra. Ortega".
        if (isBareTitle(name)) continue;
        // And an ordinary word is not a name, however capitalised. The same
        // list that decides whether to call the model at all also filters what
        // comes back — the model is the thing being checked here, so its
        // output cannot be the only thing consulted.
        if (!rescued && COMMON_CAPITALISED.has(name)) continue;
        // Nor a day or a date, with or without its dot or its number:
        // "Tue.", "Sept 3", "Friday 5:30".
        if (!rescued && isDateWords(name)) continue;
        // And neither is a pair of them — "Hot Dog" is not a person.
        if (isEverydayPhrase(name)) continue;
        // Nor an ordinary word written the ordinary way — "hat".
        if (isCommonLowercaseWord(name)) continue;
        // Nor one of another language's, capitalised as it opens a sentence or
        // as German writes nouns: "Hallo", "Beste", "Ciao", "Daten".
        if (isForeignCommonWords(name)) continue;
        // Nor a greeting that is also a name, used as the greeting ("Cher
        // Shqipton,"), nor a German compound ending in a noun ("Mosaik-Kurs").
        if (isGreetingHere(name, text) || isNounCompound(name)) continue;
        // Nor a slice of the sentence around one — "an aws".
        if (isSentenceFragment(name)) continue;
        // Nor a piece of technology named like a person — "Secure Enclave".
        if (isTechnicalTerm(name)) continue;
        // Nor a field label, a role, a description of a person, or a currency.
        // Unless it is a town written after "tía" or "profe": see isTownNamingAPerson.
        if (isNotAPerson(name) && !isTownNamingAPerson(name, text)) continue;
        // Nor one word that is an ordinary word in this text: "the", "Article",
        // "PROCEDURE" over a judgment that says "the procedure".
        if (!rescued && isOrdinaryWordHere(name, text)) continue;
        // Nor a word nobody would take for a name: "sympathy" in a cased
        // message, 소아과, לי.
        if (isPlainlyNotAName(name, text)) continue;
        // Nor a pet, named as one: "my dog is called Biscuit".
        if (isPetName(name, text)) continue;
        // Nor somebody famous the question is about: "has Steffi Graf won".
        if (isFamousPersonHere(name, text)) continue;
        // Nor half of a reported case: "the holding in Miranda v. Arizona".
        if (isCaseName(name, text)) continue;
        // Nor the second half of a species: "E. coli", "S. aureus", "H. pylori".
        if (isSpeciesName(name, text)) continue;
        if (isAcronym(name)) continue;
        if (!isSubstitutable(name)) continue;
        if (names.length >= NER_MAX_NAMES) {
          capped = true;
          break;
        }
        names.push(name);
      }
      return names;
    } catch {
      return null;
    }
  };

  /*
   * Every candidate window, and honest about any it did not read.
   *
   * decided stays true only if all of them were read and answered. A window
   * skipped for budget, or one the model would not answer about twice, makes
   * the whole answer undecided — because a caller asking "were all the names
   * found" cannot act on "some of them were".
   */
  const found: string[] = [];
  let decided = true;

  const started = Date.now();
  const maxWindows = opts?.scanAll ? NER_MAX_WINDOWS : NER_MAX_CHAT_WINDOWS;
  for (const [i, window] of candidates.entries()) {
    if (i >= maxWindows || Date.now() - started > NER_ONESHOT_BUDGET_MS) {
      decided = false;
      break;
    }

    let answer = await attempt(window, opts?.scanAll ? NER_ONESHOT_TIMEOUT_MS : NER_TIMEOUT_MS);
    if (answer === null) {
      // Only here — the first go produced nothing usable, so this is text
      // whose names are otherwise about to go out in the clear.
      answer = await attempt(window, opts?.scanAll ? NER_ONESHOT_RETRY_MS : NER_RETRY_TIMEOUT_MS);
    }

    // Both failed for this window. The caller decides what that means:
    // ordinarily the message still goes, because the earlier stages have run
    // and losing someone their answer to protect a name that may not be
    // there is its own harm. Under strict redaction it does not go at all.
    if (answer === null) {
      decided = false;
      continue;
    }

    for (const name of answer) if (!found.includes(name)) found.push(name);
  }

  /* More names than one window may carry is the same kind of gap as a
     window never read: the answer is a part of the answer. Strict redaction
     refuses on it, which is what strict redaction is for. */
  if (capped) decided = false;

  const names = withCues(found);
  const places = opts?.places ? { places: placesFound.filter((p) => !names.includes(p)) } : {};
  if (!opts?.organisations) return { names, decided, ...places };
  // A span both models disagree on is hidden as a person: the stronger claim.
  return { names, decided, organisations: orgsFound.filter((o) => !names.includes(o)), ...places };
}

/**
 * The name as the text writes it, or null when the text does not have it.
 *
 * Verbatim first. Otherwise the same words in any spacing and any case,
 * bounded by non-letters, and the span the text holds is what is returned:
 * "Sarah  Chen", "sarah chen", "Sarah\nChen" for a model that answered
 * "Sarah Chen". Short answers of one word keep the case the model gave, so
 * "will" is never read off "Will" (a word of two letters or more in all).
 */
function locateName(asked: string, text: string): string | null {
  if (asked.length < 2) return null;
  if (text.includes(asked)) return asked;
  const words = asked.split(/\s+/).filter(Boolean);
  if (words.length === 0) return null;
  const pattern = new RegExp(`(?<!\\p{L})${words.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s+")}(?!\\p{L})`, words.length > 1 ? "iu" : "u");
  const m = pattern.exec(text);
  if (!m) return null;
  // One word, differently cased, only when the text has no capitals of its
  // own to go by: "tell priya" for "Priya"; never "will" for "Will".
  if (words.length === 1 && m[0] !== asked) {
    const loose = new RegExp(`(?<!\\p{L})${words[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?!\\p{L})`, "iu").exec(text);
    if (!loose || /\p{Lu}/u.test(text)) return null;
    return loose[0];
  }
  return m[0];
}

/**
 * Adds an alias for each detected name, longest first so "Sarah Chen" is
 * mapped before "Sarah" and the pair stay consistent with each other.
 */
export async function addNameRedactions(
  map: RedactionMap,
  names: string[],
  haystack: string,
  /** Names the person has said may be sent as written. See AllowList. */
  allow: AllowList = new Set(),
): Promise<RedactionMap> {
  const taken = new Set(Object.keys(map));
  const covered = new Set(Object.values(map).map((value) => value.toLowerCase()));
  const coveredWords = new Set([...covered].flatMap((v) => v.split(/\s+/)));
  const cover = (value: string) => {
    covered.add(value);
    for (const w of value.split(/\s+/)) coveredWords.add(w);
  };
  /* The words that have a stand-in: a whole value, or a half put in below. */
  const halvesMapped = new Set([...covered].filter((v) => !/\s/.test(v)));
  const out: RedactionMap = { ...map };
  // How much of the stand-in grid is taken: a first and last name pair, or
  // one of the names alone.
  const firsts = new Set(FAKE_FIRST), lasts = new Set(FAKE_LAST);
  let gridTaken = 0, singlesTaken = 0;
  const countTaken = (standIn: string) => {
    const [f, l, extra] = standIn.split(" ");
    if (extra === undefined && l !== undefined && firsts.has(f) && lasts.has(l)) gridTaken++;
    else if (l === undefined && (firsts.has(f) || lasts.has(f))) singlesTaken++;
  };
  for (const k of taken) countTaken(k);

  for (const name of [...names].sort((a, b) => b.length - a.length)) {
    if (taken.size >= MAX_REDACTION_ENTRIES) break;
    if (covered.has(name.toLowerCase())) continue;
    if (isAllowed(name, allow)) continue;
    /*
     * A name already inside one we have mapped — "Sarah" under "Sarah Chen" —
     * would otherwise get a second, unrelated alias, and the two halves of one
     * person would come back as two different people. The halves of a mapped
     * name are put in the map below, so there is nothing left to do for it.
     *
     * A whole word, though, not any substring. As a substring test this also
     * caught names that merely sit inside a longer one — "Ann" inside "Anna",
     * "Chris" inside "Christina", "Lee" inside "Leena" — and those are
     * different people with nothing covering them. The shorter name was
     * skipped here and then sent to the model exactly as the person wrote it.
     */
    const lower = name.toLowerCase();
    // A set of every covered word, not a split of every covered name each
    // time: four thousand names took seconds that way (2026-10-08).
    // Covered means it has a stand-in of its own: a word of a mapped name
    // whose half could not be added ("Sylvie" already taken, so "Lucía"
    // got none) was skipped here and sent as written (leak hunt,
    // 2026-11-14). It gets its own instead.
    if (covered.has(lower) || (coveredWords.has(lower) && halvesMapped.has(lower))) continue;

    const parts = name.split(/\s+/);
    /*
     * The attempt number has to reach candidates the earlier attempts did not.
     *
     * Both indices below used to be `(hash + i) % 32`, so sixty-four attempts
     * visited thirty-two candidates and then repeated them. Every one taken
     * meant pickFake returned null, and a null alias is not a degraded alias:
     * the loop below skips the name and it goes to the model as written. Forty
     * ordinary first names in one conversation mapped twenty-eight and sent
     * twelve — under the sixty-four-entry cap, so nothing anywhere said a
     * limit had been reached.
     *
     * So `i` now walks a grid rather than a ring. A single-word name takes a
     * first name, then a surname used as one, then a full pair — thirty-two,
     * then sixty-four, then a thousand. The first thirty-two candidates are
     * unchanged at every branch, so a conversation already under way keeps the
     * stand-ins it has.
     */
    // The whole grid already taken: straight to a placeholder rather than
    // trying all of it again for every name. Six thousand names took
    // fourteen seconds that way (2026-10-08).
    const spent = gridTaken >= FAKE_FIRST.length * FAKE_LAST.length && (parts.length >= 2 || singlesTaken >= FAKE_FIRST.length + FAKE_LAST.length);
    /* A woman's name gets a woman's stand-in and a man's a man's, while
       there are any left (redactionNameGender): the model takes "he" or
       "she" from the stand-in. Past 256 attempts, every first name again. */
    const pool = standInFirstsFor(name, FAKE_FIRST);
    const fake = await pickFake(name, taken, haystack, (i, hex) => {
      const a = parseInt(hex.slice(0, 6), 16);
      const b = parseInt(hex.slice(6, 12), 16);
      const firsts = i < 256 ? pool : FAKE_FIRST;
      const first = firsts[(a + i) % firsts.length];
      const last = FAKE_LAST[(b + i * 7 + Math.floor(i / FAKE_LAST.length)) % FAKE_LAST.length];
      if (parts.length >= 2) return `${first} ${last}`;
      if (i < firsts.length) return first;
      if (i < FAKE_FIRST.length + FAKE_LAST.length) return FAKE_LAST[(b + i) % FAKE_LAST.length];
      return `${first} ${last}`;
    }, true, spent ? 0 : 1024);

    if (fake) {
      out[fake] = name;
      taken.add(fake);
      countTaken(fake);
      cover(name.toLowerCase());

      /*
       * The halves of the name, mapped as well.
       *
       * Only the whole stand-in used to be in the map, and restoration is a
       * literal replacement — so a model that answered with one half of it
       * left that half on the screen. Live, in production, "Marta Kowalczyk"
       * was aliased correctly and the bakery names came back as "Okonkwo's
       * Oven" and "The Okonkwo Patisserie"; a note written three turns later
       * opened "Hi Beatrix". The person is reading a stranger's name where
       * theirs should be, which is precisely the failure that had aliasing
       * switched off in this codebase once before.
       *
       * Mapping the parts fixes the other direction too: a bare first name on
       * a later turn is now aliased rather than sent as written, which is how
       * anybody refers to somebody after the first mention.
       *
       * Each part is subject to the same checks as the whole. A part already
       * present in the message cannot be used — it would corrupt the text it
       * collides with — and a part the person has allowed is left alone.
       */
      const fakeParts = fake.split(/\s+/);
      // A placeholder ("[hidden 3]", see pickFake) has no halves to lend.
      if (parts.length >= 2 && fakeParts.length >= 2 && !fake.startsWith("[hidden ")) {
        // A title is not a half: "Dr. Sarah Lee" travels as "Noor Nakashima",
        // and with "Dr." as the first part an answer opening "Hi Noor" came
        // back "Hi Dr.,". With only a surname after the title ("Dr Reyes") the
        // first name stands for all of it, and the last for the surname, so
        // "Dr. Nakashima" still reads right.
        const named = withoutTitle(name).split(/\s+/);
        const halves: Array<[string, string]> = [
          [fakeParts[0], named.length >= 2 ? named[0] : name],
          [fakeParts[fakeParts.length - 1], named[named.length - 1]],
        ];
        for (const [fakePart, realPart] of halves) {
          if (taken.size >= MAX_REDACTION_ENTRIES) break;
          if (taken.has(fakePart)) continue;
          if (haystack.includes(fakePart)) continue;
          if (realPart !== name && covered.has(realPart.toLowerCase())) continue;
          if (isAllowed(realPart, allow)) continue;
          out[fakePart] = realPart;
          halvesMapped.add(realPart.toLowerCase());
          taken.add(fakePart);
          countTaken(fakePart);
          cover(realPart.toLowerCase());
        }
      }
    }
  }

  return out;
}

/** Stand-ins for an organisation: invented, and plainly a company. */
const FAKE_ORG_STEMS = [
  "Harrowgate", "Bellmont", "Quillon", "Ostervale", "Brightmere", "Calderwick", "Fenmoor", "Larkspire",
  "Thistlecombe", "Marlowfield", "Eastholm", "Wrenbury", "Corrigan", "Ashgrove", "Pellucid", "Northwold",
];
const FAKE_ORG_KINDS = ["Group", "Holdings", "Partners", "Associates", "Industries", "Institute", "Trust", "Systems"];

/**
 * Adds an alias for each organisation, longest first, after the people: a
 * value already covered (a person's name, or a longer organisation holding
 * this one as a whole) is left to that entry. Only called when the person
 * asked for organisations to be hidden.
 */
export async function addOrganisationRedactions(
  map: RedactionMap,
  organisations: string[],
  haystack: string,
  allow: AllowList = new Set(),
): Promise<RedactionMap> {
  const taken = new Set(Object.keys(map));
  const covered = new Set(Object.values(map).map((value) => value.toLowerCase()));
  const out: RedactionMap = { ...map };
  for (const org of [...organisations].sort((a, b) => b.length - a.length)) {
    if (taken.size >= MAX_REDACTION_ENTRIES) break;
    const lower = org.toLowerCase();
    if (covered.has(lower) || isAllowed(org, allow)) continue;
    const fake = await pickFake(org, taken, haystack, (i, hex) => {
      const a = parseInt(hex.slice(0, 6), 16);
      const b = parseInt(hex.slice(6, 12), 16);
      return `${FAKE_ORG_STEMS[(a + i) % FAKE_ORG_STEMS.length]} ${FAKE_ORG_KINDS[(b + Math.floor(i / FAKE_ORG_STEMS.length)) % FAKE_ORG_KINDS.length]}`;
    }, true);
    if (!fake) continue;
    out[fake] = org;
    taken.add(fake);
    covered.add(lower);
  }
  return out;
}
