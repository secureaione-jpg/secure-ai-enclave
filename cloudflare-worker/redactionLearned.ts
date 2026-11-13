/**
 * PII redaction: cues the engine learned from its own misses.
 *
 * The loop (cloudflare-worker/bench/learnCues.bench.test.ts):
 *
 *   1. Run the patterns over the practice rows of the field suites (public,
 *      labelled data; never anybody's messages) and keep every labelled
 *      value nothing found.
 *   2. Read the words right in front of each miss: "Badge No.", "Policy
 *      Number", "Ref". A word that keeps turning up in front of missed
 *      values is a label the engine does not know yet.
 *   3. Score each one twice: how many missed values it would catch on the
 *      practice rows, and how often it would fire on 131,000 real chats,
 *      e-mails and logs, where nothing should be taken.
 *   4. Write the ranked candidates to bench/.learned-candidates.md.
 *
 * A candidate becomes a line below only when a person has read it and the
 * real-text matches it would take. Nothing here changes by itself at run
 * time: a redactor that rewrote its own rules from what passed through it
 * would be learning from the very text it promises not to keep, and a rule
 * nobody read is a rule nobody can vouch for. So the learning is automatic
 * and the landing is reviewed, the same as every other change to this
 * module (redaction/LOCKED).
 *
 * Each entry is a label and what follows it. Adding one is a line of data,
 * not a regular expression: the pattern is built here, bounded, from the
 * escaped label.
 */

export type LearnedCue = {
  /** The label, as written before the value, lower case: "badge no". */
  cue: string;
  /** What the value is: an identifier, or a phone number. */
  kind: "govid" | "phone";
  /** Where it was learned, and what review found. */
  source: string;
};

const COURT_CASE = "realistic5: 11 caught, 0 wrong, 0 real (2026-10-27)";

export const LEARNED_CUES: readonly LearnedCue[] = [
  // First run, 2026-10-06. Reviewed: a phone's or laptop's identifier names
  // its owner as well as a serial number does. "identifier" alone scored
  // higher (5 caught) and was held back: on real text it is a Windows SID
  // ("S-1-5-18") and an SPDX licence line ("GPL-3.0-or-later").
  { cue: "device id", kind: "govid", source: "practice: 4 caught, 0 wrong, 0 real (2026-10-06)" },
  { cue: "device identifier", kind: "govid", source: "practice: 3 caught, 0 wrong, 0 real (2026-10-06)" },
  // Second run, 2026-10-07, on 1,627 practice rows and scored by the whole
  // engine with each label added. Most are labels in Markdown bold
  // ("**Phone Number:** 0694 1870"), which the hand-written patterns trip
  // over. "screws" passed every check and was rejected on review: it is a
  // part count ("Screws (1029)") one generated document labelled as an ID.
  { cue: "phone number", kind: "phone", source: "practice: 9 caught, 0 wrong, 0 real (2026-10-07)" },
  { cue: "phone at", kind: "phone", source: "practice: 9 caught, 0 wrong, 0 real (2026-10-07)" },
  { cue: "license number", kind: "govid", source: "practice: 8 caught, 0 wrong, 0 real (2026-10-07)" },
  { cue: "customer", kind: "govid", source: "practice: 5 caught, 0 wrong, 0 real (2026-10-07)" },
  { cue: "national id", kind: "govid", source: "practice: 5 caught, 0 wrong, 0 real (2026-10-07)" },
  { cue: "record number", kind: "govid", source: "practice: 3 caught, 0 wrong, 0 real (2026-10-07)" },
  // Read off realistic5's misses by hand, 2026-10-27, and scored the same
  // way: a court case's number after the word for it, in the languages the
  // messages were written in ("procedimiento 342/2026", "processo nº
  // 0812345-67.2025.8.26.0100", "مقدمہ نمبر 1287/2026"). A court's file
  // names the people in it. Not an order's number, which names a purchase
  // (recordShapes.test.ts); nor "case", which is as often a public judgment
  // ("case C-283/14"); nor "causa" alone, which is "because of" ("a causa
  // del COVID-19").
  { cue: "aktenzeichen", kind: "govid", source: COURT_CASE },
  { cue: "zaaknummer", kind: "govid", source: COURT_CASE },
  { cue: "procedimiento", kind: "govid", source: COURT_CASE },
  { cue: "procedimiento ordinario", kind: "govid", source: COURT_CASE },
  { cue: "procediment", kind: "govid", source: COURT_CASE },
  { cue: "procediment ordinari", kind: "govid", source: COURT_CASE },
  { cue: "procedimento", kind: "govid", source: COURT_CASE },
  { cue: "processo", kind: "govid", source: COURT_CASE },
  { cue: "processo n.º", kind: "govid", source: COURT_CASE },
  { cue: "processo nº", kind: "govid", source: COURT_CASE },
  { cue: "causa rit", kind: "govid", source: COURT_CASE },
  { cue: "expediente", kind: "govid", source: COURT_CASE },
  { cue: "r.g.", kind: "govid", source: COURT_CASE },
  { cue: "dosya no", kind: "govid", source: COURT_CASE },
  { cue: "esas no", kind: "govid", source: COURT_CASE },
  { cue: "sp. zn.", kind: "govid", source: COURT_CASE },
  { cue: "sygn. akt", kind: "govid", source: COURT_CASE },
  { cue: "वाद संख्या", kind: "govid", source: COURT_CASE },
  { cue: "مقدمہ نمبر", kind: "govid", source: COURT_CASE },
  { cue: "القضية رقم", kind: "govid", source: COURT_CASE },
  { cue: "القضية", kind: "govid", source: COURT_CASE },
];

/** Labels the miner proposed and review turned down, with why, so it does
 *  not propose them again. Not read by the engine. */
export const REJECTED_CUES: readonly LearnedCue[] = [
  { cue: "identifier", kind: "govid", source: "2026-10-06: Windows SIDs and SPDX licence lines on real text" },
  { cue: "screws", kind: "govid", source: "2026-10-07: a part count one generated document labelled as an ID" },
];

/** The value after a learned label: one token with a digit (an identifier),
 *  or a phone-shaped run of digits. Bounded on every side. */
const VALUE = {
  govid: String.raw`(?=[A-Za-z0-9./-]{0,29}\d)[A-Za-z0-9](?:[A-Za-z0-9./-]{2,28}[A-Za-z0-9])`,
  phone: String.raw`\+?[\d(][\d ().-]{6,18}\d`,
} as const;

/** The cue as a pattern: escaped, any run of spaces between its words, and
 *  an optional full stop after an abbreviation ("No" or "No."). */
function cueSource(cue: string): string {
  return cue
    .trim()
    .split(/\s+/)
    .map((w) => w.replace(/\.$/, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\.?")
    .join("[ \\t]+");
}

/** Whether a value after a learned label is taken: a phone has seven to
 *  sixteen digits; an identifier is not a year or a date, and has two digits
 *  among letters or four on its own. Shared by findStructured and the miner,
 *  so a candidate is scored by the rule it would ship with. */
export function acceptLearned(kind: LearnedCue["kind"], value: string): boolean {
  const digits = value.replace(/\D/g, "").length;
  if (kind === "phone") return digits >= 7 && digits <= 16;
  if (/^(?:19|20)\d\d$/.test(value) || /^\d{1,4}[-./]\d{1,2}[-./]\d{1,4}$/.test(value)) return false;
  return /[A-Za-z]/.test(value) ? digits >= 2 : digits >= 4;
}

/** One pattern per kind over every learned cue of that kind, or null when
 *  there are none. Case-insensitive on the label only: the value classes
 *  name both cases already. */
export function learnedCuePatterns(cues: readonly LearnedCue[] = LEARNED_CUES): Array<{ kind: LearnedCue["kind"]; pattern: RegExp }> {
  const out: Array<{ kind: LearnedCue["kind"]; pattern: RegExp }> = [];
  for (const kind of ["govid", "phone"] as const) {
    const labels = cues.filter((c) => c.kind === kind).map((c) => cueSource(c.cue));
    if (!labels.length) continue;
    // A bracket after a phone label opens the number's area code, "(97)
    // 9856-7733", so it is not read as part of the label there.
    const open = kind === "phone" ? "" : String.raw`|\(`;
    out.push({
      kind,
      pattern: new RegExp(
        String.raw`(?<![\p{L}\p{N}])(?:${labels.join("|")})(?![\p{L}])[ \t]*(?:(?:is|was|:|#|=${open}|\*{1,2}|["'\x60])[ \t]*){0,4}(${VALUE[kind]})(?![A-Za-z0-9-])`,
        "giud",
      ),
    });
  }
  return out;
}
