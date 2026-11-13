/**
 * How a tagger's output is read into names, organisations and places: the
 * part of the name stage that does not depend on where the model runs. The
 * enclave (localNameModel.ts) and the browser (lib/deviceNames.worker.ts)
 * both read through this, so a name means the same thing in either place.
 * Kept apart from the loaders because they import the model runtime, and
 * the browser build cannot bundle the server's.
 */
import { GIVEN_NAMES } from "../../cloudflare-worker/redactionGivenNames.js";

export type Token = { entity?: string; entity_group?: string; word: string; score?: number; index?: number };

/** BERT reads 512 word pieces at most, so text is read in overlapping pieces
 *  cut at whitespace. 900 characters is well under that for any language
 *  these models know; the 200-character overlap keeps a name that straddles
 *  a cut whole in one of the two pieces. */
const SIZE = 900;
const STEP = 700;

export function pieces(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < Math.max(1, text.length); i += STEP) {
    let a = i, b = Math.min(text.length, i + SIZE);
    while (a > 0 && !/\s/.test(text[a - 1])) a--;
    while (b < text.length && !/\s/.test(text[b])) b++;
    out.push(text.slice(a, b));
    if (b >= text.length) break;
  }
  return [...out, ...linesAlone(text)];
}

/** Lines in another script, read on their own as well as in their piece.
 *  Measured 2026-10-26 with our own model: after one English line it tags
 *  田中由美, 佐藤健太 and 王小明 as no name, and keeps only "Ивану" of
 *  "Ивану Петрову", though it finds each of them whole when the line is read
 *  alone. A chat is every turn joined into one text, so a Chinese or
 *  Japanese message after an English turn went out with its names in it.
 *  Only lines with letters outside the Latin script, and only when there is
 *  other text around them: an English chat pays for no extra reading. */
export function linesAlone(text: string): string[] {
  const lines = text.split(/\n+/).map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) return [];
  return lines.filter((l) => /(?=\p{L})\P{Script=Latin}/u.test(l));
}

/** Whether `s` stands in the text as whole words. A tagger that marks the
 *  first word piece of "Email" as a person hands back "Em", which is in the
 *  text but is not a word of it. A Latin name written straight against
 *  Chinese or Japanese ends where the script changes, as in toWholeWord. */
function asWord(s: string, text: string): boolean {
  const escaped = s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const seen = UNSPACED.test(s) ? text : text.replace(new RegExp(UNSPACED.source, "gu"), " ");
  return new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, "u").test(seen);
}

/** A tagger often marks only the first pieces of an unusual name as a person
 *  ("Kat" of "Kattie", "Hett" of "Hettinger"): it has found the name, and
 *  split the word. Stretch the span to the whole word it starts in, so the
 *  name is hidden whole rather than dropped as a fragment. */
export function toWholeWord(s: string, text: string): string | null {
  const at = text.indexOf(s);
  if (at < 0) return null;
  // A name in Latin letters written straight against Chinese or Japanese
  // ("Mariele\u7ec4\u7ec7\u4e86\u4e00\u573a\u2026") stops where the script changes; otherwise it takes
  // the sentence after it with it. UNSPACED is defined further down.
  const spaced = !UNSPACED.test(s);
  const letter = (c: string) => /[\p{L}\p{M}'\u2019-]/u.test(c) && !(spaced && UNSPACED.test(c));
  let a = at, b = at + s.length;
  while (a > 0 && letter(text[a - 1])) a--;
  while (b < text.length && letter(text[b])) b++;
  return text.slice(a, b).replace(/^['\u2019-]+|['\u2019-]+$/g, "");
}

/** The people in one model's tags: B-PER starts a name, I-PER continues it,
 *  word pieces ("##ez") join the word before them. Only a name found verbatim
 *  in the text is returned, the same rule the name stage applies after. */
export function people(tokens: Token[], text: string, asTagged: RegExp = UNSPACED): string[] {
  return tagged(tokens, text, /PER/, 0, false, asTagged);
}

/** The organisations in one model's tags, read the same way: B-ORG, I-ORG.
 *  Both models tag them; they are returned beside the people and hidden only
 *  when the caller asked (hideOrganisations). */
export function organisations(tokens: Token[], text: string, asTagged: RegExp = UNSPACED): string[] {
  return tagged(tokens, text, /ORG/, ORG_MIN_SCORE, false, asTagged);
}

/** How sure a tagger must be of an organisation, on average over its pieces.
 *  The English model reading German or Spanish tags ordinary nouns as ORG at
 *  0.3 to 0.6 ("Klägerin", "Antidumpingzollsätze"); real ones score 0.9 and
 *  up. MAPA validation, 2026-10-06: 442 German nouns hidden without this. */
const ORG_MIN_SCORE = 0.8;

/** The places in one model's tags: B-LOC, I-LOC. Returned beside the people
 *  and hidden only in medical mode, where a town is an identifier. Held to
 *  the same floor as organisations, for the same reason. */
export function places(tokens: Token[], text: string, asTagged: RegExp = UNSPACED): string[] {
  return tagged(tokens, text, /LOC/, ORG_MIN_SCORE, true, asTagged);
}

/** How sure the English tagger must be of a lone word as a person, in text
 *  that is not English, and it must have tagged the whole word.
 *
 *  German capitalises every noun, and the English model reads a capital as
 *  a name. Often it tags only the first piece ("Z" of "Zweifellos", at
 *  0.94) and the span is stretched to the word. On MAPA's practice rows
 *  (2026-10-07), its one-word people in German, French, Spanish, Italian
 *  and Portuguese were 425 unlabelled words ("Hersteller", "Prüfung",
 *  "Orbene") to 261 labelled people; the stretched or unsure ones, not also
 *  found by the multilingual model, were 375 words to 46 labelled, half of
 *  those titles ("Frau", "Rechtsanwalt"). In English those same guesses are
 *  mostly real surnames ("Shroff-Tiwari", "Balvan"), so English text is
 *  left exactly as it was.
 *
 *  A known given name is never dropped. Without that, ai4privacy's French
 *  and German practice rows lost 96 of 1,412 labelled first names ("Cher
 *  Betty", "Hallo Evangeline"), 86 of them in GIVEN_NAMES; with it, MAPA
 *  keeps 448 of the 453 words this drops. */
const UNSURE_ABROAD = 0.7;

/** Words that are common in running English and rare in the other
 *  languages these models read, and the reverse. */
const ENGLISH_WORDS = /(?<![\p{L}])(?:the|and|of|to|is|was|that|for|with|which|this|have|has|by)(?![\p{L}])/giu;
const OTHER_WORDS = /(?<![\p{L}])(?:der|die|das|und|nicht|ist|den|dem|für|von|mit|auf|sich|des|les|une|est|sur|pour|dans|aux|della|che|del|nel|nella|alla|los|las|que|una|para|por|não|uma|pelo)(?<![./@:][\p{L}]*)(?![\p{L}.@])/gu;

/** Whether a piece of text reads as English, by its function words. Two
 *  other-language words at least, so a log line or a form with none of
 *  either stays English, as all text was before. */
export function readsAsEnglish(text: string): boolean {
  const en = text.match(ENGLISH_WORDS)?.length ?? 0;
  const other = text.match(OTHER_WORDS)?.length ?? 0;
  return other < 2 || en >= other;
}

/** A lone word the English tagger was not sure was a person, or tagged only
 *  the start of, in text that is not English, that the multilingual tagger
 *  did not find either. A hyphenated word ("Ruiz-Jarabo") is kept: nouns
 *  are not hyphenated. */
export function unsureOutsideEnglish(name: string, tokens: Token[], text: string, otherModel: string[]): boolean {
  if (/[\s-]/.test(name) || GIVEN_NAMES.has(name.toLowerCase()) || readsAsEnglish(text)) return false;
  if (otherModel.some((o) => o === name || o.split(/\s+/).includes(name))) return false;
  const score = personScore(tokens, name);
  return score !== null && score < UNSURE_ABROAD;
}

/** The best mean score of a PER span that is the whole of `name`; 0 when
 *  the tagger only ever marked its start; null when it never marked it. */
function personScore(tokens: Token[], name: string): number | null {
  let best: number | null = null;
  let cur: Token[] | null = null;
  const close = () => {
    if (!cur) return;
    let s = "";
    for (const w of cur.map((t) => t.word)) s += w.startsWith("##") ? w.slice(2) : (s ? " " : "") + w;
    s = s.trim();
    if (s && name.startsWith(s)) {
      const mean = s === name ? cur.reduce((sum, t) => sum + (t.score ?? 1), 0) / cur.length : 0;
      best = Math.max(best ?? 0, mean);
    }
  };
  for (const t of tokens) {
    const tag = t.entity ?? t.entity_group ?? "";
    if (/PER/.test(tag) && cur && !/^B-/.test(tag)) { cur.push(t); continue; }
    close();
    cur = /PER/.test(tag) ? [t] : null;
  }
  close();
  return best;
}

/** Scripts written without spaces between words. toWholeWord stretches to
 *  the whole run of letters, and there that run is the rest of the sentence:
 *  "スミス" tagged in "スミスさんは東京にいます" came back as the entire
 *  sentence, and the sentence was hidden as a name. A span in these scripts
 *  is taken as tagged instead.
 *
 *  Not Korean, which puts spaces between words. Stretching there takes a
 *  particle with the name ("김경수님은"), but it also completes a name the
 *  tagger only began, and without it recall fell from 41.5% to 39.3%
 *  (namesEastAsia bench, practice, 2026-10-21). */
const UNSPACED = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Thai}]/u;

/** The same, with Korean, for our own model (ownNameModel). It is trained to
 *  tag a name exactly and leave the particle after it untagged
 *  ([[PER|김민수]]님께서는), so there is no half-tagged name to complete, and
 *  stretching would only put the particle back: round 1 returned "님께" with
 *  names (2026-10-22). */
export const AS_TAGGED_OWN = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Thai}\p{Script=Hangul}]/u;

/** BERT's tokenizer splits Chinese characters into words of their own, so
 *  "唐冬梅" comes back as "唐 冬 梅", which is not in the text. */
const IDEOGRAPH_GAP = /(?<=\p{Script=Han}) (?=\p{Script=Han})/gu;

/** The same characters as the text writes them, with one space or none
 *  between each: a Japanese name is often written surname, space, given
 *  name ("山本 健太"), and the tagger's "山本 健 太" matches neither the text
 *  nor its gapless "山本健太". Only these scripts, only a space. */
function asWritten(s: string, text: string): string | null {
  const chars = [...s.replace(/\s+/g, "")];
  if (chars.length < 2) return null;
  const re = new RegExp(chars.map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[ 　]?"), "u");
  return text.match(re)?.[0] ?? null;
}

function tagged(tokens: Token[], text: string, kind: RegExp, minScore = 0, wholeOnly = false, asTagged: RegExp = UNSPACED): string[] {
  const spans: Token[][] = [];
  let cur: Token[] | null = null;
  for (const t of tokens) {
    const tag = t.entity ?? t.entity_group ?? "";
    const isKind = kind.test(tag);
    if (isKind && cur && !/^B-/.test(tag)) { cur.push(t); continue; }
    if (cur) spans.push(cur);
    cur = isKind ? [t] : null;
  }
  if (cur) spans.push(cur);
  const names: string[] = [];
  for (const span of spans) {
    if (minScore > 0) {
      // A span that starts mid-word is a fragment, not a guess worth stretching.
      if (span[0].word.startsWith("##")) continue;
      if (span.reduce((sum, t) => sum + (t.score ?? 1), 0) / span.length < minScore) continue;
    }
    const words = span.map((t) => t.word);
    let s = "";
    for (const w of words) s += w.startsWith("##") ? w.slice(2) : (s ? " " : "") + w;
    s = s.trim();
    if (asTagged.test(s)) {
      const found = text.includes(s) ? s : text.includes(s.replace(IDEOGRAPH_GAP, "")) ? s.replace(IDEOGRAPH_GAP, "") : asWritten(s, text);
      if (found && found.length > 1 && text.includes(found) && !names.includes(found)) names.push(found);
      continue;
    }
    const whole = toWholeWord(s, text);
    // Stretching is for a name the tagger split. A place it marked only the
    // start of is a guess at a word: "Acc" of "Account", "Bir" of "Birth".
    if (wholeOnly && whole !== s) continue;
    if (whole && whole.length > 1 && asWord(whole, text) && !names.includes(whole)) names.push(whole);
  }
  return names;
}

/** Our own model's tokens, written the way the BERT taggers write theirs.
 *
 *  Everything above reads WordPiece, which marks the rest of a word
 *  ("##alska"). XLM-R and mmBERT use SentencePiece, which marks the start of
 *  one ("▁Kow", "alska"), and transformers.js decodes both pieces of that to
 *  bare text, so from `word` alone a word's second half looks like a new
 *  word. `raw` is the tokenizer's own pieces for the same text, with the
 *  marks still on; a token's `index` counts the <s> in front of them.
 *
 *  SentencePiece sometimes gives the space a piece of its own ("▁", "田中").
 *  That piece is dropped, and a name it started passes its B- on. */
export function asWordPieces(tokens: Token[], raw: string[]): Token[] {
  const out: Token[] = [];
  let carried: string | null = null;
  for (const t of tokens) {
    const at = t.index === undefined ? -1 : t.index - 1;
    const r = raw[at];
    if (r === undefined) { out.push(t); continue; }
    const tag = t.entity ?? t.entity_group ?? "";
    if (r === "▁") { carried = /^B-/.test(tag) ? tag : null; continue; }
    const starts = r.startsWith("▁") || raw[at - 1] === "▁" || at === 0;
    const word = r.replace(/^▁/, "");
    const entity = carried && tag === carried.replace(/^B-/, "I-") ? carried : tag;
    carried = null;
    out.push({ ...t, entity, word: starts ? word : `##${word}` });
  }
  return out;
}
