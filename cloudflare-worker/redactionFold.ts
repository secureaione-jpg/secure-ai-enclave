/**
 * The text the scanner's patterns read, and the way back to the original.
 *
 * Every pattern in redactionPatterns.ts reads a cleaned-up copy of the
 * message: digits from other scripts written as ASCII, invisible characters
 * gone, and (below) the disguises a paste or a dictation puts on a number.
 * Every value is still cut out of the original, by way of `from` and `to`,
 * because the original is what gets replaced.
 *
 * Split out of redactionStructured.ts, to keep that file to the patterns' rules.
 */

/**
 * Where the digits of the world's other scripts begin.
 *
 * Every one of these blocks lays its ten digits out in order, so the value of
 * a character is its distance from the start of its block. Listed rather than
 * computed because the ones that matter are few, and a table can be read.
 */
const DIGIT_BLOCKS = [
  0x0660, // Arabic-Indic — how a phone number is written across the Arab world
  0x06f0, // Extended Arabic-Indic (Persian, Urdu)
  0x0966, // Devanagari
  0x09e6, // Bengali
  0x0a66, // Gurmukhi
  0x0ae6, // Gujarati
  0x0b66, // Oriya
  0x0be6, // Tamil
  0x0c66, // Telugu
  0x0ce6, // Kannada
  0x0d66, // Malayalam
  0x0e50, // Thai
  0x0ed0, // Lao
  0x0f20, // Tibetan
  0x1040, // Myanmar
  0x17e0, // Khmer
  0x1810, // Mongolian
  0xff10, // Fullwidth — what a Japanese or Chinese keyboard produces
];

/**
 * The same text with every digit written as an ASCII one.
 *
 * `\d` in JavaScript means 0-9 and nothing else, in every pattern, always. A
 * card number typed on a Persian keyboard, a phone number written the way it
 * is written in Cairo, a fullwidth number pasted out of a Japanese form — the
 * scanner did not see any of them, and a value the scanner cannot see is a
 * value that reaches the provider exactly as typed. It was not that these were
 * redacted badly; they were not redacted at all.
 *
 * Length-preserving, and that is the whole trick. Every digit here is one
 * UTF-16 unit and becomes one ASCII digit, so a span found in this string is
 * the same span in the original — which is what lets the patterns run over the
 * normalised text while the value taken away is the one the person actually
 * typed. Redacting the ASCII form instead would leave the original characters
 * sitting in the message.
 */
/**
 * Characters that are not a digit and not a separator, but sit between them.
 *
 * Copying a card number off a bank's web page brings zero-width spaces with
 * it, because that is how the page stops the number wrapping mid-group.
 * Copying a phone number out of Word brings an en-dash, because autocorrect
 * turned the hyphen into one. Copying anything out of a PDF brings
 * non-breaking spaces. None of it is visible and all of it stopped the
 * scanner dead: "4111<ZWSP>1111<ZWSP>1111<ZWSP>1111" matched nothing, and the
 * person looking at their own message could not see why, because there is
 * nothing to see.
 *
 * This is not an attack anybody is mounting. It is what a paste is.
 *
 * Mapped one character to one character, like the digits below, so every index
 * still lines up and the value replaced is still taken from the original text.
 */
const INVISIBLE = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/;
const UNICODE_DASH = /[\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D]/;
const UNICODE_SPACE = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/;

export function normaliseDigits(text: string): string {
  let out = "";
  for (const char of text) {
    if (char.length === 1) {
      // A zero-width character becomes a space rather than nothing, because
      // nothing would change the length and every span after it. A space is
      // what the patterns already accept between groups of a card, an IBAN or
      // a phone number, so those all start matching.
      //
      // The one it does not rescue is an email with a zero-width character
      // inside the local part, where a space is not allowed and cannot be —
      // see the test that records this.
      if (INVISIBLE.test(char)) { out += " "; continue; }
      if (UNICODE_DASH.test(char)) { out += "-"; continue; }
      if (UNICODE_SPACE.test(char)) { out += " "; continue; }
    }
    // Iterating by code point, but only single-unit characters may be
    // rewritten: an astral digit is two units, and swapping it for one ASCII
    // digit would shift every index after it.
    if (char.length === 1) {
      const code = char.charCodeAt(0);
      const start = DIGIT_BLOCKS.find((base) => code >= base && code <= base + 9);
      if (start !== undefined) { out += String(code - start); continue; }
    }
    out += char;
  }
  return out;
}

/**
 * The text the patterns read, with the invisible characters taken out, and
 * where each of its characters came from.
 *
 * normaliseDigits turns an invisible character into a space, which rescues
 * the paste it was written for — a card with a zero-width space between the
 * groups. It does not rescue the two that are just as common: one beside an
 * ordinary space ("4111 <ZWSP>1111", how a bank page stops a number wrapping),
 * which became two spaces and matched nothing, and one inside a word — a soft
 * hyphen Word put in an email, a zero-width space in a key copied off a web
 * page — which split the value in two. Measured, both let every card, phone,
 * IBAN, email and key through as written.
 *
 * Taken out, they cannot get in the way of anything. The patterns read the
 * folded text; every value is still cut from the original by way of `from`
 * and `to`, invisible characters and all, because the original is what is
 * replaced.
 *
 * Three more disguises are undone the same way, each measured letting nearly
 * every card, phone, SSN and IBAN through as written (disguisedValues.test):
 *
 *  - Digits spaced or dashed one by one, "4 1 1 1 1 1 1 1 …", the way a
 *    number is read out, or typed into a form that wants one box per digit.
 *  - Digits spelled out, "four one one one …", the way dictation writes them.
 *  - A number broken across a line, "4111 1111 1111\n1111", the way a window
 *    narrower than the number wraps it when it is copied.
 *
 * Each is undone only where it cannot be ordinary writing: seven digits or
 * more, not one digit over and over, not only noughts and ones (a bit
 * pattern, "1 0 1 1 0 0 1"), and not a count ("one two three four five six
 * seven", "1 2 3 4 5 6 7").
 */
export function foldForScan(input: string): { scan: string; from: number[]; to: number[] } {
  const digits = normaliseDigits(input);
  const rewrites = new Map<number, { end: number; text: string }>();
  const rewrite = (start: number, end: number, text: string) => { rewrites.set(start, { end, text }); };

  for (const m of digits.matchAll(SPACED_DIGITS)) {
    const run = m[0].replace(/\D/g, "");
    if (!aNumber(run)) continue;
    for (let i = m.index + 1; i < m.index + m[0].length; i += 2) rewrite(i, i + 1, "");
  }

  for (const m of input.matchAll(SPELLED_DIGITS)) {
    const words = [...m[0].matchAll(DIGIT_WORD)];
    if (!aNumber(words.map((w) => DIGIT_WORDS.indexOf(w[0].toLowerCase())).join(""))) continue;
    let last = m.index;
    // Dictation writes the international prefix as a word: "plus four four".
    const plus = /^(?:plus|\+)[ \t]*/i.exec(m[0]);
    if (plus) { rewrite(m.index, m.index + plus[0].length, "+"); last = m.index + plus[0].length; }
    for (const w of words) {
      if (plus && w.index < plus[0].length) continue;
      const start = m.index + w.index;
      if (start > last) rewrite(last, start, "");
      rewrite(start, start + w[0].length, String(DIGIT_WORDS.indexOf(w[0].toLowerCase())));
      last = start + w[0].length;
    }
  }

  for (const m of digits.matchAll(BROKEN_LINE)) {
    // A window either side, not the whole text: a page of numbered lines has
    // a break like this on every line, and reading all of the text before
    // each one made the scan quadratic. A number and the words before it fit
    // in eighty characters.
    const before = digits.slice(Math.max(0, m.index - 80), m.index);
    const after = digits.slice(m.index + m[0].length, m.index + m[0].length + 80);
    const tail = /[\d +()-]*$/.exec(before)![0];
    const head = /^[\d -]*/.exec(after)![0];
    const counted = (tail + head).replace(/\D/g, "").length;
    // A line of single digits is a printed sequence — "f(100)\n 0 1 1 2 3 5 8
    // 13 21", the Fibonacci example in Python's tutorial — not a number's
    // other half.
    if (head.trim().split(/[ -]+/).filter((g) => g.length === 1).length >= 3) continue;
    if ((tail.match(/\d/g) ?? []).length < 2 || counted < 9 || counted > 34) continue;
    // A number that is its whole line is a row of a table or a line of an
    // address block, not one a window wrapped: "5130\n 2565 1-18-02  55.50",
    // "SW1A 1AA\n020 7946 0958". Wrapping happens to a number written in a
    // sentence, so the line before has words in front of it — words, set
    // apart from the number by a space, not welded onto it: "BAI0210001\n95,
    // avenue de Blanchet" is a reference above a street, and "ip=10.20.4.55\n
    // 2025-06-03T10:22:43Z" an address at the end of a log line.
    const line = before.slice(before.lastIndexOf("\n") + 1);
    const lead = line.slice(0, line.length - tail.length);
    if (!/\p{L}/u.test(lead) || !/^[\s(+]/.test(tail)) continue;
    // Nor a postcode ending its line above a phone number: "APO AA 61487\n416
    // 60 039 office", "South Africa 70651\n082 490 1693". Joined, they read as
    // one phone number and the address lost its postcode. One opening with 0
    // is a UK dialling code as often ("07700\n900123"), so that one is joined —
    // unless a state's two letters stand before it ("Canton, CT  06019").
    if (/^\s*\d{5}\s*$/.test(tail) && (!/^\s*0/.test(tail) || /\b[A-Z]{2}[ \t,]*$/.test(lead))) continue;
    // Nor a line that opens with a time or a date: "…off the record
    // 212-522-0040\n4:32 PM - 12/3/01" is a log, and joined the phone number
    // gained a digit and stopped being one.
    if (/^\d{1,4}[:/]|^\d{4}-\d{2}-\d{2}/.test(after)) continue;
    // A group cut in two has no space either side of the break and no more
    // than a group's worth of digits around it: "4111 1\n111". Anything else
    // is a separator the window turned into a line end.
    const left = /\d*$/.exec(before)![0].length;
    const right = /^\d*/.exec(after)![0].length;
    const split = !/[ \t]/.test(m[0]) && left + right <= 6;
    rewrite(m.index, m.index + m[0].length, split ? "" : " ");
  }

  let scan = "";
  const from: number[] = [];
  const to: number[] = [];
  for (let i = 0; i < input.length; ) {
    const r = rewrites.get(i);
    if (r) {
      for (const ch of r.text) { scan += ch; from.push(i); to.push(r.end); }
      i = r.end;
      continue;
    }
    if (!INVISIBLE.test(input[i])) { scan += digits[i]; from.push(i); to.push(i + 1); }
    i += 1;
  }
  return { scan, from, to };
}

/** Seven or more single digits, one separator used throughout. */
const SPACED_DIGITS = /(?<![\p{L}\p{N}.,]|\d[ -])\d([ -])\d(?:\1\d){5,}(?![\p{L}\p{N}]|[.,]\d|[ -]\d)/gu;
const DIGIT_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
const DIGIT_WORD = /zero|one|two|three|four|five|six|seven|eight|nine/gi;
/** Seven or more digit words, apart by spaces, commas or hyphens, with the
 *  "plus" of an international number if it was said. */
const SPELLED_DIGITS = /(?:(?:\bplus|\+)[ \t]*)?\b(?:zero|one|two|three|four|five|six|seven|eight|nine)(?:(?:[ \t]*[,-][ \t]*|[ \t]+)(?:zero|one|two|three|four|five|six|seven|eight|nine)\b){6,}/gi;
/** A line end with a digit, a bracket or a hyphen before it and a digit after. */
const BROKEN_LINE = /(?<=[\d)-])[ \t]*\r?\n[ \t]*(?=\d)/g;

/** Whether a run of digits could be somebody's number rather than a count
 *  or a bit pattern. */
function aNumber(run: string): boolean {
  if (/^[01]*$/.test(run) || /^(\d)\1*$/.test(run)) return false;
  let up = true;
  let down = true;
  for (let i = 1; i < run.length; i += 1) {
    const step = Number(run[i]) - Number(run[i - 1]);
    if (step !== 1 && step !== -9) up = false;
    if (step !== -1 && step !== 9) down = false;
  }
  return !up && !down;
}
