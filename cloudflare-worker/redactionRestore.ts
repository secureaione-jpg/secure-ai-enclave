/**
 * PII redaction, part four: applying the map, and taking it back out.
 *
 * redactText and redactMessages put the stand-ins in on the way to the
 * provider; restoreText and restoreStream put the real values back on the
 * copy addressed to the user, including across chunk boundaries of a
 * streamed reply. redactionHeader is what the client reads to draw the swap.
 */

import { b64urlEncode, escapeRegex, ZH_TITLE } from "./redactionMap.js";
import { caseForms, lookalikes, restoreText, sameCase } from "./restoreCore.js";
export { caseForms, lookalikes, restoreText };
import type { Provider, RedactionMap, RequestMessage } from "./redactionMap.js";


/**
 * Replaces real values with their aliases. Names are matched on word
 * boundaries so a user called Sam does not turn every "same" in their message
 * into an alias; emails and phone numbers are matched literally, since the
 * characters around them are punctuation as often as not.
 *
 * Longest real value first: a full name has to be consumed before its parts
 * are, or "Herbert Perryman" becomes "Marcus Perryman".
 *
 * In one pass, the way restoreText puts them back. Replaced one value at a
 * time, a later value could match inside a stand-in an earlier one had just
 * written: "com", the second half of a name read off "shockwave.com@…", was
 * replaced inside the stand-in address's own ".com", and the answer came
 * back with an address nobody had written (bench/roundTrip, Enron). One
 * pattern over the original text never looks at what it wrote.
 */
export function redactText(text: string, map: RedactionMap): string {
  if (!text) return text;
  const pairs = Object.entries(map)
    .map(([fake, real]) => [real, fake] as const)
    .filter(([real]) => real.length > 0)
    .sort((a, b) => b[0].length - a[0].length);
  if (pairs.length === 0) return text;
  const alternatives = pairs.map(([real]) => `(${valuePattern(real)})`);
  const pattern = new RegExp(alternatives.join("|"), "giu");
  // Matched in any case, written in the case it was found in: "jeff" in a
  // display name went out as "Priya" and came back as "Jeff", so the
  // person's own text was changed by being sent (350 of 7,100 Enron
  // messages, bench/roundTrip). restoreText maps the cased stand-in back.
  return text.replace(pattern, (found: string, ...groups: unknown[]) => {
    const at = groups.findIndex((g, i) => i < pairs.length && g !== undefined);
    const [real, fake] = pairs[at];
    return found === real ? fake : sameCase(found, fake);
  });
}

/** One real value as a pattern, with the boundaries its shape needs. */
export function valuePattern(real: string): string {
  const wordish = /^[\p{L}\p{N} ]+$/u.test(real);
  /* A number may touch letters. The word boundary is there for names —
     Sam inside "same" — and applied to numbers it let found values through
     as written wherever the text had welded them to a word: "Account
     76948092" written without its space, "visa167", "XXXXXX07133007",
     "Eichholzweg 12A", "marzo 14º". The scanner had found every one, and
     the replacement skipped it (bench/roundTrip). Decided per end: an end
     that is a digit may touch a letter, and is still never inside a longer
     number; an end that is a letter keeps the word boundary.

     Chinese, Japanese, Thai, Lao, Khmer and Burmese put no space between
     words, so a name there always touches a letter: "我是陈思远，", "田中さんに",
     "เรียนคุณสมชาย". With the word boundary every one was found and then sent
     as written (2026-10-24). An end in one of those scripts touches what it
     touches; only a value of two such characters or more, so a lone 李 or 王
     is still never taken out of 李子 or 王国.

     Korean puts spaces between words, but its particles and honorifics
     join the name with none: "정하늘님,", "민준이가", "지은 씨에게" (realistic2).
     A Hangul name keeps the boundary in front and none behind.

     A Chinese surname on its own, 李 of 李老师, is taken only where a title
     follows it (ZH_TITLE): the stand-in goes in front of 老师 and 李子 keeps
     its 李. */
  if (/^\p{Script=Han}$/u.test(real)) return `(?:${escapeRegex(real)}(?=${ZH_TITLE})|(?<=${JA_KIN_BEFORE})${escapeRegex(real)}|${escapeRegex(real)}(?=${JA_HONORIFIC_AFTER}))`;
  /* An address in those scripts carries its numbers: "市玄武区中山路218号",
     "台北市信義區松仁路58號12樓". Digits did not count as theirs, so such a
     value was held to a word boundary it can never have, and sent as written
     (realistic5, 2026-10-25). Each end decides for itself, so a Latin
     building letter inside ("…环球中心E2区1607") changes nothing; a value
     with two characters of the script or more. */
  const unspaced = (real.match(UNSPACED_CHAR) ?? []).length >= 2;
  const left = /^\p{N}/u.test(real) ? "(?<!\\p{N})" : unspaced && UNSPACED_END.test(real.charAt(0)) ? "" : leftEdge(real);
  const hangul = /^[\p{Script=Hangul}\s]+$/u.test(real) && real.replace(/\s+/g, "").length >= 2;
  const right = /\p{N}$/u.test(real) ? "(?!\\p{N})" : (unspaced && UNSPACED_END.test(real.charAt(real.length - 1))) || hangul ? "" : rightEdge(real);
  return wordish ? `${left}${escapeRegex(real)}${right}` : escapeRegex(real);
}

const UNSPACED_CHAR = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}]/gu;
const UNSPACED_END = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}ー々]/u;
// A one-kanji Japanese name after the word for a relative, or before an
// honorific: 息子蓮の, 蓮くん. See eastAsianKinNames in redactionNameWords.
const JA_KIN_BEFORE = "息子|娘|孫|長男|長女|次男|次女";
const JA_HONORIFIC_AFTER = "さん|ちゃん|くん|君|様";

/* A word's edge is blocked only by a letter of its own script, or a digit:
   "Sam" stays inside "same", but an IBAN welded to Arabic ("الايبانSA44…"),
   a name to Chinese ("Kevin你好") or a street to Hebrew is still a word of its
   own there (realistic5, 2026-10-25). Hebrew writes its prepositions on the
   front of the next word ("ברחוב ביאליק 31", in the street), so one of those
   letters may come before a Hebrew value. A street and number run into the
   word before it ("wonendeTuinstraat 8") is taken where a capital follows a
   small letter. */
const SCRIPTS = ["Latin", "Cyrillic", "Greek", "Hebrew", "Arabic", "Devanagari", "Bengali", "Tamil", "Telugu", "Gujarati", "Gurmukhi", "Kannada", "Malayalam", "Sinhala", "Armenian", "Georgian", "Ethiopic", "Hangul"];
function scriptOf(ch: string): string | undefined {
  return SCRIPTS.find((s) => new RegExp(`\\p{Script=${s}}`, "u").test(ch));
}
function leftEdge(real: string): string {
  const script = scriptOf(real.charAt(0));
  if (!script) return "(?<![\\p{L}\\p{N}])";
  // Its letters, not its punctuation: Hebrew's ״ is Hebrew too ("״לרוני").
  const blocked = `(?<!(?=\\p{L})\\p{Script=${script}})(?<![\\p{M}\\p{N}])`;
  if (script === "Hebrew") return `(?:${blocked}|(?<=(?<![\\p{L}\\p{N}])[בהוכלמש]))`;
  if (script === "Latin" && /^\p{Lu}/u.test(real) && /\p{N}/u.test(real)) return `(?:${blocked}|(?<=\\p{Ll}))`;
  return blocked;
}
/* The same at the other end: an ID that ends in a capital, run into the next
   field of a form copied flat ("DNI:93863956JTeléfono", "NRIC:T2011849GPostal")
   is taken where another capital follows. Found and then sent as written
   before (ID practice set, 2026-10-26). Four digits at least, so a word is
   never cut off a longer one. */
function rightEdge(real: string): string {
  const script = scriptOf(real.charAt(real.length - 1));
  if (!script) return "(?![\\p{L}\\p{N}])";
  const blocked = `(?!(?=\\p{L})\\p{Script=${script}})(?![\\p{M}\\p{N}])`;
  if (script === "Latin" && /\p{Lu}$/u.test(real) && (real.match(/\p{N}/gu) ?? []).length >= 4) return `(?:${blocked}|(?=\\p{Lu}))`;
  return blocked;
}

export function redactMessages(messages: RequestMessage[], map: RedactionMap): RequestMessage[] {
  return messages.map((m) => ({
    role: m.role,
    content: typeof m.content === "string"
      ? redactText(m.content, map)
      : Array.isArray(m.content)
        ? m.content.map((part) => part?.type === "text" && typeof part.text === "string"
          ? { ...part, text: redactText(part.text, map) }
          : part)
        : m.content,
  }));
}

/**
 * Everything the person wrote in these messages, as one text to look for
 * identifiers in: plain-string content, and the text parts of content given
 * as a list of parts — which is how OpenAI clients send it, and how any
 * message with a picture attached arrives.
 *
 * Reading only the string form is the mistake this exists to stop making
 * twice. The enclave and the proxy both did: a message sent as parts was
 * scanned as empty, found to hold nothing, and went to the provider as
 * written while every stage reported that it had decided.
 */
export function messagesText(messages: readonly RequestMessage[]): string {
  return messages
    .map((m) => typeof m.content === "string"
      ? m.content
      : Array.isArray(m.content)
        ? m.content
          .filter((part) => part?.type === "text" && typeof (part as { text?: unknown }).text === "string")
          .map((part) => (part as { text: string }).text)
          .join(" ")
        : "")
    .join("\n");
}

/* lookalikes, caseForms and restoreText live in restoreCore.ts, with nothing
   imported, so the developer SDK can carry an exact copy (2026-10-15). */
/**
 * Locates the text a provider's stream frame carries, as slots that can be
 * read and written in place. Three providers, three shapes, and the frames
 * that carry no text at all (pings, start/stop events, usage) are simply not
 * slots — they pass through untouched.
 */
function textSlots(frame: unknown, provider: Provider): Array<{ text: string; set: (value: string) => void }> {
  const slots: Array<{ text: string; set: (value: string) => void }> = [];
  if (provider === "anthropic") {
    const j = frame as { type?: string; delta?: { type?: string; text?: string } };
    if (j?.type === "content_block_delta" && j.delta?.type === "text_delta" && typeof j.delta.text === "string") {
      const delta = j.delta;
      slots.push({ text: delta.text!, set: (value) => { delta.text = value; } });
    }
  } else if (provider === "openai") {
    const j = frame as { choices?: { delta?: { content?: string } }[] };
    for (const choice of j?.choices ?? []) {
      const delta = choice?.delta;
      if (delta && typeof delta.content === "string") {
        slots.push({ text: delta.content, set: (value) => { delta.content = value; } });
      }
    }
  } else {
    const j = frame as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
    for (const candidate of j?.candidates ?? []) {
      for (const part of candidate?.content?.parts ?? []) {
        if (part && typeof part.text === "string") {
          slots.push({ text: part.text, set: (value) => { part.text = value; } });
        }
      }
    }
  }
  return slots;
}

/** A frame of our own, for the tail left in the carry buffer when the stream
 *  ends. Shaped like the provider's own text frames so the client's existing
 *  parser handles it without knowing this happened. */
function textFrame(provider: Provider, text: string): unknown {
  if (provider === "anthropic") return { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } };
  if (provider === "openai") return { choices: [{ index: 0, delta: { content: text } }] };
  return { candidates: [{ content: { parts: [{ text }] } }] };
}

/**
 * How many characters at the end of `text` could still turn out to be the
 * start of an alias. Only that much has to be held back — everything before it
 * can be released immediately, which is what keeps the stream feeling live.
 */
function danglingPrefix(text: string, aliases: string[], max: number): number {
  const seen = lookalikes(text);
  /* Never hold back part of a stand-in that is already complete. "21-4862"
     starts and ends with a 2, so a reply ending "…21-4862" looked as if its
     last "2" might be the start of another one: that "2" was held, the
     stand-in was split across two writes, neither half matched, and the
     person read the stand-in (found 2026-09-30). Only what comes after the
     last complete stand-in can be the start of the next. */
  const free = seen.length - lastMatchEnd(seen, aliases);
  for (let k = Math.min(max, free); k > 0; k--) {
    const tail = seen.slice(seen.length - k);
    for (const alias of aliases) {
      if (alias.length > k && alias.startsWith(tail)) return k;
    }
  }
  return 0;
}

/** Where the last complete stand-in in `seen` ends, reading left to right,
 *  longest first — the same matches restoreText will make. */
function lastMatchEnd(seen: string, aliases: string[]): number {
  const sorted = [...aliases].sort((a, b) => b.length - a.length);
  let end = 0;
  let i = 0;
  while (i < seen.length) {
    // What is left could still grow into a longer stand-in ("Okonkwo" before
    // "Okonkwo Otieno" arrives): nothing from here on is settled.
    const rest = seen.slice(i);
    if (sorted.some((alias) => alias.length > rest.length && alias.startsWith(rest))) break;
    const hit = sorted.find((alias) => alias.length > 0 && seen.startsWith(alias, i));
    if (hit) { i += hit.length; end = i; } else i += 1;
  }
  return end;
}

/**
 * Puts the real values back on the way to the user.
 *
 * The naive version of this — replace over the raw bytes as they fly past —
 * does not work, and the way it fails is quiet. Providers stream token by
 * token, so "Desmond" arrives as "Des" in one SSE frame and "mond" in the
 * next, with a JSON envelope, a newline and a `data: ` prefix sitting between
 * the two halves. The alias is never contiguous in the byte stream, so a byte
 * replace matches nothing, and the user reads the alias instead of their own
 * name while every test on the request side still passes.
 *
 * So this decodes each frame, joins the text across frames, restores on that,
 * and writes the result back into the frame. Only the trailing characters that
 * could still be the start of an alias are held back, so the stream stays as
 * live as it was — one frame of latency in the worst case, none in the common
 * one. Whatever is still held when the stream ends goes out as a final frame
 * of our own, emitted before [DONE] so the client is still listening.
 */
export function restoreStream(
  body: ReadableStream<Uint8Array>,
  map: RedactionMap,
  provider: Provider,
  contentType: string,
): ReadableStream<Uint8Array> {
  // Longest stand-in first, so a half is never restored before the whole it
  // belongs to. restoreText sorts for the same reason; the stream path builds
  // its own list and needs its own sort.
  const entries = caseForms(Object.entries(map)).sort((a, b) => b[0].length - a[0].length);
  if (entries.length === 0) return body;

  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  // A non-streamed answer is one JSON document, so there are no frame
  // boundaries to work across — and no real value can carry a quote or a
  // backslash (see isSubstitutable), so replacing over the whole document
  // cannot break the JSON the client is about to parse.
  if (!contentType.includes("text/event-stream")) {
    let whole = "";
    return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk) { whole += decoder.decode(chunk, { stream: true }); },
      flush(controller) {
        controller.enqueue(encoder.encode(restoreText(whole + decoder.decode(), entries)));
      },
    }));
  }

  const aliases = entries.map(([fake]) => lookalikes(fake));
  const maxAlias = Math.max(...aliases.map((alias) => alias.length));
  let pending = "";  // bytes of a line not yet terminated by a newline

  /*
   * Text that could still be the head of an alias — one per slot, not one per
   * stream.
   *
   * A frame can carry more than one piece of text: Gemini sends several parts,
   * OpenAI several choices, and each is its own sequence continuing across
   * frames. With a single buffer, a tail held back from the first was handed to
   * the second, which is not a formatting problem — it moves text out of one
   * answer and into another, and the alias whose halves are now in different
   * places is never put back. The reader is left looking at the stand-in name
   * this whole file exists to remove, in a sentence that has been cut in half.
   */
  const carries: string[] = [];

  const flushCarry = (controller: TransformStreamDefaultController<Uint8Array>) => {
    for (let i = 0; i < carries.length; i++) {
      const carry = carries[i];
      if (!carry) continue;
      carries[i] = "";
      const text = restoreText(carry, entries);
      controller.enqueue(encoder.encode(`data: ${JSON.stringify(textFrame(provider, text))}\n\n`));
    }
  };

  const emit = (line: string, controller: TransformStreamDefaultController<Uint8Array>) => {
    const body = line.endsWith("\n") ? line.slice(0, -1) : line;
    const terminator = line.endsWith("\n") ? "\n" : "";

    if (!body.startsWith("data: ")) { controller.enqueue(encoder.encode(line)); return; }
    const payload = body.slice(6).trim();
    if (!payload) { controller.enqueue(encoder.encode(line)); return; }
    if (payload === "[DONE]") {
      // Last chance to say anything: everything after this is ignored.
      flushCarry(controller);
      controller.enqueue(encoder.encode(line));
      return;
    }

    let frame: unknown;
    try { frame = JSON.parse(payload); }
    catch { controller.enqueue(encoder.encode(line)); return; }

    const slots = textSlots(frame, provider);
    if (slots.length === 0) { controller.enqueue(encoder.encode(line)); return; }

    slots.forEach((slot, i) => {
      const joined = (carries[i] ?? "") + slot.text;
      const hold = danglingPrefix(joined, aliases, maxAlias - 1);
      carries[i] = joined.slice(joined.length - hold);
      slot.set(restoreText(joined.slice(0, joined.length - hold), entries));
    });
    controller.enqueue(encoder.encode(`data: ${JSON.stringify(frame)}${terminator}`));
  };

  return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      pending += decoder.decode(chunk, { stream: true });
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const line of lines) emit(`${line}\n`, controller);
    },
    flush(controller) {
      pending += decoder.decode();
      if (pending) emit(pending, controller);
      flushCarry(controller);
    },
  }));
}

/** The map rides back on a header so it costs no extra round trip and no
 *  server-side storage. Stage 1 produces about five entries; stages 3-4 will
 *  outgrow what a header can carry and will need a terminal SSE event. */
export function redactionHeader(map: RedactionMap): string | null {
  const entries = Object.entries(map);
  if (entries.length === 0) return null;
  const encode = (n: number) => b64urlEncode(new TextEncoder().encode(JSON.stringify(Object.fromEntries(entries.slice(0, n)))));
  const whole = encode(entries.length);
  if (whole.length <= HEADER_LIMIT) return whole;
  /* Too big for a header. It used to send nothing at all, so one long
     message cost the client every stand-in it had — the next turn minted
     fresh ones and the reply's swaps went undrawn. Now it sends the longest
     run that fits, oldest first: the entries carried from earlier turns are
     the ones the conversation already shows. What is left off is minted
     again next turn from the same real value (pickFake is stable), so it
     costs at most a stand-in that changes, never a value that leaks. */
  let lo = 0;
  let hi = entries.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (encode(mid).length <= HEADER_LIMIT) lo = mid;
    else hi = mid - 1;
  }
  return lo > 0 ? encode(lo) : null;
}

/** What one response header may carry. Proxies in front of the Worker
 *  (Vercel's /api/chat among them) refuse much larger. */
const HEADER_LIMIT = 4096;
