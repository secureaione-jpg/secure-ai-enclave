/**
 * Putting real values back, with nothing imported (2026-10-15).
 *
 * The restore half of redaction, cut out so it can run in the customer's own
 * app: the developer SDK holds a byte-for-byte copy of this file
 * (sdk/typescript/src/restore.ts, held by sdk/restoreDrift.test.ts), and the
 * Python SDK holds a port that answers sdk/restore-cases.json the same way.
 * The map never has to come back to us.
 *
 * The map runs stand-in → real value, as /v1/redact returns it.
 */

/**
 * The same text with every look-alike dash as "-" and every no-break or thin
 * space as " ", one character for one, so positions line up with the
 * original.
 *
 * A model writes a stand-in back the way it likes to typeset it: "21‑4862"
 * with a non-breaking hyphen, "Yusuf Duarte" with a no-break space. Matched
 * exactly, those were never restored, and the person read a number that is
 * not theirs.
 */
export function lookalikes(s: string): string {
  return s.replace(/[‐-―−﹘﹣－]/g, "-").replace(/[   ]/g, " ");
}

/** `to` written in the case `like` is in, where that case is all small or all
 *  capital letters; otherwise `to` as it is. */
export function sameCase(like: string, to: string): string {
  if (like === like.toLowerCase() && like !== like.toUpperCase()) return to.toLowerCase();
  if (like === like.toUpperCase() && like !== like.toLowerCase()) return to.toUpperCase();
  return to;
}

/**
 * Each stand-in with its all-small and all-capital forms, mapped to the real
 * value in the same case. Listed once each: the written form first, and a
 * form already present is not added again, so this can be applied twice.
 */
export function caseForms(entries: Array<[string, string]>): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const have = new Set<string>();
  const put = (fake: string, real: string) => {
    if (have.has(fake)) return;
    have.add(fake);
    out.push([fake, real]);
  };
  for (const [fake, real] of entries) put(fake, real);
  for (const [fake, real] of entries) {
    put(fake.toLowerCase(), sameCase(fake.toLowerCase(), real));
    put(fake.toUpperCase(), sameCase(fake.toUpperCase(), real));
  }
  return out;
}

/**
 * Put the real values back, in one pass.
 *
 * Replacing each stand-in in turn over the accumulating output lets a real
 * value that was just written be matched by a later stand-in, and the reader
 * is given the wrong person. So the text is walked once and nothing already
 * written is looked at again. Longest stand-in first, so "Okonkwo Otieno" is
 * restored whole before "Okonkwo" alone could match.
 */
export function restoreText(text: string, entries: Array<[string, string]>): string {
  const sorted = caseForms(entries)
    .filter(([fake]) => fake.length > 0)
    .map(([fake, real]): [string, string] => [lookalikes(fake), real])
    .sort((a, b) => b[0].length - a[0].length);
  if (sorted.length === 0) return text;
  // Matched on the look-alike-free copy; written from the original.
  const seen = lookalikes(text);

  /* Bucketed by first character so each position tries only the handful of
     stand-ins that could start there. */
  const byFirst = new Map<string, Array<[string, string]>>();
  for (const entry of sorted) {
    const head = entry[0][0];
    const bucket = byFirst.get(head);
    if (bucket) bucket.push(entry);
    else byFirst.set(head, [entry]);
  }

  let out = "";
  let i = 0;
  let plain = 0;
  while (i < text.length) {
    const bucket = byFirst.get(seen[i]);
    let hit: [string, string] | null = null;
    if (bucket) {
      for (const entry of bucket) {
        if (seen.startsWith(entry[0], i)) { hit = entry; break; }
      }
    }
    if (hit) {
      out += text.slice(plain, i) + hit[1];
      i += hit[0].length;
      plain = i;
    } else {
      i += 1;
    }
  }
  return cardTails(rewritten(plain === 0 ? text : out + text.slice(plain), entries), entries);
}

/*
 * A stand-in the model wrote back in its own style. An email re-cased
 * ("Colette.Marsh@Gmail.com"), a phone with other separators ("415-212-3344"
 * for "(415) 212-3344", or "+1" in front), a card with no spaces: matched
 * exactly, none was found, and the person read a number or an address that
 * is not theirs (leak hunt, 2026-11-14). An address is matched in any case;
 * a number by its digits, as a run of groups standing on its own, written
 * back as the person wrote it.
 */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NUMBER_SHAPE = /^[+(]?[\d][\d ().-]*\d$/;
const EMAIL_RUN = /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+/gu;
const NUMBER_RUN = /(?<![\p{L}\p{N}.])[+(]?\d(?:[\d().-]*[\d)])?(?:[ \t]+[+(]?\d(?:[\d().-]*[\d)])?)*(?![\p{L}\p{N}]|[.-]\d)/gu;
function rewritten(text: string, entries: Array<[string, string]>): string {
  const emails = new Map<string, string>();
  const numbers = new Map<string, string>();
  for (const [fake, real] of entries) {
    if (EMAIL_SHAPE.test(fake)) emails.set(fake.toLowerCase(), real);
    else if (NUMBER_SHAPE.test(fake) && NUMBER_SHAPE.test(real) && fake.replace(/\D/g, "").length >= 7) numbers.set(fake.replace(/\D/g, ""), real);
  }
  let out = text;
  if (emails.size > 0) out = out.replace(EMAIL_RUN, (run) => emails.get(run.toLowerCase()) ?? run);
  if (numbers.size === 0) return out;
  return out.replace(NUMBER_RUN, (run) => {
    // The groups of the run, any window of them: "on 3 Jan call 415 212 3344".
    const groups = [...run.matchAll(/\S+/g)];
    for (let len = groups.length; len >= 1; len -= 1) {
      for (let from = 0; from + len <= groups.length; from += 1) {
        const a = groups[from].index ?? 0;
        const last = groups[from + len - 1];
        const b = (last.index ?? 0) + last[0].length;
        const piece = run.slice(a, b);
        const real = numbers.get(piece.replace(/\D/g, ""));
        if (real !== undefined && real.replace(/\D/g, "") !== piece.replace(/\D/g, "")) {
          // A bracket the window cut in two is left as it was found.
          const lead = /^\)/.test(piece) ? ")" : "";
          // The stand-in's "+1" goes with it when the real number has its own
          // country code: "+1 415 212 3344" is "+44 7700 900123", not "+1 +44…".
          const before = /^\+?1[ \t]+$/.test(run.slice(0, a)) && real.startsWith("+") ? "" : run.slice(0, a);
          return before + lead + real + run.slice(b);
        }
      }
    }
    return run;
  });
}

/* A reply that names a card by its last four only: "a refund to the card
   ending in 4534". Those four are the stand-in's, and the whole number never
   appears for the pass above to find, so the reply came back with digits
   that belong to no card the user has (2026-10-25). Each card in the map
   lends its last four, stand-in to real, and only as four digits standing
   on their own. */
function cardTails(text: string, entries: Array<[string, string]>): string {
  const card = (v: string) => /^[\d -]+$/.test(v) && /^\d{13,19}$/.test(v.replace(/[ -]/g, ""));
  const tails = new Map<string, string>();
  for (const [fake, real] of entries) {
    if (!card(fake) || !card(real)) continue;
    const f = fake.replace(/\D/g, "").slice(-4);
    const r = real.replace(/\D/g, "").slice(-4);
    if (f !== r) tails.set(f, r);
  }
  if (tails.size === 0) return text;
  return text.replace(/(?<!\d)\d{4}(?!\d)/g, (four) => tails.get(four) ?? four);
}

const WORD = /^[\p{L}'-]+$/u;

/**
 * Half a stand-in name, and the half of the real name it stands for.
 *
 * A model writing to "Colette Marsh" says "Hi Colette", using half of a
 * stand-in no map lists. For a two-word stand-in standing for a two-word
 * name, each word maps to the matching word: Colette → Sarah, Marsh → Jones.
 *
 * Left out, so a real person is never renamed:
 *   - a stand-in word that is also a word of any real value ("Daniel Kowal"
 *     standing for someone, while a real Daniel is in the text);
 *   - a word that would map two ways;
 *   - a word the same in both.
 */
/* The second word of an organisation's stand-in ("Harrowgate Group") is an
   ordinary word, and a half of it put back would turn every "Group" a reply
   writes into "Ltd". Only the invented first word is a half. */
const ORG_KINDS = new Set(["Group", "Holdings", "Partners", "Associates", "Industries", "Institute", "Trust", "Systems"]);

export function halfNames(map: Record<string, string>): Array<[string, string]> {
  const realWords = new Set(Object.values(map).flatMap((r) => r.toLowerCase().split(/\s+/)));
  const pairs = new Map<string, string | null>();
  for (const [standIn, real] of Object.entries(map)) {
    const a = standIn.trim().split(/\s+/);
    const b = real.trim().split(/\s+/);
    if (a.length !== 2 || b.length !== 2 || ![...a, ...b].every((w) => WORD.test(w))) continue;
    for (const i of [0, 1]) {
      if (a[i] === b[i] || realWords.has(a[i].toLowerCase())) continue;
      if (i === 1 && ORG_KINDS.has(a[1])) continue;
      const seen = pairs.get(a[i]);
      pairs.set(a[i], seen === undefined || seen === b[i] ? b[i] : null);
    }
  }
  return [...pairs].filter((p): p is [string, string] => p[1] !== null);
}

/**
 * The whole restore: every stand-in in the map, then the halves of stand-in
 * names (halfNames) where they stand as words of their own.
 */
export function restore(text: string, map: Record<string, string>): string {
  let out = restoreText(text, Object.entries(map));
  for (const [from, to] of halfNames(map)) {
    out = out.replace(new RegExp(`(?<![\\p{L}])${from}(?![\\p{L}])`, "gu"), to);
  }
  return out;
}
