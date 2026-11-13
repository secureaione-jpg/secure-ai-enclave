/**
 * Phone numbers known by where they stand rather than by a label in front:
 *
 *   after an email   "julka.pietrzak@wp.pl, 698 214 557." — a contact line
 *                    gives the address and then the number.
 *   a chat's reply   "[21:10] Inês: tens o nº da Matilde?" and then
 *                    "[21:11] Rodrigo: 913 482 077" — the answer to someone
 *                    asking for a number is the number, "ага 89261234598".
 *
 * realistic5 sent all three (2026-10-26). Nine digits at least, so a time,
 * a price or a quantity is never one.
 */

export type ContextPhone = { start: number; end: number; kind: "phone" };

const PHONE = String.raw`\+?\d[\d \t().-]{7,17}\d`;
const digits = (s: string) => s.replace(/\D/g, "").length;

// No slash between: "…@p28-contacts.icloud.com/874161398/principal/" is a
// URL's path (Loghub, 2026-10-26).
const AFTER_EMAIL = new RegExp(
  String.raw`(?<=[\w.+-]+@[\w-]+(?:\.[\w-]+)+[ \t]*[,;|][ \t]*)(${PHONE})(?![\d\p{L}])`,
  "gdu",
);

/** A chat turn: "[21:11] Rodrigo: …", "Rodrigo: …", "- Rodrigo: …". */
const TURN = /^[ \t]*(?:\[[^\]\n]{1,20}\][ \t]*)?(?:[-–][ \t]*)?[\p{L}][\p{L}\p{M} .'’-]{0,30}:[ \t]*/u;
/** What someone says asking for a number, in the languages of the benchmark. */
const ASKED = /(?<![\p{L}])(?:n[º°]|n[úu]mero|numero|number(?![ \t]+of\b)|номер|номерок|телефон|тел|phone|cell|cel|celular|whatsapp|wa|mobile|m[óo]vil|telem[óo]vel|telefone?|tel[ée]fono|handy|puh(?:elin)?|电话|電話|手机|번호|전화|رقم|جوال|מספר|טלפון|nomor|no\s+hp|hp|sđt|số)(?![\p{L}])/iu;
/** A word or two said with the number: "ага", "sure", "aqui", "here". */
const LEAD = /^(?:[\p{L}!.,]{1,8}[ \t]+){0,2}/u;

export function findContextPhones(text: string): ContextPhone[] {
  const out: ContextPhone[] = [];
  for (const m of text.matchAll(AFTER_EMAIL)) {
    const [a, b] = (m as RegExpMatchArray & { indices: Array<[number, number]> }).indices[1];
    if (digits(m[1]) >= 9 && digits(m[1]) <= 15) out.push({ start: a, end: b, kind: "phone" });
  }
  const lines: Array<{ start: number; text: string }> = [];
  let at = 0;
  for (const line of text.split("\n")) {
    lines.push({ start: at, text: line });
    at += line.length + 1;
  }
  for (let i = 1; i < lines.length; i += 1) {
    const turn = TURN.exec(lines[i].text);
    if (!turn) continue;
    const said = lines[i].text.slice(turn[0].length);
    const lead = LEAD.exec(said)?.[0] ?? "";
    const rest = said.slice(lead.length);
    const m = new RegExp(String.raw`^(${PHONE})[ \t]*[.!]?[ \t]*$`, "u").exec(rest);
    // Not a round amount: "120 000 000".
    if (!m || digits(m[1]) < 9 || digits(m[1]) > 15 || /[ .,]000$/.test(m[1])) continue;
    // Somebody asked, within the three turns before.
    if (!lines.slice(Math.max(0, i - 3), i).some((l) => ASKED.test(l.text))) continue;
    const start = lines[i].start + turn[0].length + lead.length;
    out.push({ start, end: start + m[1].length, kind: "phone" });
  }
  return out;
}
