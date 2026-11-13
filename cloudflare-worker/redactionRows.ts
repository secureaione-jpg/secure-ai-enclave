/**
 * The rest of a person's record, pasted as a row with no header (2026-10-31).
 *
 * "Emilie_Beatty53@hotmail.com,63652332,8824" is an email, an account number
 * and a PIN; "597,5987448817889806,39eUZxg2VqYSfcyBS4eMXzQWziAmHK" a CVV, a
 * card and a wallet. With a header the column names say so (redactionFields);
 * without one only the email has a shape of its own, and the numbers beside
 * it went out as written: a card was caught in 7% of headerless CSV rows, an
 * account in 1%, a PIN in 1% (formats bench, practice half).
 *
 * A row that already holds an email, an IBAN, a card, an SSN, a phone or a
 * street is somebody's record, and its other cells are that somebody's too.
 * So, in such a row only, a cell that is a whole value of one of these shapes
 * is hidden:
 *
 *   - digits alone, three or more (an account, a card, a PIN, a CVV, a
 *     building number, a postcode);
 *   - a phone with a plus or separators;
 *   - a BIC, a Bitcoin address, a street;
 *   - letters and digits in one token (a username, a password).
 *
 * A row with none of those anchors is left alone, which is what keeps an
 * order line — "ORD-48213,SKU-2231-B,120,19.99,2024-03-02" — whole. A table
 * with a header is left to the header.
 */
import { STREET_CELL_PATTERN } from "./redactionPatterns.js";
import type { StructuredKind } from "./redactionStructured.js";

export type RowCell = { start: number; end: number; kind: StructuredKind };

/** The kinds that make a row somebody's record. A postcode or an ID alone
 *  does not: either can be a misreading of a count. */
const ANCHORS = new Set<StructuredKind>(["email", "iban", "card", "ssn", "phone", "address"]);

const BIC = /^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/;
const BITCOIN = /^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,59})$/;
const PHONE = /^(?:\+\d[\d .()\-]{5,}\d|\(?\d{2,5}\)?[ .\-]\d[\d .\-]{4,}\d)$/;
/** A date, a time or an amount, which a record holds too and which is not
 *  what this is for. */
const NOT_A_PHONE = /^\d{4}-\d{2}-\d{2}$|^\d{1,2}[./-]\d{1,2}[./-]\d{2,4}$|^\d+[.,]\d{1,2}$/;
const TOKEN = /^(?=[^\s]*\p{L})(?=[^\s]*\d)[\p{L}\d_.\-!@#$%^&*+=?]{6,40}$/u;

function delimiterOf(line: string): string | null {
  if (line.includes("\t")) return "\t";
  if (line.includes(";") && !line.includes(",")) return ";";
  if (line.includes(",")) return ",";
  return null;
}

function cellsOf(line: string, sep: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let start = 0;
  let quoted = false;
  for (let i = 0; i <= line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') quoted = !quoted;
    if (i === line.length || (ch === sep && !quoted)) {
      out.push([start, i]);
      start = i + 1;
    }
  }
  return out;
}

/** The value a cell holds, its quotes and spaces off. */
function inner(line: string, [a, b]: [number, number]): [number, number] {
  while (a < b && /[\s"]/.test(line[a])) a += 1;
  while (b > a && /[\s"]/.test(line[b - 1])) b -= 1;
  return [a, b];
}

function kindOf(value: string): StructuredKind | null {
  const digits = value.replace(/[\s-]/g, "");
  if (/^\d+$/.test(digits) && /^\d[\d -]*$/.test(value)) {
    if (digits.length >= 13 && digits.length <= 19) return "card";
    if (digits.length >= 3 && digits.length <= 12) return "govid";
    return null;
  }
  if (NOT_A_PHONE.test(value)) return null;
  if (PHONE.test(value) && (value.match(/\d/g) ?? []).length >= 7) return "phone";
  if (BIC.test(value) && (/\d/.test(value) || value.length === 11)) return "iban";
  if (BITCOIN.test(value)) return "govid";
  if (STREET_CELL_PATTERN.test(value)) return "address";
  if (TOKEN.test(value)) return "govid";
  return null;
}

/** A cell a record could hold: short, and not a clause of a sentence. */
const isValue = (cell: string) =>
  cell.length <= 60 && cell.split(/\s+/).length <= 5 && !/[.!?:]$/.test(cell) && !/\s\p{Ll}{2,}\s/u.test(` ${cell} `.replace(/^ \p{Ll}/u, " X"));

/**
 * A new value strong enough to make the row a record by itself: a street, a
 * Bitcoin address, a phone with its plus, a card's length of digits. Not a
 * timestamp in milliseconds, microseconds or nanoseconds, which a log row
 * starts with: "1698771234567" is thirteen digits. Nor one digit repeated,
 * which is a placeholder.
 */
function strong(value: string, kind: StructuredKind): boolean {
  if (kind === "address") return true;
  if (kind === "phone") return value.startsWith("+");
  if (BITCOIN.test(value)) return true;
  const digits = value.replace(/[\s-]/g, "");
  return kind === "card" && !/^(\d)\1+$/.test(digits) &&!([13, 16, 19].includes(digits.length) && /^1[6-8]/.test(digits));
}

/** True for a row of names: every cell letters and underscores, no digits. */
const isHeader = (line: string, sep: string) =>
  cellsOf(line, sep).every(([a, b]) => /^[\s"]*[\p{L}_][\p{L}_ ./()-]*[\s"]*$/u.test(line.slice(a, b)));

/**
 * The cells to hide, as spans of `text`. `kindAt` gives the kind of whatever
 * the scan already claimed over a span, or null.
 */
export function findRowCells(
  text: string,
  kindAt: (start: number, end: number) => StructuredKind | null | undefined,
): RowCell[] {
  const out: RowCell[] = [];
  const headed = new Set<string>();
  let offset = 0;
  for (const line of text.split("\n")) {
    const base = offset;
    offset += line.length + 1;
    const sep = delimiterOf(line) ?? "\u0000";
    const cells = cellsOf(line, sep).map((c) => inner(line, c));
    if (cells.length > 30) continue;
    // A sentence with commas in it is not a row.
    if (cells.some(([a, b]) => !isValue(line.slice(a, b)))) continue;
    // A header names the columns for every row under it; those rows are
    // redactionFields' to read.
    const key = `${sep}${cells.length}`;
    if (isHeader(line, sep)) { headed.add(key); continue; }
    if (headed.has(key)) continue;

    const claimedKinds = cells.map(([a, b]) => (b > a ? kindAt(base + a, base + b) : null));
    const fresh = cells.map(([a, b], i) => (claimedKinds[i] || b <= a ? null : kindOf(line.slice(a, b))));
    const isStrong = cells.map(([a, b], i) => !!fresh[i] && strong(line.slice(a, b), fresh[i]!));
    // A line that is one value alone, "5987448817889806", is taken only if
    // that value is strong; two cells or more are a row.
    if (cells.length === 1) {
      if (isStrong[0] && fresh[0] !== "address") out.push({ start: base + cells[0][0], end: base + cells[0][1], kind: fresh[0]! });
      continue;
    }
    const anchored = claimedKinds.some((k) => k && ANCHORS.has(k)) || isStrong.some(Boolean);
    if (!anchored) continue;
    cells.forEach(([a, b], i) => {
      const kind = fresh[i];
      if (kind) out.push({ start: base + a, end: base + b, kind });
    });
  }
  return out;
}
