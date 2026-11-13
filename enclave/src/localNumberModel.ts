import type { NameModel } from "../../cloudflare-worker/redaction.js";

/**
 * The number stage, answered inside the enclave.
 *
 * The name stage stopped leaving the enclave in v22; this is the other half.
 * Until now the numbers the patterns left were shown to Llama 3.2 3B on
 * Workers AI, with the message around them, to ask which identify somebody.
 * They are judged here instead, from the words beside each number: a unit or
 * a currency after or before it, a year or a year-month, a street word after
 * it, or a word before it that names what it is ("account", "policy", "call",
 * "under"). A long bare number with none of that counts as an identifier.
 *
 * Measured on the number benchmark (cloudflare-worker/bench/liveStage, 2,000
 * documents of the ai4privacy practice set, 562 with numbers left to judge):
 *
 *   Llama 3.2 3B on Workers AI   recall 84.4%   no-harm precision 80.0%
 *   these rules                  recall 85.2%   no-harm precision 84.8%
 *
 * It answers the question redactionNumbers.ts asks (numberQuestion) in the
 * envelope readNumberReply already reads, so the stage runs unchanged.
 */

const UNIT = /^\s*(%|percent|ms\b|s\b|secs?\b|seconds?|mins?\b|minutes?|hrs?\b|hours?|days?|weeks?|months?|years?|yrs?\b|kg\b|g\b|lbs?\b|km\b|mi\b|miles?|m\b|cm\b|mm\b|gb\b|mb\b|kb\b|tb\b|units?|items?|pcs\b|pieces?|records?|requests?|rows?|pages?|users?|people|persons|customers|accounts|employees|staff|restarts?|checks?|times|each|x\b|dollars|euros|pounds|usd|eur|gbp|calories|steps|views|visits|downloads|orders|tickets|votes|points|copies|words|characters|lines|files|nodes|servers|cores|threads|mph|km\/h|rpm|°|degrees)/i;
const MONEY_BEFORE = /([$€£¥₹₽₩]|лв|kr|zł|R\$|CHF|USD|EUR|GBP)\s*$/;
const NOT_BEFORE = /\b(total|totals|amount|price|priced|cost|costs|sum|subtotal|qty|quantity|count|version|ver|v|page|pages|row|line|step|level|chapter|section|figure|fig|table|item|items|top|approximately|approx|nearly|almost|roughly|up to|at least|more than|less than|fewer than|increase|decrease|grew|fell|rose|dropped|budget|revenue|salary|paid|pay|owed|balance|fee|fees|rate|score|scored|rank|ranked|year|in the year|since|until|during)\s*[:#]?\s*$/i;
const ID_BEFORE = /\b(account|acct|a\/c|iban|number|num|no|nr|#|id|ident|identifier|ref|reference|customer|client|patient|member|membership|policy|claim|case|file|record|zip|zipcode|postal|postcode|post code|code|pin|ssn|tin|tax|vat|license|licence|passport|card|phone|tel|telephone|mobile|cell|fax|sort|routing|swift|bic|reg|registration|plate|vin|badge|employee|staff|student|matric|enrollment|enrolment|mrn|nhs|insurance|insured|beneficiary|contract|loan|mortgage|invoice|receipt|order|booking|reservation|confirmation|tracking|shipment|parcel|serial|imei|device|meter|unit|apt|apartment|suite|flat|room|house|building|lot|box|p\.?o\.? box|from|to|into|onto|at|in|is|was|call|calling|contact|reach|text|whatsapp|dial|ring|monitor|verify|confirm|check|update|use|using|with)\s*[:#.]?\s*$/i;
const STREET_AFTER = /^\s+([A-Z][\p{L}'-]+\s+){0,3}(street|st\b|road|rd\b|avenue|ave\b|lane|ln\b|drive|dr\b|boulevard|blvd|way|court|ct\b|place|pl\b|terrace|close|crescent|square|sq\b|parkway|highway|hwy|route|circle|trail|path|row|walk|strasse|straße|calle|rue|via|avenida|rua|laan|gatan|vej)/iu;

function isYear(d: string) { const n = +d; return d.length === 4 && n >= 1900 && n <= 2099; }
function isYearMonth(d: string) { if (d.length !== 6) return false; const y = +d.slice(0, 4), m = +d.slice(4, 6); return y >= 1900 && y <= 2099 && m >= 1 && m <= 12; }
function isDate8(d: string) { if (d.length !== 8) return false; const y = +d.slice(0, 4), m = +d.slice(4, 6), dd = +d.slice(6, 8); return y >= 1900 && y <= 2099 && m >= 1 && m <= 12 && dd >= 1 && dd <= 31; }

export function judgeNumbers(text: string, candidates: readonly string[]): string[] {
  const out: string[] = [];
  for (const c of candidates) {
    const i = text.indexOf(c);
    if (i < 0) continue;
    const before = text.slice(Math.max(0, i - 40), i);
    const after = text.slice(i + c.length, i + c.length + 40);
    const digits = c.replace(/\D/g, "");
    if (/^\d{1,3}(,\d{3})+(\.\d{1,2})?$/.test(c) || /^\d{1,6}\.\d{1,2}$/.test(c)) continue; // 1,200 or 3.5, not 7561.5671
    if (MONEY_BEFORE.test(before) || UNIT.test(after)) continue;
    if (isYear(digits) || isYearMonth(digits) || isDate8(digits)) continue;
    if (digits.length >= 9) { out.push(c); continue; }                               // too long to be a quantity
    if (STREET_AFTER.test(after)) { out.push(c); continue; }                        // 42 Wexford Street
    if (ID_BEFORE.test(before)) { out.push(c); continue; }
    if (NOT_BEFORE.test(before)) continue;
    if (digits.length >= 5) out.push(c);                                             // a bare long number
  }
  return out;
}

/** The question numberQuestion writes: the message, then the numbers found in
 *  it, comma-separated, on the line after "Numbers found in it:". */
export function readQuestion(user: string): { text: string; candidates: string[] } | null {
  const m = user.match(/^Message:\n([\s\S]*)\n\nNumbers found in it:\n([^\n]*)\n/);
  if (!m) return null;
  return { text: m[1].replace(/…$/, ""), candidates: m[2].split(", ").filter(Boolean) };
}

export const localNumberModel: NameModel = async (_system, user) => {
  const q = readQuestion(user);
  return { response: q ? judgeNumbers(q.text, q.candidates) : [] };
};
