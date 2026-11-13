/**
 * Health records in the formats hospital systems exchange, read by their
 * fields rather than as prose: HL7 v2 messages, FHIR JSON, C-CDA XML, and a
 * spreadsheet export with a header row.
 *
 * In prose a name is found by a model and a date by its shape. A record says
 * what each value is: PID-5 is the patient's name, "birthDate" is a birth
 * date, <city> is a town, a column headed "last_name" holds surnames. Read
 * that way, "Becker^Harold^James" is three names and "19310502" a birth
 * date, which no sentence-trained model reads from "PID|1||00482913^^^MERCY
 * ^MR||Becker^Harold^James||19310502|M". And the codes beside them —
 * LOINC 4548-4, SNOMED 385093006, ICD-10 J18.9, RxNorm 860975 — are what
 * the record is about, and their fields say so too, so they stay.
 *
 * Used by medical mode (redactionMedical.ts). Nothing here guesses: a value
 * is taken only from a field that names what it is.
 */

export type RecordKind = "name" | "date" | "id" | "place" | "address" | "phone" | "email" | "ssn" | "facility";
/** `start` is where the value stands in the text, when the reader knows it:
 *  searching 170,000 characters again for each of 18,000 values was most of
 *  five seconds (2026-10-08). */
export type RecordFinding = { kind: RecordKind; value: string; start?: number };

// ── HL7 v2 ────────────────────────────────────────────────────

/** Which components of which field are what, per segment. 1-based field
 *  numbers as the standard counts them (MSH counts its separator as 1). */
type Part = RecordKind | "name-parts" | "address-parts" | "xcn";
const HL7_FIELDS: Record<string, Record<number, Part>> = {
  MSH: { 7: "date" },
  EVN: { 2: "date", 6: "date" },
  PID: { 2: "id", 3: "id", 4: "id", 5: "name-parts", 6: "name-parts", 7: "date", 9: "name-parts", 11: "address-parts", 13: "phone", 14: "phone", 18: "id", 19: "ssn", 20: "id", 29: "date" },
  PD1: { 4: "xcn" },
  NK1: { 2: "name-parts", 4: "address-parts", 5: "phone", 6: "phone" },
  PV1: { 7: "xcn", 8: "xcn", 9: "xcn", 17: "xcn", 19: "id", 44: "date", 45: "date" },
  PV2: { 8: "date", 9: "date" },
  ORC: { 9: "date", 12: "xcn" },
  OBR: { 7: "date", 8: "date", 14: "date", 16: "xcn", 22: "date", 32: "xcn" },
  OBX: { 14: "date", 16: "xcn", 19: "date" },
  IN1: { 16: "name-parts", 19: "address-parts", 36: "id" },
  GT1: { 3: "name-parts", 5: "address-parts", 6: "phone", 12: "ssn" },
  DG1: { 5: "date" },
  AL1: { 6: "date" },
  TXA: { 4: "date", 22: "xcn" },
  // Scheduling and the people on it.
  SCH: { 12: "xcn", 16: "xcn", 20: "xcn" },
  AIP: { 3: "xcn", 6: "date" },
  AIS: { 4: "date" },
  // Roles, referrals, pharmacy, merges.
  ROL: { 4: "xcn" },
  PRD: { 2: "name-parts", 3: "address-parts", 5: "phone" },
  RXA: { 3: "date", 4: "date", 10: "xcn" },
  RXE: { 13: "xcn" },
  RXO: { 14: "xcn" },
  MRG: { 1: "id", 5: "id", 7: "name-parts" },
};
const HL7_SEGMENT = /^(?:MSH|EVN|PID|PD1|NK1|PV1|PV2|ORC|OBR|OBX|IN1|GT1|DG1|AL1|TXA|NTE|SCH|AIP|AIS|AIL|ROL|PRD|RXA|RXE|RXO|MRG)\|/m;

function hl7(text: string, out: RecordFinding[]): void {
  if (!HL7_SEGMENT.test(text)) return;
  let pos = 0;
  for (const line of text.split(/\r\n|\r|\n/)) {
    const lineStart = text.indexOf(line, pos);
    pos = lineStart + line.length;
    const seg = line.slice(0, 3);
    const map = HL7_FIELDS[seg];
    if (!map || line[3] !== "|") continue;
    const fields = line.split("|");
    // MSH-1 is the separator itself, so MSH-n sits at index n-1.
    const at = (n: number) => (seg === "MSH" ? fields[n - 1] : fields[n]);
    for (const [n, part] of Object.entries(map)) {
      const field = at(Number(n));
      if (!field) continue;
      for (const rep of field.split("~")) {
        const c = rep.split("^");
        const add = (kind: RecordKind, v: string | undefined) => {
          const value = (v ?? "").replace(/\\[A-Z]\\/g, "").trim();
          if (!value || !/[\p{L}\p{N}]/u.test(value)) return;
          const at = line.indexOf(value);
          out.push({ kind, value, start: at < 0 ? undefined : lineStart + at });
        };
        switch (part) {
          case "name-parts": add("name", c[0]); add("name", c[1]); add("name", c[2]); break;
          // XCN: id ^ family ^ given ^ middle.
          case "xcn": add("id", /\d/.test(c[0] ?? "") ? c[0] : ""); add("name", c[1]); add("name", c[2]); add("name", c[3]); break;
          // XAD: street ^ other ^ city ^ state ^ zip ^ country.
          case "address-parts": add("address", c[0]); add("address", c[1]); add("place", c[2]); add("place", c[4]); break;
          case "date": add("date", c[0]); break;
          case "id": add("id", c[0]); break;
          default: add(part, c[0]);
        }
      }
    }
  }
}

// ── FHIR JSON ─────────────────────────────────────────────────

/** Keys whose string value is the thing itself. */
const FHIR_KEYS: Record<string, RecordKind> = {
  family: "name", given: "name",
  line: "address", city: "place", district: "place", postalCode: "place",
  birthDate: "date", deceasedDateTime: "date", effectiveDateTime: "date", issued: "date", authoredOn: "date",
  recorded: "date", occurrenceDateTime: "date", onsetDateTime: "date", abatementDateTime: "date", start: "date",
  end: "date", date: "date", collectedDateTime: "date", performedDateTime: "date", assertedDate: "date",
};
/** A reference to a person's own resource: "Patient/88123". */
const PERSON_REFERENCE = /^(?:Patient|Practitioner|RelatedPerson|Person|Encounter|EpisodeOfCare|Account|Coverage)\/[\w.-]{1,64}$/;

function fhir(text: string, out: RecordFinding[]): void {
  // A resource, or a fragment of one cut from a log: two of a person's keys.
  if (!/"resourceType"\s*:/.test(text) && (text.match(/"(?:family|given|birthDate|postalCode|deceasedDateTime)"\s*:|"reference"\s*:\s*"(?:Patient|Practitioner|RelatedPerson)\//g)?.length ?? 0) < 2) return;
  let root: unknown;
  try { root = JSON.parse(text); } catch { root = null; }
  if (root !== null) {
    const walk = (node: unknown, key: string, parentKey: string, resourceType: string) => {
      if (Array.isArray(node)) { for (const v of node) walk(v, key, parentKey, resourceType); return; }
      if (node && typeof node === "object") {
        const o = node as Record<string, unknown>;
        const rt = typeof o.resourceType === "string" ? o.resourceType : resourceType;
        // A person's own resource id: "Patient/pat-00482913" is referred to by it.
        if (typeof o.resourceType === "string" && /^(?:Patient|Practitioner|RelatedPerson|Person)$/.test(o.resourceType) && typeof o.id === "string") out.push({ kind: "id", value: o.id });
        for (const [k, v] of Object.entries(o)) walk(v, k, key, rt);
        return;
      }
      if (typeof node !== "string" || !node.trim()) return;
      const kind = FHIR_KEYS[key];
      if (kind) { out.push({ kind, value: node }); return; }
      // A name, a phone or an identifier's value, by what holds it.
      if (key === "text" && parentKey === "name") { out.push({ kind: "name", value: node }); return; }
      if (key === "value" && (parentKey === "telecom" || parentKey === "identifier")) { out.push({ kind: parentKey === "telecom" ? "phone" : "id", value: node }); return; }
      if (key === "reference" && PERSON_REFERENCE.test(node)) { out.push({ kind: "id", value: node }); return; }
      // The display of a person it points at: "subject": {"display": "Harold Becker"}.
      if (key === "display" && /^(?:subject|patient|requester|performer|recorder|asserter|author|practitioner|participant|individual|informant|beneficiary|subscriber|policyHolder)$/.test(parentKey)) {
        out.push({ kind: "name", value: node.replace(/,[ \t]*(?:MD|DO|NP|PA|RN|PhD|DPM)\.?$/, "") });
        return;
      }
      if (key === "display" && parentKey === "serviceProvider") out.push({ kind: "facility", value: node });
    };
    walk(root, "", "", "");
    return;
  }
  // Not whole JSON (a fragment pasted from a log): the same keys, read as text.
  for (const m of text.matchAll(/"(\w+)"\s*:\s*(\[\s*(?:"[^"\n]{1,200}"\s*,?\s*){1,6}\]|"[^"\n]{1,200}")/g)) {
    const kind = FHIR_KEYS[m[1]];
    if (!kind) continue;
    for (const v of m[2].matchAll(/"([^"\n]{1,200})"/g)) out.push({ kind, value: v[1] });
  }
  for (const m of text.matchAll(/"reference"\s*:\s*"([^"\n]{1,80})"/g)) if (PERSON_REFERENCE.test(m[1])) out.push({ kind: "id", value: m[1] });
}

// ── C-CDA XML ─────────────────────────────────────────────────

const CDA_TAGS: Record<string, RecordKind> = { given: "name", family: "name", streetAddressLine: "address", city: "place", county: "place", postalCode: "place" };

function cda(text: string, out: RecordFinding[]): void {
  if (!/<(?:ClinicalDocument|recordTarget|patientRole)\b/.test(text)) return;
  for (const m of text.matchAll(/<(given|family|streetAddressLine|city|county|postalCode)\b[^>]{0,200}>([^<]{1,200})<\/\1>/g)) out.push({ kind: CDA_TAGS[m[1]], value: m[2].trim() });
  for (const m of text.matchAll(/<(?:birthTime|deceasedTime|effectiveTime|time|low|high)\b[^>]{0,200}?\bvalue="(\d{8,14}(?:[+-]\d{4})?)"/g)) out.push({ kind: "date", value: m[1] });
  for (const m of text.matchAll(/<telecom\b[^>]{0,200}?\bvalue="(?:tel:|fax:|mailto:)?([^"]{4,100})"/g)) out.push({ kind: /@/.test(m[1]) ? "email" : "phone", value: m[1] });
  // An identifier's extension, not its root: the root names the issuing system.
  for (const m of text.matchAll(/<id\b[^>]{0,200}?\bextension="([^"]{2,64})"/g)) out.push({ kind: "id", value: m[1] });
}

// ── A spreadsheet export ──────────────────────────────────────

/** Column headers and what their column holds. */
const CSV_COLUMNS: Array<[RegExp, RecordKind]> = [
  [/^(?:patient[ _]?)?(?:first|given|middle|last|family|sur|full)?[ _]?name$|^(?:first|last|given|family|surname|forename)s?$/i, "name"],
  [/^(?:dob|date[ _]?of[ _]?birth|birth[ _]?date|birthdate)$/i, "date"],
  [/(?:^|[ _])(?:date|datetime|dt|admit|admission|discharge|death|visit|seen|service)(?:[ _]?(?:date|time|dt))?$/i, "date"],
  [/^(?:zip|zip[ _]?code|post[ _]?code|postal[ _]?code)$/i, "place"],
  [/^(?:city|town|county)$/i, "place"],
  [/^(?:address|street|street[ _]?address|address[ _]?line[ _]?\d?)$/i, "address"],
  [/^(?:phone|telephone|mobile|cell|fax)(?:[ _]?(?:number|no))?$/i, "phone"],
  [/^e[-_ ]?mail(?:[ _]?address)?$/i, "email"],
  [/^(?:ssn|social[ _]?security(?:[ _]?number)?)$/i, "ssn"],
  [/^(?:mrn|patient[ _]?id|medical[ _]?record[ _]?(?:number|no)|member[ _]?id|account[ _]?(?:number|no)|encounter[ _]?id|visit[ _]?id|subject[ _]?id)$/i, "id"],
];

function splitCsv(line: string, sep: string): string[] {
  const cells: string[] = [];
  let cur = "", quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === "\"" && line[i + 1] === "\"") { cur += "\""; i++; }
      else if (ch === "\"") quoted = false;
      else cur += ch;
    } else if (ch === "\"") quoted = true;
    else if (ch === sep) { cells.push(cur); cur = ""; }
    else cur += ch;
  }
  cells.push(cur);
  return cells.map((c) => c.trim());
}

function csv(text: string, out: RecordFinding[]): void {
  const lines = text.split(/\r\n|\r|\n/);
  const starts: number[] = [];
  for (let i = 0, pos = 0; i < lines.length; i++) {
    starts.push(text.indexOf(lines[i], pos));
    pos = starts[i] + lines[i].length;
  }
  for (let h = 0; h < lines.length - 1; h++) {
    const sep = lines[h].includes("\t") ? "\t" : lines[h].includes(";") && !lines[h].includes(",") ? ";" : ",";
    const header = splitCsv(lines[h], sep);
    if (header.length < 3) continue;
    const kinds = header.map((cell) => CSV_COLUMNS.find(([re]) => re.test(cell))?.[1]);
    // A header names at least two personal columns, and the rows after it
    // have as many cells.
    if (kinds.filter(Boolean).length < 2) continue;
    for (let r = h + 1; r < lines.length; r++) {
      const cells = splitCsv(lines[r], sep);
      if (cells.length !== header.length) break;
      cells.forEach((cell, i) => {
        const kind = kinds[i];
        if (kind && cell && /[\p{L}\p{N}]/u.test(cell)) {
          const at = lines[r].indexOf(cell);
          out.push({ kind, value: cell, start: at < 0 ? undefined : starts[r] + at });
        }
      });
    }
    return;
  }
}

/** Every personal value a record's fields name, in the formats above. */
export function findRecordFields(text: string): RecordFinding[] {
  const out: RecordFinding[] = [];
  hl7(text, out);
  fhir(text, out);
  cda(text, out);
  csv(text, out);
  // Where each stands, when its reader could not say: searched from where
  // the last was found, as a record is read in order.
  let cursor = 0;
  for (const f of out) {
    if (f.start !== undefined && text.startsWith(f.value, f.start)) continue;
    let at = text.indexOf(f.value, cursor);
    if (at < 0) at = text.indexOf(f.value);
    f.start = at < 0 ? undefined : at;
    if (at >= 0) cursor = at;
  }
  // In the text as written, once each, and not a bare code system or unit.
  const seen = new Set<string>();
  return out.filter((f) => {
    const key = `${f.kind}:${f.value}`;
    if (seen.has(key) || f.start === undefined) return false;
    seen.add(key);
    return !/^(?:https?:|urn:)/.test(f.value) && f.value.length <= 200;
  });
}
