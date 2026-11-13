/**
 * Values under a field name: a record pasted as data rather than written as a
 * sentence.
 *
 * The patterns know a value by its shape and by the words in front of it.
 * Pasted data puts the word somewhere else — a column header two lines up, a
 * table cell to the left, a JSON key — and measured on ai4privacy's records
 * written out that way (bench/formats), a card number in a CSV was found
 * one time in twelve, an account number in a Markdown or HTML table one time
 * in a hundred, and a street in JSON or YAML never.
 *
 * This reads the field names those formats carry and reports the value under
 * each one it knows, with the kind the name says:
 *
 *   JSON        "card_number": "4111 …"
 *   colon/YAML  account_number: 0123…        (one per line)
 *   key=value   pin=4821 password="x y"
 *   tables      | iban | GB82 … |   <td>Email</td><td>…</td>
 *   columns     a header row — CSV, TSV, semicolons or a Markdown table —
 *               and the cells under it
 *
 * A value that is a placeholder is left alone: documentation is full of
 * `password: <your-password>`, `username: admin`, `token: ${TOKEN}`.
 */

import type { StructuredKind } from "./redactionStructured.js";

export type FieldValue = { start: number; end: number; kind: StructuredKind };

/** Field name, lower-cased with everything but letters and digits removed. */
// No prototype: a field called "constructor" in Python's documentation looked
// up Object's own constructor and came back as a kind (bench/formats diff).
const FIELD_KINDS: Record<string, StructuredKind> = Object.create(null);
const name = (kind: StructuredKind, ...names: string[]) => { for (const n of names) FIELD_KINDS[n] = kind; };
name("email", "email", "emailaddress", "mail", "contactemail", "workemail", "personalemail");
name("phone", "phone", "phonenumber", "telephone", "tel", "mobile", "mobilenumber", "cell", "cellphone", "fax", "contactnumber", "homephone", "workphone");
name("card", "cardnumber", "creditcard", "creditcardnumber", "ccnumber", "debitcard", "cvv", "cvc", "cvv2", "securitycode", "cardsecuritycode");
name("iban", "iban", "accountnumber", "bankaccount", "bankaccountnumber", "accountno", "acctno", "acctnumber", "bban", "bic", "swift", "swiftcode", "swiftbic", "routingnumber", "sortcode", "abanumber");
name("ssn", "ssn", "socialsecuritynumber", "socialsecurity");
name("govid", "passport", "passportnumber", "passportno", "driverslicense", "driverlicense", "licensenumber", "drivinglicence", "nationalid", "nationalidnumber", "idnumber", "taxid", "tin", "nino", "nationalinsurancenumber", "username", "userid", "loginname", "bitcoinaddress", "walletaddress", "medicalrecordnumber", "mrn", "employeeid", "customerid", "memberid", "patientid");
// Record fields Nemotron's practice rows (2026-10-08) put in two-column
// tables and XML: "| VIN | JN1FV… |", "<HealthPlanBeneficiaryNumber>…".
name("govid", "vin", "vehicleidentificationnumber", "vehicleid", "licenseplate", "licenceplate", "platenumber", "numberplate", "identificationnumber", "personalidnumber", "certificatelicensenumber", "certificatenumber", "healthplanbeneficiarynumber", "beneficiarynumber", "healthplannumber", "insuranceid", "policyholderid", "employeenumber", "staffid", "studentid", "accountid", "biometricidentifier");
name("secret", "password", "passwd", "pwd", "pin", "pincode", "passcode");
name("address", "street", "streetaddress", "address", "homeaddress", "mailingaddress", "billingaddress", "shippingaddress", "addressline1", "addressline2", "address1", "address2", "buildingnumber", "housenumber");
name("postcode", "zip", "zipcode", "postcode", "postalcode", "plz");
// The same fields as other countries name them, in a header row or before a
// colon: "nimi;hetu;puh", "ime,oib,iznos", "氏名,マイナンバー,電話",
// "শম,এনআইডি,মোবাইল" (realistic5, where every one went out). Written as
// fieldKind folds them: lower case, letters and digits only, in any script.
name("govid", "dni", "nie", "nif", "dninie", "nifnie", "hetu", "henkilötunnus", "pesel", "oib", "mbo", "rč", "rodnéčíslo", "ičo",
  "dič", "αφμ", "αμκα", "αδτ", "adószám", "adóazonosító", "adóazonosítójel", "tajszám", "nik", "npwp", "ktp", "nomorktp", "curp",
  "rfc", "cuit", "cuil", "cpf", "cnpj", "siret", "siren", "nir", "nin", "bvn", "bsn", "burgerservicenummer", "fnr", "fødselsnummer",
  "personnummer", "cpr", "cprnummer", "マイナンバー", "個人番号", "身份证号", "身份证号码", "身份证", "身分證字號", "주민등록번호", "주민번호",
  "תז", "תעודתזהות", "מספרזהות", "এনআইডি", "nid", "জাতীয়পরিচয়পত্র", "aadhaar", "aadhar", "आधार", "आधारसंख्या", "pan", "gstin",
  "رقمالهوية", "الهوية", "رقمالهويةالوطنية", "الرقمالقومي", "رقمالإقامة", "iqama", "emiratesid", "tckimlikno", "tckimlik", "kimlikno",
  "codicefiscale", "steuerid", "steueridnr", "svnr", "ahvnummer", "nss", "egn", "єгн", "инн", "снилс", "ипн", "рнокпп",
  // And as people type them into a spreadsheet's first row: "nome,niss,telemovel",
  // "ad;tc;eposta", "pangalan,sss,cellphone", "meno;ico;suma" (realistic5).
  // Not "run" or "cc", which are a CI step and a mail header.
  "niss", "sss", "sssno", "umid", "philhealth", "pagibig", "tc", "tcno", "ico", "cnp", "rut", "dpi", "cedula", "cédula", "nuip",
  "rg", "contribuinte", "utente", "kra", "nhis", "mykad", "nokp", "cccd", "cmnd", "nric", "hkid", "amka", "afm", "edrpou", "єдрпоу",
  "едрпоу");
name("phone", "msisdn", "telemovel", "telemóvel", "telèfon", "telefon", "telefono", "teléfono", "telefone", "téléphone", "tél", "tlf", "tlfnr", "puh", "puhelin", "mobil", "móvil",
  "celular", "handy", "gsm", "nomortelepon", "nohp", "電話", "電話番号", "携帯", "电话", "手机", "手机号", "電話號碼", "전화", "전화번호",
  "휴대폰", "هاتف", "رقمالهاتف", "جوال", "טלפון", "נייד", "মোবাইল", "ফোন", "मोबाइल", "फ़ोन", "फोन", "τηλέφωνο", "τηλ", "телефон", "тел");
name("email", "correo", "correoelectrónico", "courriel", "epost", "eposta", "sähköposti", "メール", "이메일", "邮箱", "電子郵件",
  "البريدالإلكتروني", "אימייל", "ইমেইল", "ईमेल", "почта");
name("address", "dirección", "direccion", "adresse", "adresa", "adres", "osoite", "cím", "alamat", "indirizzo", "morada", "endereço",
  "住所", "주소", "地址", "العنوان", "عنوان", "כתובת", "ঠিকানা", "पता", "διεύθυνση", "адрес");
name("postcode", "códigopostal", "codigopostal", "codepostal", "postnummer", "postinumero", "irányítószám", "kodepos", "郵便番号",
  "우편번호", "邮编", "الرمزالبريدي", "מיקוד", "postnr", "cp", "cap", "cep", "codicepostale", "postakodu", "kodpocztowy", "psč", "郵遞區號");
name("iban", "kontonummer", "kontonr", "númerodecuenta", "rib", "rekening", "tilinumero", "口座番号", "계좌번호", "账号");

/** The kind a field name says, or undefined. Letters and digits of any
 *  script, so "adószám" and "ת״ז" fold to names the lists above hold. */
export function fieldKind(field: string): StructuredKind | undefined {
  return FIELD_KINDS[field.normalize("NFC").toLowerCase().replace(/[^\p{L}\p{M}\p{N}]/gu, "")];
}

/** What a template, an example or an empty field holds instead of a value. */
const PLACEHOLDER = /^(?:|null|none|nil|n\/a|na|-+|\*+|x+|true|false|yes|no|undefined|unknown|redacted|hidden|changeme|change[-_ ]?me|password\d*|secret|example|test|admin|root|user|guest|default|string|required|optional|tbd|tba|todo|pending|unspecified|not[ _-](?:specified|provided|available|applicable)|\.\.\.|…)$/i;
const TEMPLATE = /[<>{}]|\$\{|\$\(|\$[A-Z_]|^%.*%$|^your[-_ ]|^my[-_ ]|example\.(?:com|org)|^https?:\/\//i;
/** The user names every manual uses, and a system's own identities:
 *  "system:serviceaccount:default:my-sa", "oidc:jane.doe". */
const EXAMPLE_USER = /^(?:foo|bar|baz|qux|jane|john|alice|bob|carol|dave|eve|tiger|scott|demo|dev|devuser|testuser|test-user|k8s-admin|kube-admin|operator|ubuntu|ec2-user|postgres|mysql|sa|(?:jane|john)[._]doe)$|[:/]/i;
/** Code where a value would be: a property read or a call
 *  ("os.environ['DB_PASSWORD']", "getpass()"), a type ("URLPatternComponentResult;"),
 *  a mask with a note ("******** (hidden)"). */
const CODE = /^[A-Za-z_$][\w$]*(?:\.[\w$]+|\[[^\]]*\]|\([^)]*\))+$|;$|^\*{3,}/;
/** A file a value is read from, not the value: "./password.txt", "~/.pgpass". */
const A_PATH = /^(?:\.{1,2}\/|~\/|\/[\w.-]+\/)|\.(?:txt|json|ya?ml|pem|key|env|cfg|conf|ini)$/i;
/** What `kubectl describe` prints for a secret it will not show: a size. */
const A_SIZE = /^\d+\s*(?:bytes?|b|kb|chars?|characters?)$/i;
/** A network address, where an `address` field holds one. */
const NETWORK = /\b\d{1,3}(?:\.\d{1,3}){3}\b|localhost|\.svc\b|cluster\.local|^[\w-]+(?:\.[\w-]+)+(?::\d+)?$/i;

function usable(value: string, kind: StructuredKind): boolean {
  const v = value.trim();
  if (v.length < 2 || v.length > 120) return false;
  if (PLACEHOLDER.test(v) || TEMPLATE.test(v) || A_SIZE.test(v) || A_PATH.test(v) || CODE.test(v)) return false;
  // Several sentences' worth of words is a description, not a value.
  if (v.split(/\s+/).length > 8) return false;
  if (kind === "address") {
    // A house number on its own, under "building_number".
    if (/^\d{1,5}[A-Za-z]?$/.test(v)) return true;
    // A street, not a network address: "10.0.0.1", "localhost:8080",
    // "10.0.0.10 kube-dns.kube-system.svc.cluster.local" are what an
    // `address` field holds in a config or a command's output — and a
    // street has a space in it, where a host ("kube-worker-1") does not.
    if (/^[\d.:]+$/.test(v) || NETWORK.test(v) || !/\s/.test(v)) return false;
    return /\p{L}/u.test(v);
  }
  if (kind === "email") return /@/.test(v);
  if (kind === "govid" && (EXAMPLE_USER.test(v) || v.length < 4)) return false;
  // An account number has digits; a BIC is its own shape. "Swift" is also a
  // programming language, in a table of client libraries.
  if (kind === "iban") return /\d{2}/.test(v) || /^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/.test(v);
  if (kind === "postcode") return /\d/.test(v) && v.length <= 10;
  if (kind === "phone" || kind === "card" || kind === "ssn") return /\d{2}/.test(v);
  return true;
}

/** A value's span, trimmed of the space and quotes around it. */
function trimSpan(text: string, start: number, end: number): [number, number] {
  const open = (s: string, c: string) => s.split(c).length - 1;
  for (;;) {
    while (start < end && /[\s"']/.test(text[start])) start += 1;
    while (end > start && /[\s"',;]/.test(text[end - 1])) end -= 1;
    // A bracket closing a call the value sits in: "passwd='kadidd!ehopper')".
    const last = text[end - 1];
    const pair = last === ")" ? "(" : last === "]" ? "[" : null;
    if (end > start && pair && open(text.slice(start, end), pair) < open(text.slice(start, end), last)) { end -= 1; continue; }
    return [start, end];
  }
}

const JSON_PAIR = /"([A-Za-z][\w -]{0,40})"\s*:\s*(?:"((?:[^"\\\n]|\\.)*)"|(-?\d[\d.]*))/gd;
const LINE_PAIR = /^[ \t]*-?[ \t]*([A-Za-z][\w -]{0,40}?)[ \t]*[:=][ \t]*(?!\/\/)([^\n]*?)[ \t]*$/gmd;
const KEY_EQUALS = /(?<![\w.-])([A-Za-z][\w-]{1,40})=(?:"([^"\n]*)"|'([^'\n]*)'|([^\s,;&)]+))/gd;
const MD_PAIR = /^[ \t]*\|[ \t]*([^|\n]{1,40}?)[ \t]*\|[ \t]*([^|\n]*?)[ \t]*\|[ \t]*$/gmd;
const HTML_PAIR = /<t[hd][^>]*>\s*([^<]{1,40}?)\s*<\/t[hd]>\s*<td[^>]*>\s*([^<]*?)\s*<\/td>/gid;
/** An XML element holding a value: <EmployeeID>005493</EmployeeID>. The
 *  closing tag must match, so the value never takes a tag with it. */
const XML_PAIR = /<([A-Za-z][\w.-]{0,40})(?:[ \t][^<>\n]{0,200})?>([^<>\n]{1,120})<\/\1>/gd;

type Indexed = RegExpMatchArray & { indices: Array<[number, number] | undefined> };
/** Where a match's value sits: the first of its value groups that took part. */
const valueAt = (m: RegExpMatchArray): [number, number] | undefined => (m as Indexed).indices.slice(2).find(Boolean);

export function findFields(text: string): FieldValue[] {
  const out: FieldValue[] = [];
  const add = (field: string, start: number, end: number) => {
    const kind = fieldKind(field);
    if (!kind) return;
    const [a, b] = trimSpan(text, start, end);
    if (b <= a || !usable(text.slice(a, b), kind)) return;
    // A label table, not a record: "USERNAME":"Username" is the text a form
    // shows for the field (WildChat, a translation file).
    if (text.slice(a, b).toLowerCase().replace(/[\s_-]/g, "") === field.toLowerCase().replace(/[\s_-]/g, "")) return;
    out.push({ start: a, end: b, kind });
  };

  for (const re of [JSON_PAIR, KEY_EQUALS, MD_PAIR, HTML_PAIR, XML_PAIR]) {
    for (const m of text.matchAll(re)) {
      const at = valueAt(m);
      if (at) add(m[1], at[0], at[1]);
    }
  }

  /* A colon or equals line, only inside a block of them: a YAML document, a
     config, a form dumped one field per line. Alone, "Label: value" is a
     sentence the labelled patterns already read with more care — "password:
     please ask Dave", "Address: 3 attempts failed", "IBAN: … and BIC: …" —
     and the field names here are a machine's: no spaces in them. */
  // A neighbour may be any short label ("Customer ID: ArnJoh35263" above
  // "Password: cowboy"); the field a value is taken under has no spaces.
  const lineOf = lineIndex(text);
  const pairs: Array<{ line: number; field: string; at: [number, number] }> = [];
  for (const m of text.matchAll(LINE_PAIR)) {
    const at = valueAt(m);
    if (!at || m[1].trim().split(/\s+/).length > 3) continue;
    // A value that opens a structure belongs to the JSON or table rule.
    if (/^[|{["]/.test(text.slice(at[0], at[1]))) continue;
    pairs.push({ line: lineOf(m.index), field: m[1].trim(), at });
  }
  const lines = new Set(pairs.map((p) => p.line));
  for (const p of pairs) {
    if (/\s/.test(p.field)) continue;
    if (lines.has(p.line - 1) || lines.has(p.line + 1)) add(p.field, p.at[0], p.at[1]);
  }
  for (const cell of columns(text)) add(cell.field, cell.start, cell.end);
  return out;
}

/** The line a position falls on, by binary search over the line starts. */
function lineIndex(text: string): (at: number) => number {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text[i] === "\n") starts.push(i + 1);
  return (at) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= at) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
}

/**
 * Cells under a header row. A header is a line of two or more short cells
 * with no digits, at least one of them a field name this knows; the rows
 * under it, up to the first blank line or a row with a different number of
 * cells, are read column by column.
 */
function columns(text: string): Array<{ field: string; start: number; end: number }> {
  const out: Array<{ field: string; start: number; end: number }> = [];
  const lines: Array<{ start: number; text: string }> = [];
  let at = 0;
  for (const line of text.split("\n")) {
    lines.push({ start: at, text: line });
    at += line.length + 1;
  }
  for (let i = 0; i < lines.length - 1; i += 1) {
    const sep = delimiter(lines[i].text);
    if (!sep) {
      // A column of one: the field name alone on its line and one value on
      // the next — "card_number\n4111…", a spreadsheet's single column, a
      // form copied a line at a time. Held to more than a table is, since a
      // heading followed by a short sentence has the same layout: no full
      // stop at the end, a digit or an @ in it, and no spaces in a password
      // or a user name.
      const field = lines[i].text.trim();
      const next = lines[i + 1].text;
      const value = next.trim();
      const kind = fieldKind(field);
      if (kind && value && !delimiter(next) && !/\.$/.test(value) && /[\d@]/.test(value)
        && !((kind === "secret" || kind === "govid") && /\s/.test(value))) {
        const lead = next.length - next.trimStart().length;
        out.push({ field, start: lines[i + 1].start + lead, end: lines[i + 1].start + lead + value.length });
      }
      continue;
    }
    const head = cells(lines[i].text, sep);
    if (head.length < 2) continue;
    // A header opens its table. A row inside one is data, however much it
    // looks like names: "| VIN | JN1FV8G78CJ123456 |" in a Field/Value
    // table read as a header took every label under it as a VIN.
    // A row has the header's cells, though: the sentence above a table may
    // have a comma of its own ("iz excela, napravi mi tablicu:" over
    // "ime,oib,iznos", realistic5), and every OIB under it was sent.
    if (i > 0 && delimiter(lines[i - 1].text) === sep && cells(lines[i - 1].text, sep).length >= head.length) continue;
    const names = head.map(([a, b]) => lines[i].text.slice(a, b).trim());
    // Names, not data: each opens with a letter ("address_line2" is a name,
    // "2024" and "4111 1111" are not).
    // In any script: Bengali and Hindi write their vowels as marks, Hebrew
    // abbreviates with ״ (ת״ז).
    if (!names.every((n) => n.length > 0 && n.length <= 40 && /^\p{L}[\p{L}\p{M}\d _/()#.'"״׳-]*$/u.test(n))) continue;
    // A header, not a sentence with a comma in it: two names this knows, or
    // every cell a single word the way a spreadsheet's columns are named.
    // "…changes of address, PIN" and "Included Fields...(ID, Email)" are
    // prose, and the line after them is not a row.
    const known = names.filter((n) => fieldKind(n)).length;
    // A known name may be two words, "Nama,No HP,Kota"; the others one each,
    // or "Hello Sarah, PIN" is a greeting.
    if (known === 0 || (known < 2 && names.some((n) => fieldKind(n) ? n.trim().split(/\s+/).length > 2 : /\s/.test(n)))) continue;
    for (let j = i + 1; j < lines.length; j += 1) {
      const row = lines[j].text;
      if (!row.trim()) break;
      if (sep === "|" && /^\s*\|?[\s:|-]+\|?\s*$/.test(row)) continue; // a Markdown rule line
      const got = cells(row, sep);
      // A row may have a cell or two more than its header when the last
      // column is an amount with a decimal comma ("Tomislav
      // Jurić,73015284961,1.200,00"): the columns before it still line up.
      if (got.length < head.length || got.length > head.length + 2) break;
      const lined = got.length === head.length ? head.length : head.length - 1;
      got.slice(0, lined).forEach(([a, b], k) => {
        if (fieldKind(names[k])) out.push({ field: names[k], start: lines[j].start + a, end: lines[j].start + b });
      });
    }
  }
  return out;
}

function delimiter(line: string): string | null {
  if (/^\s*\|.*\|\s*$/.test(line)) return "|";
  if (line.includes("\t")) return "\t";
  if (line.includes(";") && !line.includes(",")) return ";";
  if (line.includes(",")) return ",";
  return null;
}

/** The cells of a line, as spans, quotes understood. A Markdown row's outer
 *  bars are not cells. */
function cells(line: string, sep: string): Array<[number, number]> {
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
  if (sep === "|") {
    if (out.length && !line.slice(out[0][0], out[0][1]).trim()) out.shift();
    if (out.length && !line.slice(out[out.length - 1][0], out[out.length - 1][1]).trim()) out.pop();
  }
  return out;
}
