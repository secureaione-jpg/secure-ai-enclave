/**
 * National IDs and street addresses in the scripts and countries no other
 * rule reads: the United Arab Emirates, Israel, Russia, Vietnam and
 * Indonesia. Found by the third realistic hold-out (legal and accounting
 * messages, 2026-10-24), and written from each country's published format,
 * never from its sentences.
 *
 *   Emirates ID   784-YYYY-NNNNNNN-C: 784 is the country, then the holder's
 *                 birth year, and a Luhn check digit over all fifteen.
 *   Israeli ID    ת"ז / תעודת זהות and nine digits whose doubled-alternate
 *                 digit sum ends in 0.
 *   SNILS         СНИЛС and NNN-NNN-NNN CC, the last two a weighted sum of
 *                 the first nine, mod 101.
 *   NIK           NIK and sixteen digits: the province (11–94), then the day
 *                 of birth (plus 40 for a woman) and the month.
 *   Streets       רחוב/שדרות and a name and a number; ул./улица/проспект and
 *                 a name and д.; số and a number and a capitalised street;
 *                 Jl./Jalan and a name and No.
 *   Postcode      Poland's NN-NNN between a house number and its town:
 *                 "ul. Długa 17/4, 00-238 Warszawa".
 *
 * Each ID needs its label or its own dashed shape, and passes its check:
 * "784-1987-…" in a sentence about something else is not taken unless the
 * digits add up.
 */

export type MoreScriptsValue = { start: number; end: number; kind: "govid" | "address" | "postcode" };

function luhn(digits: string): boolean {
  let total = 0;
  for (let i = 0; i < digits.length; i += 1) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2) n = n * 2 > 9 ? n * 2 - 9 : n * 2;
    total += n;
  }
  return total % 10 === 0;
}

function israeliId(digits: string): boolean {
  const d = digits.padStart(9, "0");
  if (d.length !== 9) return false;
  let total = 0;
  for (let i = 0; i < 9; i += 1) {
    const n = Number(d[i]) * (i % 2 ? 2 : 1);
    total += n > 9 ? n - 9 : n;
  }
  return total % 10 === 0;
}

function snils(digits: string): boolean {
  if (digits.length !== 11) return false;
  let total = 0;
  for (let i = 0; i < 9; i += 1) total += Number(digits[i]) * (9 - i);
  const check = total < 100 ? total : total === 100 || total === 101 ? 0 : total % 101 === 100 ? 0 : total % 101;
  return check === Number(digits.slice(9));
}

function nik(digits: string): boolean {
  if (digits.length !== 16) return false;
  const province = Number(digits.slice(0, 2));
  const day = Number(digits.slice(6, 8));
  const month = Number(digits.slice(8, 10));
  return province >= 11 && province <= 94 && ((day >= 1 && day <= 31) || (day >= 41 && day <= 71)) && month >= 1 && month <= 12;
}

const EMIRATES_ID = /(?<!\d)(784-?(?:19|20)\d\d-?\d{7}-?\d)(?![\d-])/g;
const ISRAELI_ID = /(?:ת["”״]ז|ת\.ז\.?|תעודת\s+זהות|מספר\s+זהות)\s*[:：]?\s*(\d{8,9})(?!\d)/gu;
const SNILS = /СНИЛС(?:\s*№)?\s*[:：]?\s*(\d{3}[- ]?\d{3}[- ]?\d{3}[- ]?\d{2})(?![\d-])/giu;
const NIK = /\bNIK\b\s*[:：]?\s*(\d{16})(?!\d)/g;

const HEBREW_STREET = /((?:רחוב|רח['׳]|שדרות|שד['׳])\s+[\p{Script=Hebrew}"'׳״-]+(?:\s+[\p{Script=Hebrew}"'׳״-]+){0,2}\s+\d{1,4})(?![\d\p{L}])/gu;
const RUSSIAN_STREET = /((?:ул\.|улица|пр-т|проспект|пер\.|переулок|бульвар|б-р|наб\.|набережная|ш\.|шоссе)\s*\p{Lu}[\p{L}-]+(?:\s+\p{Lu}[\p{L}-]+){0,2},?\s*(?:д\.|дом)\s*\d{1,4}[а-я]?(?:\s*,\s*(?:корп\.|корпус|стр\.|строение|кв\.|квартира|оф\.|офис)\s*\d{1,4}[а-я]?)*)(?![\d\p{L}])/gu;
const VIETNAMESE_STREET = /(?<![\p{L}])((?:số|Số)\s+\d{1,4}[A-Za-z]?(?:\/\d{1,4})?\s+\p{Lu}[\p{L}]*(?:\s+\p{Lu}[\p{L}]*){0,4})(?![\p{L}])/gu;
// The house number after a street's name: "Długa 17/4, 00-238", not a
// journal's "2023, 8, 10–114 CrossRef".
const POLISH_POSTCODE = /(?<=\p{L}{2,}\.?\s+\d{1,4}[A-Za-z]?(?:\/\d{1,4})?,\s?)(\d{2}-\d{3})(?=\s+\p{Lu}\p{Ll}{2,})/gu;
const INDONESIAN_STREET = /(?<![\p{L}])((?:Jl\.|Jln\.|Jalan)\s*\p{Lu}[\p{L}.'-]*(?:\s+\p{Lu}[\p{L}.'-]*){0,4}\s+No\.?\s*\d{1,4}[A-Za-z]?)(?![\d\p{L}])/gu;

export function findMoreScriptValues(text: string): MoreScriptsValue[] {
  const out: MoreScriptsValue[] = [];
  const take = (re: RegExp, kind: MoreScriptsValue["kind"], ok: (digits: string) => boolean = () => true) => {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const value = m[1];
      if (!ok(value.replace(/\D/g, ""))) continue;
      const start = (m.index ?? 0) + m[0].lastIndexOf(value);
      out.push({ start, end: start + value.length, kind });
    }
  };
  take(EMIRATES_ID, "govid", luhn);
  take(ISRAELI_ID, "govid", israeliId);
  take(SNILS, "govid", snils);
  take(NIK, "govid", nik);
  take(HEBREW_STREET, "address");
  take(RUSSIAN_STREET, "address");
  take(VIETNAMESE_STREET, "address");
  take(INDONESIAN_STREET, "address");
  take(POLISH_POSTCODE, "postcode");
  return out;
}

/**
 * A postcode beside its town, in the address of any country (realistic5,
 * where 92 went out): after it, "Masarykova 1123/45, 602 00 Brno", "Lakcím:
 * 6720 Szeged", "35250 İzmir"; or before it, "Chennai - 600042", "กรุงเทพฯ
 * 10310", "Харків, 61002", "QUEZON CITY 1100". The number alone is anything,
 * so the hundred characters before it must read as an address (a street and
 * its number, or the word for an address) and the town must be a word, not a
 * unit, a currency or a year.
 */
// Lithuania, Latvia and Estonia write the country in front ("LT-01103",
// "LV-1011"); Brazil's CEP is five and three ("01414-001"); Argentina's CPA is
// a letter, four digits and three letters ("C1045AAB"). Address practice set,
// 2026-10-26.
const POSTCODE_SHAPE = String.raw`(?:(?:LT|LV|EE)-\d{4,5}|[A-HJ-NP-Z]\d{4}[A-Z]{3}|\d{5}-\d{3}|\d{3}[ ]\d{2}|\d{2}-\d{3}|\d{4}-\d{3}|\d{4,7})`;
const TOWN_WORD = String.raw`(?:\p{Lu}\p{Ll}[\p{L}\p{M}'’.-]+|\p{Lu}{3,}|[\p{Lo}][\p{L}\p{M}]+)`;
// A space or a comma between the number and its town, on both sides: digits
// touching letters are part of a token, a hash, an address or a VIN.
const POSTCODE_THEN_TOWN = new RegExp(String.raw`(?<![\p{L}\p{N}.,/:_-]|\d[ ])(${POSTCODE_SHAPE})(?:[ \t]+|[ \t]*[,–-][ \t]*)(?=(${TOWN_WORD}))(?![\p{L}\p{M}'’.-]*\p{Ll}\p{Lu})`, "gu");
const TOWN_THEN_POSTCODE = new RegExp(String.raw`(?<=[\p{L}\p{M}.](?:[ \t]+|[ \t]*[,–-][ \t]*))(${POSTCODE_SHAPE})(?![\p{N}\p{L}_:/\]-]|[.,]\d|\.\p{L}|[ \t]*(?:[%$€£₹₩¥]|\p{Script=Latin}))`, "gu");
// A street name followed by its house number and a comma, and not a date or
// a code: "April 13, 1743", "RFC 2945, RFC 5054" (real chats).
const STREET_NUMBER = /(\p{L}{3,})\.?[ \t]\d{1,4}\p{L}?(?:[/-]\d{1,4}\p{L}?)?,/gu;
const MONTHS = new Set(["jan", "january", "feb", "february", "mar", "march", "apr", "april", "may", "jun", "june", "jul", "july", "aug", "august", "sep", "sept", "september", "oct", "october", "nov", "november", "dec", "december", "janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre", "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre", "januar", "februar", "märz", "juni", "juli", "oktober", "dezember", "gennaio", "febbraio", "aprile", "maggio", "giugno", "luglio", "settembre", "ottobre", "dicembre", "janeiro", "fevereiro", "março", "maio", "junho", "julho", "setembro", "outubro", "novembro", "dezembro"]);
// Nor a part of a document or a count: "See Table 4, 2500 Respondents".
const NUMBERED_THINGS = new Set(["table", "tables", "figure", "fig", "chapter", "section", "page", "pages", "step", "item", "part", "note", "version", "level", "phase", "stage", "round", "line", "row", "column", "appendix", "exhibit", "article", "paragraph", "para", "clause", "rule", "question", "example", "option", "slide", "week", "day", "year", "grade", "class", "lesson", "unit", "volume", "issue", "episode", "season", "verse", "psalm", "game", "match", "test", "exercise", "problem", "task", "tabelle", "kapitel", "abschnitt", "seite", "tableau", "chapitre", "tabla", "capítulo", "página", "tabella", "capitolo", "pagina"]);
const STREET_RIGHT_BEFORE = /(\p{L}{3,})[.“”"»]?[ \t]\d{1,4}\p{L}?(?:[/-]\d{1,4}\p{L}?)?,[ \t]*$/u;
// The word's own letters, not the Japanese or Chinese written onto it
// ("ご自身のAugust 25, 1953").
const ownWord = (w: string) => /\p{Script=Latin}+$/u.exec(w)?.[0] ?? w;
const streetRightBefore = (before: string) => {
  const m = STREET_RIGHT_BEFORE.exec(before);
  const w = m && ownWord(m[1]);
  return !!w && !MONTHS.has(w.toLowerCase()) && !NUMBERED_THINGS.has(w.toLowerCase()) && !/^\p{Lu}+$/u.test(w);
};
const hasStreetNumber = (before: string) => [...before.matchAll(STREET_NUMBER)].some((m) => !MONTHS.has(m[1].toLowerCase()) && !NUMBERED_THINGS.has(m[1].toLowerCase()) && !/^\p{Lu}+$/u.test(m[1]));
// The street words and address labels of the forty languages.
// A word's edge only where words have one: Thai and Chinese write the street
// word onto its name ("ถนนพระราม", "松仁路").
const ADDRESS_NEAR = new RegExp(String.raw`(?:(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}])(?:adresse?|adresas|adresa|adrese|aadress|adres|адрес\p{L}*|adreça|address[ \t]*:|osoite|lakc[íi]m|c[íi]m|morada|endere[çc]o|indirizzo|direcci[óo]n|domicilio|bytem|zam\.|trval[ýy][ \t]+pobyt|wohnhaft|plz|c\.?p\.?|cap|c[óo]d\.?[ \t]+postal|posta[ \t]+kodu|postnr|kode[ \t]+pos|alamat|jalan|jl\.|lorong|taman|brgy\.?|purok|rt[ \t]?\d|ul\.|ulica|str\.|strada|calle|carrer|rua|av\.|avenida|via|rue|gata|gade|gate|vej|vägen|katu|tie|utca|út|tér|cad\.|sok\.|mah\.|no:|nagar|road|rd\.|street|st\.?|colony|lane|sector|д\.|кв\.|ул\.|бул\.|вул\.|улица|пр\.|רח[׳']|רחוב|מיקוד|דירה|ঠিকানা|রোড|বাসা|पता|गली|मकान|முகவரி|தெரு|చిరునామా|నం\.|ถนน|ซอย|แขวง|เขต|ต\.|อ\.|หมู่|شارع|حي|مبنى|گلی|نمبر|سیکٹر|διεύθυνση|κάτοικος|οδός|주소|번길|로[ \t]?\d|길[ \t]?\d|地址|住所|路|街|號|号|丁目|番地)(?![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}]))`, "iu");
const NOT_A_TOWN = /^(?:euro|eur|usd|dollars?|franken|francs?|franchi|kilomet(?:er|re)s?|kilom[èe]tres?|met(?:er|re)s?|miles?|meilen|tonnen|tons?|liter|litres?|einwohner|habitants|abitanti|inhabitants|kč|kc|ft|forint|lei|ron|zł|zl|rp|rs|rupees?|ringgit|rm|tl|lira|kr|kroner|kronor|dkk|nok|sek|chf|gbp|km|m2|m²|kg|ml|mg|mhz|ghz|mb|gb|tb|rpm|hz|mah|dpi|fps|pcs|stk|units?|words?|people|users?|members?|pages?|votes?|views?|items?|copies|tickets|ad|bc|ce|bce|руб|грн|тыс|млн|원|円|元|ريال|روپے|টাকা|रुपये)$/iu;

export function findPostcodesBesideTowns(text: string): Array<{ start: number; end: number }> {
  if (!/\d{3}/.test(text)) return [];
  const out: Array<{ start: number; end: number }> = [];
  const take = (start: number, value: string, town: string) => {
    const word = town.replace(/[.,'’-]+$/u, "");
    if (NOT_A_TOWN.test(word) || /^\p{Lu}\p{Ll}+$/u.test(word) && COMMON_TOWNLESS.has(word)) return;
    // Four digits are a year or a model as often as a postcode ("in 1881",
    // "Intel 8088"), so they need the address close: a label within sixty
    // characters or a street and its number within forty. Never a year.
    if (/^\d{4}$/.test(value)) {
      // Unless a street and its number come right before it: Vienna, Brussels
      // and Sofia are 1000 to 1999 ("Margaretenstraße 114/7, 1050 Wien",
      // "ул. „Граф Игнатиев“ 21, 1000 София").
      if (/^(?:1[0-9]|20)\d\d$/.test(value) && !streetRightBefore(text.slice(Math.max(0, start - 60), start))) return;
      if (!ADDRESS_NEAR.test(text.slice(Math.max(0, start - 60), start)) && !hasStreetNumber(text.slice(Math.max(0, start - 40), start))) return;
    } else {
      const before = text.slice(Math.max(0, start - 100), start);
      if (!ADDRESS_NEAR.test(before) && !hasStreetNumber(before)) return;
    }
    out.push({ start, end: start + value.length });
  };
  for (const m of text.matchAll(POSTCODE_THEN_TOWN)) take(m.index ?? 0, m[1], m[2]);
  for (const m of text.matchAll(TOWN_THEN_POSTCODE)) {
    const start = m.index ?? 0;
    const town = text.slice(Math.max(0, start - 30), start).match(/([\p{L}\p{M}.'’-]+)[ \t]*(?:[,–-][ \t]*)?$/u)?.[1] ?? "";
    if (out.some((o) => o.start === start)) continue;
    // Before the number, a town: not a label ("No", "nr", "Tel"), a unit or a
    // currency ("Rp 4.000.000").
    if (/^(?:no|nr|n[º°o]|tel|telp|tlf|puh|mob|hp|cel|fax|room|apt|unit|kamar|bl|ap|sc|et|d|kv|корп|стр|дом|блок|tel\.|ext|x|id|ref|rp|rs|rm|ft|kč|tl|kr|ron|lei|usd|eur|php|idr|inr|pkr|bdt|thb|myr|vnd|price|total|sum|amount|op|art|page|p|vol|chapter|section|§)\.?$/iu.test(town)) continue;
    // A word then a number is how code, logs and prose count things ("wire
    // 527143,", "MariaDB 100108", "TIMEOUT_CYCLE 999999"). A town is a name,
    // the last part of an address after its comma ("Сычуань, Китай 611743"),
    // and its postcode is not the start of a phone ("Outfitters 0412 345").
    // A Brazilian state's two letters before a CEP: "São Paulo - SP, 01414-001".
    const state = /^\d{5}-\d{3}$/.test(m[1]) && /^\p{Lu}{2}$/u.test(town);
    if (!state && (!/^(?:\p{Lu}\p{Ll}[\p{L}\p{M}'’.-]*|\p{Lu}{3,}\.?|\p{Lo}[\p{L}\p{M}]*)$/u.test(town) || /\p{Ll}\p{Lu}/u.test(town))) continue;
    const townAt = start - (text.slice(0, start).length - text.slice(0, start).trimEnd().replace(/[,–-]$/u, "").trimEnd().length) - town.length;
    if (!/[,،、，]/u.test(text.slice(Math.max(0, townAt - 40), townAt))) continue;
    if (/^[ \t]?\d/.test(text.slice(start + m[1].length, start + m[1].length + 2))) continue;
    take(start, m[1], town);
  }
  return out;
}
/**
 * The street and house number of the same addresses (realistic5, where 99
 * went out): the one just before a postcode findPostcodesBesideTowns took,
 * "Skovbrynet 12, 4700 Næstved", "Str. Florilor nr. 3, 300011 Timișoara";
 * and the one after the word for an address or for living somewhere,
 * "Adresa: Vukovarska 58", "bytem Palackého 27", "κάτοικος Κολοκοτρώνη 27",
 * "adresse Elgeseter gate 40". Up to four words of name, then the number.
 */
const STREET_NAME = String.raw`(?:(?:\p{Lu}[\p{L}\p{M}'’-]*\.?|de|del|dei|della|da|das|dos|do|di|du|la|le|cel|gate|vej|gade|cesta|ulica|utca|tér|út|str\.|bd\.|nr\.|calea|via|rua|av\.|carrer|c\/)[ \t]+){0,4}`;
const HOUSE_NUMBER = String.raw`(?:nr\.?[ \t]*|no\.?[ \t]*|nº[ \t]*|n\.º[ \t]*)?\d{1,4}\p{L}?(?:[/-]\d{1,4}\p{L}?)?\.?`;
// The street word after the name, as Lithuanian, Latvian and Estonian write
// it ("Gedimino pr. 9-12", "Brīvības iela 72-5", "Narva mnt 7-15"), and a name
// in quotation marks ("ул. „Граф Игнатиев“ 21"). Address practice set,
// 2026-10-26.
const STREET_SUFFIX = String.raw`(?:[“”"»]?(?:[ \t]+(?:pr\.|prospektas|g\.|gatv[ėe]|al\.|al[ėe]ja|iela|gatve|bulv[āa]ris|mnt\.?|maantee|tn\.?|t[äa]nav|pst\.?|puiestee))?)`;
const STREET_BEFORE_POSTCODE = new RegExp(String.raw`(?<![\p{L}\p{N}])(${STREET_NAME}[„“"«]?\p{Lu}[\p{L}\p{M}'’-]{2,}\.?${STREET_SUFFIX}[ \t]+${HOUSE_NUMBER})(?:,[ \t]*[^,\n]{1,20})?,[ \t]*$`, "u");
const LIVES_AT = String.raw`(?:[Aa]dres[as]?|ADRES[AS]?|[Aa]dresas|[Aa]drese|[Aa]adress|[Hh]eimilisfang(?:i[ðd])?|[Аа]дрес\p{L}*(?:[ \t]+ми[ \t]+е)?|[Aa]dresse|ADRESSE|[Aa]dress|[Aa]dreça|ADREÇA|[Oo]soite|[Ll]akc[íi]m|[Bb]ytem|[Bb]or[ \t]+p[åa]|[Ww]ohnhaft[ \t]+in|[Ww]onende(?:[ \t]+aan)?|κ[άα]τοικος|[Δδ]ιε[ύυ]θυνση|[Tt]rval[ýy][ \t]+pobyt|[Dd]omiciliu|[Dd]omiciliat[ \t]+[îi]n|[Dd]omicilio|[Mm]orada|[Ee]ndere[çc]o|END\.|[Ii]ndirizzo|[Ee]jendom|[Pp]rebivali[šs]tem[ \t]+u|[Ss]tan[ \t]+u|[Bb]yt[ \t]+na)`;
// The verb may come between: "heimilisfangið er Laugavegur 52".
const STREET_AFTER_CUE = new RegExp(String.raw`(?<![\p{L}])${LIVES_AT}(?:[ \t]+(?:er|is|es|est|ist|är|on|je|e|é))?[ \t]*[:：]?[ \t]*(${STREET_NAME}[„“"«]?\p{Lu}[\p{L}\p{M}'’-]{2,}\.?${STREET_SUFFIX}[ \t]+${HOUSE_NUMBER})(?![\p{N}])`, "gu");

export function findStreetsBesidePostcodes(text: string, postcodes: Array<{ start: number; end: number }>): Array<{ start: number; end: number }> {
  const out: Array<{ start: number; end: number }> = [];
  const add = (start: number, value: string) => {
    // A street opens with its capital: "la Str. Florilor" is "to Str. Florilor".
    const lead = value.match(/^(?:\p{Ll}[\p{L}'’]*[ \t]+)+/u)?.[0] ?? "";
    start += lead.length;
    const v = value.slice(lead.length).replace(/[ \t.]+$/u, "");
    const first = v.split(/[ \t]+/)[0].replace(/\.$/, "").toLowerCase();
    if (MONTHS.has(first) || NUMBERED_THINGS.has(first)) return;
    if (!out.some((o) => o.start < start + v.length && start < o.end)) out.push({ start, end: start + v.length });
  };
  for (const p of postcodes) {
    const from = Math.max(0, p.start - 80);
    const m = text.slice(from, p.start).match(STREET_BEFORE_POSTCODE);
    if (m) add(from + (m.index ?? 0) + m[0].indexOf(m[1]), m[1]);
  }
  for (const m of text.matchAll(STREET_AFTER_CUE)) add((m.index ?? 0) + m[0].indexOf(m[1]), m[1]);
  return out;
}

// Capitalised words that open a sentence or name a thing, never a town, after
// a number: "1200 Words", "2500 Users".
const COMMON_TOWNLESS = new Set(["The", "And", "For", "With", "From", "This", "That", "Total", "Price", "Amount", "Euro", "Euros", "Dollar", "Dollars", "Mbps", "Kbps", "Series", "Model", "Pro", "Max", "Plus", "Ultra", "Edition", "Version", "Points", "Miles", "Hours", "Minutes", "Seconds", "Days", "Years", "Calories", "Steps"]);
