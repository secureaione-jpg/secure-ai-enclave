import { addFoundRedactions } from "./redactionStructured.js";
import { isAllowed, isSubstitutable, MAX_REDACTION_ENTRIES, pickFake } from "./redactionMap.js";
import type { AllowList, RedactionMap } from "./redactionMap.js";
import { COMMON_CAPITALISED, isCommonLowercaseWord } from "./redactionNameWords.js";
import { IP_NOT_A_PERSON, IPV6_PATTERN } from "./redactionPatterns.js";
// A cycle with redactionNames (which reads placesFrom here): both sides use
// the other only inside functions, never while the module loads.
import { addNameRedactions } from "./redactionNames.js";
import { findRecordFields } from "./redactionRecords.js";

/**
 * Medical mode: what US health law asks to be removed before a record leaves
 * the building, beyond what every request already hides.
 *
 * HIPAA's Safe Harbor method (45 CFR 164.514(b)(2)) lists eighteen kinds of
 * identifier. Names, phone and fax numbers, e-mail, SSNs, record, account,
 * plan, licence, vehicle and device numbers are hidden on every request
 * already. What a chat leaves visible on purpose, and a hospital may not, is:
 *
 *   every date tied to a person but its year: admission, discharge, visit,
 *   test, death ("03/14/2024", "June 18", "11/03");
 *   an age over 89, and a birth year that gives one away;
 *   a place smaller than a state: a town, a county, a street, a ZIP code;
 *   every web address and every IP address, not only the labelled ones.
 *
 * Diagnoses, medicines, doses, results and times stay. The point of sending
 * a record to a model is to ask about them, and none of them is on the list.
 * A care facility's name goes, because it narrows a town to one building.
 *
 * Off unless the caller asks (`medical: true` on /v1/redact). In a chat
 * "my appointment is on June 18" is the question; in a record it is an
 * identifier.
 *
 * ── Dates are moved, not scrambled ──
 *
 * Every date in a request moves by the same number of weeks, picked at
 * random per conversation and between one and twenty-six, so the stay from
 * 03/14 to 03/21 is still seven days, a Tuesday is still a Tuesday, and the
 * year never changes. A date that would cross into another year moves the
 * other way. Seeing a stand-in tells a reader the year, which Safe Harbor
 * allows, and not the day.
 *
 * ── Stand-ins here are drawn at random ──
 *
 * The other stand-ins are derived from a hash of the value, which is fine
 * for a space as large as everybody's names. An age over 89 is one of
 * thirty values and a date one of 366: hashed, a table of all of them would
 * turn a stand-in straight back into the real one. So these use a random
 * draw, and the map carries the answer forward for the rest of the
 * conversation.
 */

export type MedicalKind = "date" | "age" | "year90" | "place" | "facility" | "url" | "host" | "id" | "name" | "address" | "phone" | "email" | "ssn";
export type MedicalFinding = { kind: MedicalKind; value: string };

const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
const MONTH_RE = String.raw`(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?`;
const ORD = String.raw`(?:st|nd|rd|th)?`;

/** Month names in the other languages of a European record. A moved date is
 *  written back in its own: "14. März" becomes "28. März", not "28 March". */
const INTL_MONTHS: string[][] = [
  ["januar", "februar", "märz", "april", "mai", "juni", "juli", "august", "september", "oktober", "november", "dezember"],
  ["jänner", "feber", "märz", "april", "mai", "juni", "juli", "august", "september", "oktober", "november", "dezember"],
  ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"],
  ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"],
  ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"],
  ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"],
  ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"],
];
const INTL_MONTH_RE = `(?:${[...new Set(INTL_MONTHS.flat())].sort((a, b) => b.length - a.length).join("|")})`;
/** The small words of each list's language, in INTL_MONTHS order: "marzo"
 *  is Spanish and Italian, and a date moved out of March must land in the
 *  record's own April ("abril" or "aprile"). */
const INTL_SMALL_WORDS = [
  /(?<!\p{L})(?:der|die|das|und|ist|mit|von|für|nicht|den|dem)(?!\p{L})/giu,
  /(?<!\p{L})(?:der|die|das|und|ist|mit|von|für|nicht|den|dem)(?!\p{L})/giu,
  /(?<!\p{L})(?:le|les|des|du|et|est|pour|avec|dans|une|au)(?!\p{L})/giu,
  /(?<!\p{L})(?:el|los|las|del|y|con|por|para|una|que)(?!\p{L})/giu,
  /(?<!\p{L})(?:il|gli|della|del|di|che|e|per|con|nel|una)(?!\p{L})/giu,
  /(?<!\p{L})(?:het|een|en|van|op|met|voor|niet|zijn)(?!\p{L})/giu,
  /(?<!\p{L})(?:do|da|os|as|em|com|não|uma|pelo|para)(?!\p{L})/giu,
];
/** The month lists in the order the text's own language suggests. */
export function monthListsFor(text: string): string[][] {
  const scores = INTL_SMALL_WORDS.map((re) => text.match(re)?.length ?? 0);
  return INTL_MONTHS.map((list, i) => ({ list, score: scores[i], i })).sort((a, b) => b.score - a.score || a.i - b.i).map((x) => x.list);
}
/** Which list a month name is in, and where: the first list that has it,
 *  in the order of the text being redacted. */
function intlMonth(name: string, lists: string[][] = INTL_MONTHS): { list: string[]; index: number } | null {
  const lower = name.toLowerCase();
  for (const list of lists) {
    const index = list.indexOf(lower);
    if (index !== -1) return { list, index };
  }
  return null;
}
/** "14. März 2024", "12 de enero de 2025", "5 avril", "1er mai", "2. Oktober". */
const DATE_DAY_FIRST_INTL = new RegExp(String.raw`(?<![\p{L}\d.])(\d{1,2})(\.|er|º|°)?([ \t]+(?:de[ \t]+)?)(${INTL_MONTH_RE})(?:((?:,|[ \t]+de)?[ \t]+)(\d{4}))?(?![\p{L}\d])`, "giu");
/** "März 2024", "marzo de 2025". */
const DATE_MONTH_YEAR_INTL = new RegExp(String.raw`(?<![\p{L}\d])(${INTL_MONTH_RE})([ \t]+(?:de[ \t]+)?)(\d{4})(?![\p{L}\d])`, "giu");

/** "June 18, 2024", "Oct 3, 2024", "March 3rd", "April 12". */
const DATE_MONTH_FIRST = new RegExp(String.raw`(?<![\p{L}\d])(${MONTH_RE})[ \t]+(\d{1,2})(${ORD})(?:(,?[ \t]+)(\d{4}))?(?![\p{L}\d])`, "giu");
/** "14 February 2025", "12 Jan 2025", "the 5th of May". */
const DATE_DAY_FIRST = new RegExp(String.raw`(?<![\p{L}\d])(\d{1,2})(${ORD})([ \t]+(?:of[ \t]+)?)(${MONTH_RE})(?:(,?[ \t]+)(\d{4}))?(?![\p{L}\d])`, "giu");
/** "March 2024": a month and a year. */
const DATE_MONTH_YEAR = new RegExp(String.raw`(?<![\p{L}\d])(${MONTH_RE})(,?[ \t]+)(\d{4})(?![\p{L}\d])`, "giu");
/** "03/14/2024", "13.11.2024", "07-22-1975", "1/9/25". */
const DATE_NUMERIC = /(?<![\d./-])(\d{1,2})([/.-])(\d{1,2})\2(\d{4}|\d{2})(?![\d/-]|\.\d)/g;
/** "2024-11-02", "2024/11/02". */
const DATE_ISO = /(?<![\d./-])((?:19|20)\d\d)([/.-])(\d{1,2})\2(\d{1,2})(?![\d/-]|\.\d)/g;
/** "20300615": a year, a month and a day run together. */
const DATE_COMPACT = /(?<![\w.\/-])((?:19|20)\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?![\w.\/-]|\.\w)/g;
/** "11/03", "2/28", only after a word that makes it a day: "on 11/03",
 *  "until 2/28", "Friday 11/15". Without one, "3/10" is a pain score and
 *  "20/40" is eyesight. */
const DATE_SHORT = /(?<=(?:\b(?:on|since|from|until|till|to|by|before|after|dated?|due|next|seen|visit(?:ed)?|admitted|discharged|drawn|scheduled|appointment|follow[ -]?up|called|returns?|(?:appt|appointment|visit|review|surgery|operation|op|scan|clinic|test|follow[ -]?up)[ \t]+(?:is|was|on))|(?:mon|tues|wednes|thurs|fri|satur|sun)day)[ \t]+)(\d{1,2})\/(\d{1,2})(?![\d/]|\.\d|[ \t]*(?:mg|mcg|ml|mL|units?|tabs?|caps?|OD|OS|OU|mmHg)\b)/gi;

const NOT_A_DATE_BEFORE = /(?:\bv(?:er(?:sion)?)?\.?|\bversion|\brelease|\bbuild|\bfirmware|\bsdk|\b(?:ICD|CPT|NDC)[\s-]*(?:10|9)?[\s:]*)\s*$/i;

/** An age over 89. Ninety and older may stay as "90 or older"; the number
 *  itself may not. */
const AGE_NUMBER = String.raw`(9\d|1[01]\d)`;
const AGE_PATTERNS = [
  new RegExp(String.raw`(?<![\d.])${AGE_NUMBER}[- ](?:years?|yrs?)[- ](?:old|of[ \t]+age)\b`, "gi"),
  new RegExp(String.raw`(?<![\d.])${AGE_NUMBER}[ \t]*(?:y\/o|yo|y\.o\.)(?![\p{L}])`, "giu"),
  new RegExp(String.raw`\b(?:aged?|age:)[ \t]*:?[ \t]*${AGE_NUMBER}\b(?![ \t]*(?:\+|and[ \t]+(?:older|over|above)|or[ \t]+(?:older|over|above)|%|-))`, "gi"),
  new RegExp(String.raw`\b(?:he|she|i|they|patient|pt|(?:my[ \t]+)?(?:mom|mum|mother|dad|father|grandmother|grandma|granny|grandfather|grandpa|husband|wife|aunt|uncle|nan|nana))(?:'s|’s|'m|’m|[ \t]+is|[ \t]+am|[ \t]+was|[ \t]+turned|[ \t]+turns)[ \t]+(?:now[ \t]+|just[ \t]+)?${AGE_NUMBER}\b(?![.,]?\d|[ \t]*(?:%|mg|mcg|kg|kgs|lbs?|pounds?|bpm|mmhg|percent|°|degrees?|beats|cm|mm|ml|units?|points?|minutes?|mins?|hours?|hrs?|days?|times|over|\/))`, "gi"),
  // The same in the other languages of a European record: "93-jährige",
  // "92 Jahre alt", "âgé de 91 ans", "94 años", "95 jaar", "96 anos",
  // "di anni 92", "sie ist 97".
  new RegExp(String.raw`(?<![\d.])${AGE_NUMBER}[ \t-]*(?:Jahre?n?|jährige[rnms]?|ans|años|anni|anos|jaar)(?![\p{L}])`, "giu"),
  new RegExp(String.raw`\b(?:di[ \t]+)?anni[ \t]+${AGE_NUMBER}\b`, "gi"),
  new RegExp(String.raw`(?<![\p{L}])(?:sie|er|ich|elle|il|ella|él|lei|lui|zij|hij|ela|ele)[ \t]+(?:ist|bin|wird|wurde|est|a|tiene|ha|is|wordt|tem)[ \t]+(?:jetzt[ \t]+|maintenant[ \t]+|ya[ \t]+|ora[ \t]+|nu[ \t]+|já[ \t]+)?${AGE_NUMBER}(?![.,]?\d|[ \t]*(?:%|kg|mg|mmHg|bpm|°|cm|ml|Punkte|points|puntos|punti))(?![\p{L}\d])`, "giu"),
  // "Mrs. Dorothy Hale, 93, is recovering": a name, then the age between commas.
  // "Mrs Joan Pritchard (NHS No …), 93, of 14 Mill Lane": a bracket before it, "of" after.
  new RegExp(String.raw`(?<=(?:\b[A-Z][a-z'’-]+|\)),[ \t])${AGE_NUMBER}(?=,[ \t]+(?:is|was|has|had|who|lives|presents|reports|with|and|of|from)\b)`, "g"),
];

/** A birth year that says the person is over 89: "year of birth 1931". */
const BIRTH_YEAR = /\b(?:year[ \t]+of[ \t]+birth|birth[ \t]*year|born(?:[ \t]+in)?|b\.)[ \t]*:?[ \t]*(?:is[ \t]+)?((?:18|19|20)\d\d)\b/gi;

const URL_PATTERN = /\b(?:(?:https?|ftp):\/\/|www\.)[^\s<>"'`]+/gi;
const IPV4_ANY = /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.]*\d)/g;

/** A county or parish: "Cumberland County", "Robeson County". */
const COUNTY_PATTERN = /\b((?:St\.?[ \t]+)?[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,2})[ \t]+(County|Parish|Borough)\b/g;

/** A town before a state's two letters: "Hope Mills, NC 28348", "Fall River, MA". */
const STATE_CODES = "AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY";
const TOWN_BEFORE_STATE = new RegExp(String.raw`\b([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,2}),[ \t]+(?:${STATE_CODES})\b(?:[ \t]+(\d{5}(?:-\d{4})?))?`, "g");
/** A ZIP code after a state's two letters, with a town before them: "product
 *  ID 12345" is Idaho only to a pattern. */
const ZIP_AFTER_STATE = new RegExp(String.raw`(?<=\b[A-Z][a-z]+,?[ \t]+)(?:${STATE_CODES})[ \t]+(\d{5}(?:-\d{4})?)\b`, "g");
/** A postcode under its label, in markdown or a table: "**Postcode:**
 *  17271", "| Postcode | 25567 |", "postcodes 83297 and 2633", "postcode
 *  of 60938", "the 2489 postcode area". */
const POSTCODE_LABELLED = /\b(?:post(?:al)?[ \t]*codes?|zip(?:[ \t]*codes?)?|pin[ \t]*code)\b(?:[ \t*|:]|of\b|is\b){0,8}(\d{4,6}(?:-\d{4})?)(?!\d|\.\d)(?:[ \t]+(?:and|or|&)[ \t]+(\d{4,6})(?!\d|\.\d))?|(?<![\d.])(\d{4,6})[ \t]+post(?:al)?[ \t]*code\b/gi;

/** The name in a record's name field: "Name: Gwendolyn Marsh", "Patient:
 *  Harold Becker", "Patientin: Gerda Hoffmann". The name models read
 *  "Gwendolyn Marsh   Hospital No" as a place; the field says it is not. */
const NAME_FIELD = /(?<![\p{L}])(?:(?:Patient|Pt|Resident|Client|Decedent|Subject|Member|Insured)(?:[ \t]+(?:Full[ \t]+)?Name)?|(?:Full[ \t]+)?Name|Patient(?:in)?|Patiente?|Paciente|Paziente|Utente|Patiënt|Nome|Nom|Nombre)[ \t]*:[ \t]*((?:(?:Mr|Mrs|Ms|Miss|Dr|Herr|Frau|M|Mme|Sr|Sra|Sig|Dott)\.?[ \t]+)?[A-ZÀ-Ý][\p{L}'’-]+(?:[ \t]+[A-ZÀ-Ý][\p{L}'’-]+){1,3})(?=[ \t]{2,}|[ \t]*[,;\n(]|$)/gmu;

/** A postcode before its town, as most of Europe writes an address: "50667
 *  Köln", "Calle Mayor 23, 28013 Madrid", "wohnhaft in 80331 München",
 *  "1100-053 Lisboa". Only after a comma, a colon, a line start or a word
 *  that says where: "1000 Patienten" in German is a count. */
const EU_POSTCODE_TOWN = /(?<=(?:^|[,:;(]|\b(?:in|à|en|te|em|im|bei|a|wohnhaft[ \t]+in|domicilié[e]?[ \t]+(?:à|au)|residente[ \t]+(?:a|em|en|in)))[ \t]*)(?:[A-Z]{1,2}-)?(\d{4,5}(?:-\d{3})?)[ \t]+([A-ZÀ-Ý][\p{L}'’-]+(?:[ \t-][A-ZÀ-Ý][\p{L}'’-]+)?)(?=[\s,.;)]|$)/gmu;
/** A UK postcode, and the town just before it: "Harrogate HG1 2AB",
 *  "Otley, LS21 3HX", "Cardiff CF10 3AT". */
const UK_POSTCODE = /(?:\b([A-Z][a-z]+(?:[ \t][A-Z][a-z]+)?),?[ \t]+)?\b((?:[A-Z]{1,2}\d[A-Z\d]?|GIR)[ \t]?\d[A-Z]{2})\b/g;

/** State codes that are also a title, a rank or a word in capitals: "Jane
 *  Ross, PA", "However, DC Harrison", "relapsing MS". A town before one of
 *  these needs a ZIP after it as well. */
const AMBIGUOUS_STATE = /^(?:MD|PA|ME|DO|IN|OR|OK|DE|CO|LA|MA|DC|ID|MS|HI|AL|OH|NP|RN)$/;

/**
 * A place of care by its name: "Mercy General Hospital", "St. Luke's Medical
 * Center", "Endoscopy Center of Wilmington", "Greensboro Orthopedics". One
 * capitalised word at least before the kind of place, or a place after it.
 */
const FACILITY_KIND = String.raw`(?:General[ \t]+)?(?:Hospital|Medical[ \t]+Cent(?:er|re)|Health[ \t]+(?:Cent(?:er|re)|System|Department)|Clinic|Infirmary|Hospice|Family[ \t]+(?:Practice|Medicine)|Orthop(?:a)?edics|Pediatrics|Paediatrics|Cardiology|Surgery[ \t]+Cent(?:er|re)|Surgical[ \t]+Cent(?:er|re)|Urgent[ \t]+Care|Endoscopy[ \t]+Cent(?:er|re)|Dialysis[ \t]+(?:Cent(?:er|re)|Unit)|Rehabilitation[ \t]+Cent(?:er|re)|Nursing[ \t]+(?:Home|Facility)|Care[ \t]+Home|Medical[ \t]+Group|Surgery(?![ \t]+Cent)|U?MC|NHS[ \t]+(?:Foundation[ \t]+)?Trust)`;
/** Specialties, not places: "General Surgery", "Cardiac Surgery". */
const SPECIALTY_BEFORE = /^(?:General|Cardiac|Cardiothoracic|Plastic|Oral|Vascular|Thoracic|Orthop(?:a)?edic|Paediatric|Pediatric|Neuro|Day|Minor|Bariatric|Colorectal|Breast|Eye|Hand|Spinal|Robotic|Cosmetic|Dental|Keyhole|Emergency|Elective|Ambulatory|Upper[ \t]+GI|Hepatobiliary|Transplant|Trauma)[ \t]+Surgery$/;
const FACILITY_PATTERN = new RegExp(
  String.raw`(?<![\p{L}])((?:(?:St\.?|Saint)[ \t]+)?(?!(?:The|A|An|Our|Your|His|Her|Their|This|That|At|In|To|From|Of|And)[ \t])[A-Z][\p{L}'’.-]*(?:[ \t]+(?:(?:and|&)[ \t]+)?(?!${FACILITY_KIND}(?![\p{L}]))[A-Z][\p{L}'’.-]*){0,4}[ \t]+${FACILITY_KIND}(?:[ \t]+of[ \t]+[A-Z][\p{L}'’-]+(?:[ \t]+[A-Z][\p{L}'’-]+)?)?|${FACILITY_KIND}[ \t]+of[ \t]+[A-Z][\p{L}'’-]+(?:[ \t]+[A-Z][\p{L}'’-]+)?)(?![\p{L}])`,
  "gu",
);

/**
 * The kind of place first, then its name, as most of Europe writes it:
 * "Klinikum Schwabing", "Universitätsklinikum Heidelberg", "CHU de Rennes",
 * "Centre Hospitalier de Villefranche", "Hospital Universitario La Paz",
 * "Ospedale San Raffaele", "Ziekenhuis Gelderse Vallei", "Centro de Salud de
 * Alcalá". A capitalised name after it, always.
 */
const KIND_FIRST_HEAD = String.raw`(?:Universitätsklinikum|Kreiskrankenhaus|Krankenhaus|Klinikum|Klinik|Hôpital|Clinique|Centre[ \t]+Hospitalier(?:[ \t]+Universitaire)?|CHU|CHR|EHPAD|Hospital(?:[ \t]+(?:Universitario|General|Clínico|Universitário))?|Clínica|Clinica|Centro[ \t]+de[ \t]+(?:Salud|Saúde)|Centro[ \t]+Hospitalar|Ospedale|Policlinico|Casa[ \t]+di[ \t]+[Cc]ura|Ziekenhuis|Kliniek|Ambulatorio)(?:[ \t]+(?:de|di|du|des|del|da|do|dos|van|te|der|am|an|la|le))?`;
const FACILITY_KIND_FIRST = new RegExp(String.raw`(?<![\p{L}])(${KIND_FIRST_HEAD}(?:[ \t]+[A-ZÀ-Ý][\p{L}'’-]+){1,4})`, "gu");

/** A town before a kind of place written small: "the Pembroke dialysis unit",
 *  "the Clinton walk-in clinic". */
const TOWN_BEFORE_UNIT = /\b(?:the|at|in)[ \t]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)?)[ \t]+(?:(?:dialysis|cancer|eye|heart|kidney|renal|walk-in|outpatient|community|county|district|regional|memorial|general|children's|women's|mental[ \t]+health|urgent[ \t]+care|maternity|fertility|sleep|wound|pain)[ \t]+)?(?:unit|clinic|hospital|centre|center|practice|surgery|ward|infirmary|hospice|pharmacy)\b/g;

/**
 * Any other number that names a patient's record, under a clinical label:
 * "Accession #RAD-77812034", "specimen S24-11873", "pacemaker serial
 * PJK829104L", "subject 014-0237", "Prescription #RX4482019", "patient
 * 7731-0042". Safe Harbor's last item. A digit in it, and five characters.
 */
const CLINICAL_ID = /\b(?:accession|specimen|sample|subject|serial|prescription|rx|patient|case|encounter|requisition|study|enrol(?:l)?ment|screening|participant|device|implant|kit)(?:[ \t]+(?:no\.?|number|id|#))?[ \t]*(?:[:#][ \t]*)?#?((?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{3,24}[A-Z0-9])(?![\w-])/gi;

/**
 * Numbers that are identifiers by their shape alone, which Safe Harbor's
 * last item covers in a record and a chat may need to keep: a UUID, a long
 * hex or base-32 string, a device's 12-to-20-digit number, a VIN, a code
 * of a few letters and eight digits or more ("BIO-7459312689").
 */
const ID_SHAPES = [
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
  /(?<![\w-])(?=[0-9a-f]{0,63}\d)(?=[0-9a-f]{0,63}[a-f])[0-9a-f]{16,64}(?![\w-])/gi,
  /(?<![\w-])(?=[0-9A-Z]{0,25}\d)(?=[0-9A-Z]{0,25}[A-Z])[0-9A-HJKMNP-TV-Z]{26}(?![\w-])/g,
  /(?<![\d.,\/:-])\d{12,20}(?![\d,\/:-]|\.\d)/g,
  /(?<![\w-])(?=(?:[0-9]{0,16}[A-HJ-NPR-Z]){3})(?=(?:[A-HJ-NPR-Z]{0,16}[0-9]){3})[A-HJ-NPR-Z0-9]{17}(?![\w-])/g,
  /(?<![\w-])[A-Z]{1,4}-?\d{8,14}(?![\w-])/g,
];

/** An identifier a few words after its label: "the health plan beneficiary
 *  number for the applicant is AET-2345-6789-12", "biometric identifier
 *  BIO-7459312689", "the vehicle identified by 3VW9JT7G5A948256". */
const ID_AFTER_LABEL = /\b(?:health[ \t]+plan[ \t]+beneficiary[ \t]+number|beneficiary[ \t]+(?:number|id)|hpbn|member[ \t]+id|biometric[ \t]+identifiers?|device[ \t]+(?:identifiers?|ids?)|unique[ \t]+(?:ids?|identifiers?)|vehicle[ \t]+(?:identifier|identified[ \t]+by)|individual[ \t]+id|record[ \t]+id|report[ \t]+id)\b(?:[ \t]+(?!(?:is|was|like|of|by)\b)[a-z']{1,15}){0,6}?(?:[ \t]*[:=]|[ \t]*,|[ \t]+(?:is|was|like|of|by|such[ \t]+as))?[ \t]*[*'"`]{0,2}((?=[\w-]{0,63}\d)[A-Za-z0-9][\w-]{3,62}[A-Za-z0-9])(?![\w-])/gi;

/** Diseases and vaccines named after a place: "COVID-19", "Lyme disease",
 *  "West Nile virus". A tagger reads the place; the record means the illness. */
const PLACE_IS_ILLNESS = /^(?:covid|sars|mers|lyme|zika|ebola|marburg|lassa|norwalk|coxsackie|hendra|nipah|west nile|rocky mountain|rift valley|cancer|tropic of cancer)$/i;
const ILLNESS_AFTER = /^(?:['’]s)?[ \t-]*(?:\d|virus|disease|fever|syndrome|vaccine|booster|infection|encephalitis|flu|strain|variant|cancer|tumou?r|carcinoma|lymphoma|sarcoma|palsy|an(?:a)?emia|ulcer|sclerosis|dystrophy|unspecified|acute|chronic)/i;

/** Words a record uses for what is wrong with someone, which a tagger can
 *  read as a place when one starts a cell or a line: "Pneumonia
 *  unspecified" in a diagnosis column (2026-10-08). A diagnosis is what the
 *  record is about and is never hidden. None of 5,807 labelled places has
 *  one of these words in it. */
const CLINICAL_WORDS = new Set(("pneumonia sepsis septicaemia septicemia diabetes asthma hypertension hypotension fracture stroke " +
  "cancer carcinoma lymphoma leukaemia leukemia melanoma dementia delirium depression anxiety schizophrenia epilepsy migraine " +
  "arthritis osteoporosis osteoarthritis gout cirrhosis hepatitis pancreatitis appendicitis cholecystitis colitis gastritis " +
  "bronchitis bronchiolitis pharyngitis tonsillitis sinusitis otitis conjunctivitis cellulitis dermatitis eczema psoriasis " +
  "obesity anaemia anemia angina infarction arrhythmia fibrillation tachycardia bradycardia embolism thrombosis aneurysm " +
  "influenza tuberculosis malaria measles mumps rubella pertussis tetanus diphtheria polio shingles herpes hiv aids " +
  "covid copd ckd uti dvt chf gerd ibs ibd adhd autism parkinsonism alzheimer glaucoma cataract hernia " +
  "concussion laceration contusion sprain dislocation pregnancy preeclampsia eclampsia miscarriage infertility " +
  "hypothyroidism hyperthyroidism hyperlipidaemia hyperlipidemia hyperglycaemia hyperglycemia hypoglycaemia hypoglycemia " +
  "nephritis pyelonephritis cystitis prostatitis endometriosis menopause osteomyelitis meningitis encephalopathy neuropathy " +
  "pneumothorax effusion oedema edema ascites jaundice syncope vertigo seizure dyspnoea dyspnea " +
  "nausea vomiting diarrhoea diarrhea constipation headache rash abscess biopsy chemotherapy radiotherapy dialysis").split(" "));

/** References anybody may cite, which say nothing about the patient. */
const REFERENCE_URL = /^(?:https?:\/\/|www\.)(?:[\w-]+\.)*(?:wikipedia\.org|wikimedia\.org|doi\.org|ncbi\.nlm\.nih\.gov|pubmed\.gov|nih\.gov|cdc\.gov|who\.int|nhs\.uk|medlineplus\.gov|fda\.gov|ema\.europa\.eu|clinicaltrials\.gov|cochranelibrary\.com|loinc\.org|snomed\.info|unitsofmeasure\.org|hl7\.org|fhir\.org|ama-assn\.org)(?:[/?#]|$)/i;

/** Words a form or a table puts where a tagger expects a place: "| Field |
 *  Value |", "Origin:", "SSN:", "Rear Left". Never a town on their own. */
const FORM_WORDS = /^(?:field|value|details?|origin|destination|state|country|county|city|town|region|location|address|area|zone|section|yard|square yard|front|rear|left|right|(?:front|rear)[ \t]+(?:left|right)|ssn|dob|mrn|npi|zip|pin|state of|county of|subdivision|township|district|north|south|east|west)$/i;
/** A legal heading in capitals: "IN WITNESS WHEREOF", "IN THE MATTER BETWEEN". */
const LEGAL_CAPS = /\b(?:WITNESS|WHEREOF|MATTER|BETWEEN|HEREBY|HEREIN|HERETO|AGREEMENT|PETITIONER|RESPONDENT)\b/;

/** States, countries and regions: places a record may name, larger than a state. */
const STATE_NAMES = new Set(("alabama alaska arizona arkansas california colorado connecticut delaware florida georgia hawaii idaho illinois indiana iowa " +
  "kansas kentucky louisiana maine maryland massachusetts michigan minnesota mississippi missouri montana nebraska nevada new_hampshire " +
  "new_jersey new_mexico new_york north_carolina north_dakota ohio oklahoma oregon pennsylvania rhode_island south_carolina south_dakota " +
  "tennessee texas utah vermont virginia washington west_virginia wisconsin wyoming district_of_columbia puerto_rico guam " +
  "ontario quebec british_columbia alberta manitoba saskatchewan nova_scotia england scotland wales northern_ireland bavaria").split(" ").map((s) => s.replace(/_/g, " ")));
const COUNTRY_NAMES = new Set(("afghanistan albania algeria andorra angola argentina armenia australia austria azerbaijan bahamas bahrain bangladesh barbados " +
  "belarus belgium belize benin bhutan bolivia bosnia botswana brazil brunei bulgaria burundi cambodia cameroon canada chad chile china colombia " +
  "congo costa_rica croatia cuba cyprus czechia czech_republic denmark djibouti dominica dominican_republic ecuador egypt el_salvador eritrea estonia " +
  "eswatini ethiopia fiji finland france gabon gambia germany ghana greece grenada guatemala guinea guyana haiti honduras hungary iceland india " +
  "indonesia iran iraq ireland israel italy jamaica japan jordan kazakhstan kenya kiribati korea south_korea north_korea kosovo kuwait kyrgyzstan " +
  "laos latvia lebanon lesotho liberia libya liechtenstein lithuania luxembourg madagascar malawi malaysia maldives mali malta mauritania mauritius " +
  "mexico moldova monaco mongolia montenegro morocco mozambique myanmar namibia nepal netherlands new_zealand nicaragua niger nigeria norway oman " +
  "pakistan palestine panama paraguay peru philippines poland portugal qatar romania russia rwanda samoa saudi_arabia senegal serbia seychelles " +
  "sierra_leone singapore slovakia slovenia somalia south_africa spain sri_lanka sudan suriname sweden switzerland syria taiwan tajikistan tanzania " +
  "thailand togo tonga trinidad tunisia turkey turkmenistan uganda ukraine united_arab_emirates uae united_kingdom uk united_states usa us america " +
  "uruguay uzbekistan vanuatu venezuela vietnam yemen zambia zimbabwe " +
  "africa asia europe antarctica oceania north_america south_america latin_america middle_east midwest new_england the_south the_west " +
  "caribbean scandinavia balkans").split(" ").map((s) => s.replace(/_/g, " ")));

let STATE_ZIP: RegExp | null = null;
/** A state's name, then a ZIP code: built once from STATE_NAMES. */
function stateZip(): RegExp {
  STATE_ZIP ??= new RegExp(String.raw`\b(?:${[...STATE_NAMES].map((s) => s.replace(/ /g, "[ \\t]+")).join("|")}),?[ \t]+(\d{5}(?:-\d{4})?)(?=[ \t]*(?:,|\.(?:\s|$)|$|\r?\n|\)|[ \t]+(?:USA|US|U\.S\.A?\.?|United[ \t]+States)\b))`, "gi");
  return STATE_ZIP;
}

/** A place the name model tagged, held to what a town is: in the text as
 *  written, capitalised, not a state, a country or a region, not an
 *  ordinary word. */
export function placesFrom(raw: unknown, text: string): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const candidate of raw) {
    if (typeof candidate !== "string") continue;
    const place = candidate.trim().replace(/^(?:the|in|at|to|from)\s+/i, "");
    if (place.length < 3 || !text.includes(place) || !/^\p{Lu}/u.test(place)) continue;
    const lower = place.toLowerCase();
    if (STATE_NAMES.has(lower) || COUNTRY_NAMES.has(lower) || new RegExp(`^(?:${STATE_CODES})$`).test(place)) continue;
    if (!/\s/.test(place) && (isCommonLowercaseWord(lower) || COMMON_CAPITALISED.has(place))) continue;
    if (PLACE_IS_ILLNESS.test(place) || FORM_WORDS.test(place) || LEGAL_CAPS.test(place)) continue;
    if (place.toLowerCase().split(/[\s-]+/).some((w) => CLINICAL_WORDS.has(w))) continue;
    // "State of Georgia" is a state, "State of Anystate" a placeholder.
    if (/^State[ \t]+of[ \t]/i.test(place)) continue;
    let illness = false;
    for (let i = text.indexOf(place); i !== -1 && !illness; i = text.indexOf(place, i + 1)) illness = ILLNESS_AFTER.test(text.slice(i + place.length, i + place.length + 16));
    if (illness) continue;
    if (!isSubstitutable(place) || out.includes(place)) continue;
    out.push(place);
  }
  return out;
}

const isMonth = (s: string) => MONTHS.some((m) => m.startsWith(s.toLowerCase().replace(/\.$/, "").slice(0, 3)));
const validDay = (m: number, d: number) => m >= 1 && m <= 12 && d >= 1 && d <= 31;

/** Everything medical mode hides that the ordinary stages leave. */
export function findMedical(text: string, now: Date = new Date()): MedicalFinding[] {
  const found: MedicalFinding[] = [];
  // Which characters are taken, and which values: a mark per character and a
  // set, not a list searched each time. A 3,000-row export finds twelve
  // thousand values, and searching the list for each took fifteen seconds.
  const claimed = new Uint8Array(text.length + 1);
  const seen = new Set<string>();
  const free = (a: number, b: number) => {
    for (let i = a; i < b; i++) if (claimed[i]) return false;
    return true;
  };
  const take = (kind: MedicalKind, value: string, start: number) => {
    const end = start + value.length;
    if (!value.trim() || start < 0 || !free(start, end)) return;
    claimed.fill(1, start, end);
    const key = `${kind}\u0000${value}`;
    if (!seen.has(key)) { seen.add(key); found.push({ kind, value }); }
  };
  const scan = (re: RegExp, kind: MedicalKind, pick: (m: RegExpMatchArray) => { value: string; start: number } | null) => {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const got = pick(m);
      if (got) take(kind, got.value, got.start);
    }
  };
  const whole = (m: RegExpMatchArray) => ({ value: m[0], start: m.index ?? 0 });
  const group = (m: RegExpMatchArray, g: number) => {
    const v = m[g];
    if (!v) return null;
    return { value: v, start: (m.index ?? 0) + m[0].indexOf(v) };
  };

  // A record's own fields first (HL7, FHIR, C-CDA, a spreadsheet): they say
  // what each value is. See redactionRecords.ts.
  for (const f of findRecordFields(text)) take(f.kind, f.value, f.start ?? text.indexOf(f.value));

  // Web and network addresses first: a URL can hold a date ("…/2024-03-14").
  // Not a reference anybody may cite (an encyclopedia, PubMed, a health
  // agency), nor a code namespace (uri="http://java.sun.com/jsp/jstl/core"):
  // neither says anything about the patient (real chats, 2026-10-08).
  scan(URL_PATTERN, "url", (m) => {
    const value = m[0].replace(/[.,;:!?)\]]+$/, "");
    if (REFERENCE_URL.test(value)) return null;
    if (/\b(?:xmlns(?::\w+)?|uri|schemaLocation|namespace)\s*=\s*["']$/i.test(text.slice(Math.max(0, (m.index ?? 0) - 30), m.index))) return null;
    return value.length > 10 ? { value, start: m.index ?? 0 } : null;
  });
  scan(IPV4_ANY, "host", (m) => {
    const before = text.slice(Math.max(0, (m.index ?? 0) - 12), m.index);
    // Loopback, broadcast, the documentation ranges and the public resolvers
    // are nobody's address.
    if (IP_NOT_A_PERSON.test(m[1]) || NOT_A_DATE_BEFORE.test(before)) return null;
    return group(m, 1);
  });

  // Dates: the longest forms first, so "June 18, 2024" is one value.
  // Every IPv6 address: the documentation range too, which the ordinary
  // stages leave as an example.
  scan(IPV6_PATTERN, "host", whole);
  scan(DATE_ISO, "date", (m) => (validDay(Number(m[3]), Number(m[4])) && !NOT_A_DATE_BEFORE.test(text.slice(0, m.index)) ? whole(m) : null));
  scan(DATE_COMPACT, "date", (m) => (NOT_A_DATE_BEFORE.test(text.slice(Math.max(0, (m.index ?? 0) - 20), m.index)) ? null : whole(m)));
  scan(DATE_NUMERIC, "date", (m) => {
    const a = Number(m[1]), b = Number(m[3]);
    if (!(validDay(a, b) || validDay(b, a))) return null;
    if (NOT_A_DATE_BEFORE.test(text.slice(Math.max(0, (m.index ?? 0) - 20), m.index))) return null;
    return whole(m);
  });
  // "May" is a month only with a year after it: "you may 2 tablets" is not.
  const dayOk = (d: string) => Number(d) >= 1 && Number(d) <= 31;
  scan(DATE_MONTH_FIRST, "date", (m) => (isMonth(m[1]) && dayOk(m[2]) && (!/^may$/i.test(m[1]) || m[5]) ? whole(m) : null));
  scan(DATE_DAY_FIRST, "date", (m) => (isMonth(m[4]) && dayOk(m[1]) && (!/^may$/i.test(m[4]) || m[6] || /of/.test(m[3])) ? whole(m) : null));
  scan(DATE_MONTH_YEAR, "date", (m) => (isMonth(m[1]) ? whole(m) : null));
  scan(DATE_DAY_FIRST_INTL, "date", (m) => (dayOk(m[1]) ? whole(m) : null));
  scan(DATE_MONTH_YEAR_INTL, "date", whole);
  // Either way round: "11/03" in Raleigh, "21/10" in Croydon.
  scan(DATE_SHORT, "date", (m) => (validDay(Number(m[1]), Number(m[2])) || validDay(Number(m[2]), Number(m[1])) ? whole(m) : null));

  // Ages over 89, and a birth year that gives one away.
  for (const re of AGE_PATTERNS) scan(re, "age", (m) => group(m, 1));
  // Someone born more than 120 years ago is history, not a patient: "Edith
  // Edson (b. 1870)" in an encyclopedia's family tree.
  scan(BIRTH_YEAR, "year90", (m) => (Number(m[1]) <= now.getFullYear() - 90 && Number(m[1]) > now.getFullYear() - 120 ? group(m, 1) : null));

  // The person a record's name field names, title and all taken off.
  scan(NAME_FIELD, "name", (m) => {
    const got = group(m, 1);
    if (!got) return null;
    const bare = got.value.replace(/^(?:Mr|Mrs|Ms|Miss|Dr|Herr|Frau|M|Mme|Sr|Sra|Sig|Dott).?[ 	]+/, "");
    return { value: bare, start: got.start + got.value.length - bare.length };
  });

  // Record numbers under a clinical label: not a year, not a date.
  scan(CLINICAL_ID, "id", (m) => (/^(?:19|20)\d\d$/.test(m[1]) ? null : group(m, 1)));
  scan(ID_AFTER_LABEL, "id", (m) => (/^(?:19|20)\d\d$/.test(m[1]) ? null : group(m, 1)));
  for (const re of ID_SHAPES) scan(re, "id", whole);

  // Places smaller than a state, and places of care.
  scan(FACILITY_KIND_FIRST, "facility", (m) => group(m, 1));
  scan(FACILITY_PATTERN, "facility", (m) => (SPECIALTY_BEFORE.test(m[1]) ? null : group(m, 1)));
  scan(TOWN_BEFORE_UNIT, "place", (m) => {
    const town = m[1];
    if (STATE_NAMES.has(town.toLowerCase()) || COUNTRY_NAMES.has(town.toLowerCase()) || isCommonLowercaseWord(town.toLowerCase()) || COMMON_CAPITALISED.has(town)) return null;
    return group(m, 1);
  });
  scan(COUNTY_PATTERN, "place", (m) => (STATE_NAMES.has(m[1].toLowerCase()) ? null : whole(m)));
  scan(TOWN_BEFORE_STATE, "place", (m) => {
    const town = m[1];
    if (STATE_NAMES.has(town.toLowerCase()) || isCommonLowercaseWord(town.toLowerCase()) || COMMON_CAPITALISED.has(town)) return null;
    // "Michael Adeyemi, MD", "Jane Ross, PA": a title, unless a ZIP follows.
    const code = m[0].match(/,[ \t]+([A-Z]{2})/)?.[1] ?? "";
    if (AMBIGUOUS_STATE.test(code) && !m[2]) return null;
    return group(m, 1);
  });
  scan(ZIP_AFTER_STATE, "place", (m) => group(m, 1));
  // A postcode under its label, and the second of two.
  POSTCODE_LABELLED.lastIndex = 0;
  for (const m of text.matchAll(POSTCODE_LABELLED)) {
    for (const g of [1, 2, 3]) {
      const got = group(m, g);
      if (got && !/^(?:19|20)\d\d$/.test(got.value)) take("place", got.value, text.indexOf(got.value, m.index ?? 0));
    }
  }
  // A ZIP code after a state written out: "Winnemucca, Nevada, 89445".
  scan(stateZip(), "place", (m) => group(m, 1));
  // European and UK postcodes, and the town beside them.
  for (const re of [EU_POSTCODE_TOWN, UK_POSTCODE]) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      for (const g of [1, 2]) {
        const got = group(m, g);
        if (!got || /^(?:19|20)\d\d$/.test(got.value)) continue;
        const word = got.value.toLowerCase();
        if (/^\p{L}/u.test(got.value) && (isCommonLowercaseWord(word) || COMMON_CAPITALISED.has(got.value) || STATE_NAMES.has(word) || COUNTRY_NAMES.has(word) || FORM_WORDS.test(got.value))) continue;
        take("place", got.value, got.start);
      }
    }
  }

  return found;
}

// ── Stand-ins ────────────────────────────────────────────────

const FAKE_TOWNS = ["Ashford", "Brookfield", "Cedar Falls", "Dunmore", "Eastwick", "Fairhaven", "Glenwood", "Hollis", "Kingsbridge",
  "Lakemont", "Millbrook", "Northfield", "Oakridge", "Pinecrest", "Redmond", "Stanton", "Thornbury", "Westbury", "Whitmore", "Yardley"];
const FAKE_FACILITY_STEMS = ["Brookside", "Fairview", "Hillcrest", "Lakeview", "Maple Grove", "Northgate", "Oakwood", "Ridgeview", "Summit",
  "Valley View", "Westbrook", "Willow Creek"];

function randomInt(lo: number, hi: number): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return lo + (buf[0] % (hi - lo + 1));
}

type ParsedDate = {
  /** Day of the year 2001 (no leap) or of `year`, for the arithmetic. */
  year: number | null;
  month: number;
  day: number;
  format: (y: number | null, m: number, d: number) => string;
};

function ordinal(d: number, like: string): string {
  if (!like) return "";
  const s = d % 100 >= 11 && d % 100 <= 13 ? "th" : (["th", "st", "nd", "rd"][d % 10] ?? "th");
  return like === like.toUpperCase() ? s.toUpperCase() : s;
}

/** A word written in the case of another: "März" -> "Juni", "MÄRZ" -> "JUNI". */
function caseLike(word: string, like: string): string {
  if (like === like.toUpperCase()) return word.toUpperCase();
  if (like[0] === like[0].toUpperCase()) return word[0].toUpperCase() + word.slice(1);
  return word;
}

function monthName(m: number, like: string): string {
  const full = MONTHS[m - 1];
  const dot = like.endsWith(".");
  const bare = like.replace(/\.$/, "");
  let name = bare.length <= 3 ? full.slice(0, 3) : bare.length === 4 && /^sept$/i.test(bare) ? (m === 9 ? "sept" : full.slice(0, 3)) : full;
  if (bare === bare.toUpperCase()) name = name.toUpperCase();
  else if (bare[0] === bare[0].toUpperCase()) name = name[0].toUpperCase() + name.slice(1);
  return name + (dot && name.length <= 4 ? "." : "");
}

const pad = (n: number, like: string) => (like.length === 2 ? String(n).padStart(2, "0") : String(n));
/** In words a day is padded only when it was: "June 09" stays, "June 18" moves to "July 9". */
const padText = (n: number, like: string) => (like.startsWith("0") ? String(n).padStart(2, "0") : String(n));

/** A date as written, read back into numbers and a way to write another one the same way. */
export function parseDate(value: string, lists: string[][] = INTL_MONTHS): ParsedDate | null {
  let m: RegExpMatchArray | null;
  // A record's timestamp: the date moves, the time and its zone stay.
  // "2024-03-14T08:22:00Z", "20240314082200", "19310502".
  if ((m = value.match(/^(\d{4})(-?)(\d{2})\2(\d{2})((?:T[\d:.]{2,15}|\d{4,6}(?:\.\d{1,4})?)(?:Z|[+-]\d{2}:?\d{2})?)$/))) {
    const [, y, sep, mo, d, rest] = m;
    return { year: Number(y), month: Number(mo), day: Number(d), format: (yy, mm, dd) => `${yy}${sep}${pad(mm, mo)}${sep}${pad(dd, d)}${rest}` };
  }
  if ((m = value.match(/^(\d{4})([/.-]?)(\d{1,2})\2(\d{1,2})$/)) && (m[2] || value.length === 8)) {
    const [, y, sep, mo, d] = m;
    return { year: Number(y), month: Number(mo), day: Number(d), format: (yy, mm, dd) => `${yy}${sep}${pad(mm, mo)}${sep}${pad(dd, d)}` };
  }
  if ((m = value.match(/^(\d{1,2})([/.-])(\d{1,2})\2(\d{4}|\d{2})$/))) {
    const [, a, sep, b, y] = m;
    const A = Number(a), B = Number(b);
    // Day first when it must be, or when written with dots; month first otherwise.
    const dayFirst = A > 12 || (sep === "." && B <= 12);
    const month = dayFirst ? B : A, day = dayFirst ? A : B;
    const year = y.length === 2 ? 2000 + Number(y) - (Number(y) > 40 ? 100 : 0) : Number(y);
    return {
      year, month, day,
      format: (yy, mm, dd) => {
        const ys = y.length === 2 ? String((yy ?? year) % 100).padStart(2, "0") : String(yy);
        return dayFirst ? `${pad(dd, a)}${sep}${pad(mm, b)}${sep}${ys}` : `${pad(mm, a)}${sep}${pad(dd, b)}${sep}${ys}`;
      },
    };
  }
  if ((m = value.match(/^(\d{1,2})\/(\d{1,2})$/))) {
    const [, a, b] = m;
    if (Number(a) > 12) return { year: null, month: Number(b), day: Number(a), format: (_y, mm, dd) => `${pad(dd, a)}/${pad(mm, b)}` };
    return { year: null, month: Number(a), day: Number(b), format: (_y, mm, dd) => `${pad(mm, a)}/${pad(dd, b)}` };
  }
  const monthFirst = new RegExp(String.raw`^(${MONTH_RE})[ \t]+(\d{1,2})(${ORD})(?:(,?[ \t]+)(\d{4}))?$`, "iu");
  if ((m = value.match(monthFirst))) {
    const [, mon, d, suf, sep, y] = m;
    const month = MONTHS.findIndex((x) => x.startsWith(mon.toLowerCase().replace(/\.$/, "").slice(0, 3))) + 1;
    return {
      year: y ? Number(y) : null, month, day: Number(d),
      format: (yy, mm, dd) => `${monthName(mm, mon)} ${padText(dd, d)}${ordinal(dd, suf)}${y ? `${sep}${yy}` : ""}`,
    };
  }
  const dayFirst = new RegExp(String.raw`^(\d{1,2})(${ORD})([ \t]+(?:of[ \t]+)?)(${MONTH_RE})(?:(,?[ \t]+)(\d{4}))?$`, "iu");
  if ((m = value.match(dayFirst))) {
    const [, d, suf, mid, mon, sep, y] = m;
    const month = MONTHS.findIndex((x) => x.startsWith(mon.toLowerCase().replace(/\.$/, "").slice(0, 3))) + 1;
    return {
      year: y ? Number(y) : null, month, day: Number(d),
      format: (yy, mm, dd) => `${padText(dd, d)}${ordinal(dd, suf)}${mid}${monthName(mm, mon)}${y ? `${sep}${yy}` : ""}`,
    };
  }
  const intlDay = new RegExp(String.raw`^(\d{1,2})(\.|er|º|°)?([ \t]+(?:de[ \t]+)?)(${INTL_MONTH_RE})(?:((?:,|[ \t]+de)?[ \t]+)(\d{4}))?$`, "iu");
  if ((m = value.match(intlDay))) {
    const [, d, suf = "", mid, mon, sep = "", y] = m;
    const found = intlMonth(mon, lists);
    if (found) {
      // "1er" is the first only; any other day drops it.
      return {
        year: y ? Number(y) : null, month: found.index + 1, day: Number(d),
        format: (yy, mm, dd) => `${padText(dd, d)}${suf === "er" ? (dd === 1 ? "er" : "") : suf}${mid}${caseLike(found.list[mm - 1], mon)}${y ? `${sep}${yy}` : ""}`,
      };
    }
  }
  const intlMonthYear = new RegExp(String.raw`^(${INTL_MONTH_RE})([ \t]+(?:de[ \t]+)?)(\d{4})$`, "iu");
  if ((m = value.match(intlMonthYear))) {
    const [, mon, sep, y] = m;
    const found = intlMonth(mon, lists);
    if (found) return { year: Number(y), month: found.index + 1, day: 15, format: (yy, mm) => `${caseLike(found.list[mm - 1], mon)}${sep}${yy}` };
  }
  const monthYear = new RegExp(String.raw`^(${MONTH_RE})(,?[ \t]+)(\d{4})$`, "iu");
  if ((m = value.match(monthYear))) {
    const [, mon, sep, y] = m;
    const month = MONTHS.findIndex((x) => x.startsWith(mon.toLowerCase().replace(/\.$/, "").slice(0, 3))) + 1;
    return { year: Number(y), month, day: 15, format: (yy, mm) => `${monthName(mm, mon)}${sep}${yy}` };
  }
  return null;
}

const DAY_MS = 86_400_000;

/** The date moved by `days`, kept in its year: a move that would leave the
 *  year goes the other way instead. A date with no year moves freely. */
export function shiftDate(value: string, days: number, lists: string[][] = INTL_MONTHS): string | null {
  const p = parseDate(value, lists);
  if (!p) return null;
  const year = p.year ?? 2001;
  const base = Date.UTC(year, p.month - 1, Math.min(p.day, 28 + 3));
  for (const d of [days, -days]) {
    const t = new Date(base + d * DAY_MS);
    if (p.year !== null && t.getUTCFullYear() !== p.year) continue;
    return p.format(p.year === null ? null : t.getUTCFullYear(), t.getUTCMonth() + 1, t.getUTCDate());
  }
  return null;
}

/** The weeks a map's dates were already moved by, so a later turn moves its
 *  new dates the same way. */
function existingShift(map: RedactionMap): number | null {
  for (const [standIn, real] of Object.entries(map)) {
    const a = parseDate(real), b = parseDate(standIn);
    if (!a || !b || (a.year === null) !== (b.year === null)) continue;
    const y = a.year ?? 2001;
    const diff = Math.round((Date.UTC(b.year ?? 2001, b.month - 1, b.day) - Date.UTC(y, a.month - 1, a.day)) / DAY_MS);
    if (diff !== 0 && diff % 7 === 0 && Math.abs(diff) <= 182) return Math.abs(diff);
  }
  return null;
}

/**
 * Adds stand-ins for what findMedical found, and for the places the name
 * model tagged. Network addresses take the ordinary host stand-in.
 */
export async function addMedicalRedactions(
  map: RedactionMap,
  found: MedicalFinding[],
  haystack: string,
  allow: AllowList = new Set(),
): Promise<RedactionMap> {
  let out: RedactionMap = { ...map };
  // Network addresses, record numbers, and a record's addresses, phones,
  // e-mails and SSNs take the ordinary stand-ins.
  type Ordinary = { kind: "host" | "govid" | "address" | "phone" | "email" | "ssn"; value: string };
  out = await addFoundRedactions(out, found.flatMap((f): Ordinary[] =>
    f.kind === "id" ? [{ kind: "govid", value: f.value }]
      : f.kind === "host" || f.kind === "address" || f.kind === "phone" || f.kind === "email" || f.kind === "ssn" ? [{ kind: f.kind, value: f.value }]
        : []), haystack, allow);

  // Names from a record's fields take the ordinary name stand-ins.
  out = await addNameRedactions(out, found.filter((f) => f.kind === "name").map((f) => f.value), haystack, allow);

  const taken = new Set(Object.keys(out));
  const covered = new Set(Object.values(out).map((v) => v.toLowerCase()));
  const lower = haystack.toLowerCase();
  const lists = monthListsFor(haystack);
  // One move for the whole record, drawn so that no moved date lands on a
  // date already in it. A move of one week took 03/14 to 03/21, the real
  // discharge date beside it; that one date was pushed a week further and
  // the stay came back fourteen days long (a test caught it 1 run in 8).
  const dates = found.filter((f) => f.kind === "date").map((f) => f.value);
  const clashes = (w: number) => dates.some((d) => {
    const s = shiftDate(d, w, lists);
    return s !== null && (taken.has(s) || lower.includes(s.toLowerCase()));
  });
  let weeks = existingShift(out) ?? 0;
  if (!weeks) {
    const order = Array.from({ length: 26 }, (_, i) => 7 * (i + 1)).sort(() => randomInt(0, 1) - 0.5);
    weeks = order.find((w) => !clashes(w)) ?? order[0];
  }
  const salt = String(randomInt(0, 2 ** 31));

  const put = (standIn: string | null, value: string) => {
    if (!standIn || taken.has(standIn) || lower.includes(standIn.toLowerCase())) return false;
    out[standIn] = value;
    taken.add(standIn);
    covered.add(value.toLowerCase());
    return true;
  };

  for (const { kind, value } of found) {
    if (kind === "host" || kind === "id" || kind === "name" || kind === "address" || kind === "phone" || kind === "email" || kind === "ssn") continue;
    if (taken.size >= MAX_REDACTION_ENTRIES) break;
    if (!isSubstitutable(value) || covered.has(value.toLowerCase()) || isAllowed(value, allow)) continue;
    switch (kind) {
      case "date": {
        // Same move for every date; a stand-in that collides moves a week further.
        for (let extra = 0; extra < 4; extra++) if (put(shiftDate(value, weeks + 7 * extra, lists), value)) break;
        break;
      }
      case "age": {
        for (let n = 0; n < 40; n++) {
          const age = String(randomInt(90, 105));
          if (age !== value && put(age, value)) break;
        }
        break;
      }
      case "year90": {
        const latest = new Date().getFullYear() - 90;
        for (let n = 0; n < 40; n++) {
          const year = String(randomInt(latest - 15, latest));
          if (year !== value && put(year, value)) break;
        }
        break;
      }
      case "place": {
        const zip = /^\d{5}(-\d{4})?$/.test(value);
        const suffix = value.match(/[ \t]+(County|Parish|Borough)$/)?.[1];
        // The town's own words are refused in its stand-in; "County" is kept on purpose.
        put(await pickFake(`${suffix ? value.replace(/[ 	]+(?:County|Parish|Borough)$/, "") : value}|${salt}`, taken, haystack, (i, hex) => {
          if (zip) return String(10000 + (parseInt(hex.slice(0, 6), 16) + i * 7919) % 89999) + (value.length > 5 ? `-${String(1000 + (parseInt(hex.slice(6, 10), 16) + i) % 8999)}` : "");
          // Any other postcode keeps its shape: "H91 X2Y3", "HG1 2AB", "1100-053".
          if (/\d/.test(value)) {
            return [...value].map((ch, n) => (/\d/.test(ch) ? String((parseInt(hex[(n + i) % 32], 16) + i) % 10)
              : /[A-Z]/.test(ch) ? String.fromCharCode(65 + ((parseInt(hex[(n + i + 7) % 32], 16) + i) % 26)) : ch)).join("");
          }
          const town = FAKE_TOWNS[(parseInt(hex.slice(0, 6), 16) + i) % FAKE_TOWNS.length];
          return suffix ? `${town} ${suffix}` : town;
        }, !zip && !/\d/.test(value)), value);
        break;
      }
      case "facility": {
        // The kind of place is kept: the model is still told it was a hospital.
        // Written first ("Klinikum Schwabing", "CHU de Rennes") it stays first.
        const head = value.match(new RegExp(`^${KIND_FIRST_HEAD}`, "u"))?.[0];
        const kindWords = head ?? value.match(new RegExp(`${FACILITY_KIND}(?:[ \\t]+of[ \\t]+.*)?$`, "u"))?.[0].replace(/[ \t]+of[ \t]+.*$/, "") ?? "Clinic";
        put(await pickFake(`${value.replace(kindWords, "")}|${salt}`, taken, haystack, (i, hex) => {
          const stem = FAKE_FACILITY_STEMS[(parseInt(hex.slice(0, 6), 16) + i) % FAKE_FACILITY_STEMS.length];
          return head ? `${head} ${stem}` : `${stem} ${kindWords}`;
        }, true), value);
        break;
      }
      case "url": {
        const scheme = value.match(/^(?:https?|ftp):\/\//i)?.[0] ?? "";
        put(await pickFake(`${value}|${salt}`, taken, haystack, (i, hex) => `${scheme || "www."}${scheme ? "portal" : ""}.example.org/${hex.slice(i % 20, (i % 20) + 10)}`.replace("www.portal", "www")), value);
        break;
      }
    }
  }
  return out;
}
