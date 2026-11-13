/**
 * PII redaction, part two: structured identifiers.
 *
 * Emails, cards, IBANs, national ids, phones, addresses, postcodes and
 * internal hostnames — everything with a shape, found anywhere in what the
 * user typed, whoever it belongs to. Each gets a stand-in of the same shape
 * so the model can still reason about it. See redactionMap for the map these
 * are added to.
 */

import {
  FAKE_AREA_CODES, FAKE_EMAIL_DOMAINS, FAKE_FIRST, FAKE_LAST, MAX_REDACTION_ENTRIES,
  escapeRegex, isAllowed, isSubstitutable, lowered, pickFake,
} from "./redactionMap.js";
import type { AllowList, RedactionMap } from "./redactionMap.js";
import { COMMON_CAPITALISED, isCommonLowercaseWord, isGivenNameAnywhere, isNotAPerson } from "./redactionNameWords.js";
import { GIVEN_NAMES } from "./redactionGivenNames.js";
import { foldForScan } from "./redactionFold.js";
import { findFields } from "./redactionFields.js";
import { findRowCells } from "./redactionRows.js";
import { findAsianAddresses } from "./redactionAddressAsia.js";
import { findContextPhones } from "./redactionPhoneContext.js";
import { PH_BARANGAY_PATTERN, HAS_BARANGAY, PH_POSTCODE_PATTERN, IN_LOWER_ADDRESS_PATTERN, IN_NOT_A_STREET, IN_PIN_PATTERN, HAS_INDIC, IN_PIN_INDIC_PATTERN, IN_STREET_INDIC_PATTERN, VN_NUMBER_FIRST_PATTERN, CS_STREET_PATTERN, HAS_CZECH_SLOVAK, EL_STREET_PATTERN, HU_TOWN_FIRST_PATTERN, ES_ROAD_PATTERN, ES_ROAD_FAMOUS, IT_FR_ROAD_PATTERN, IT_FR_ROAD_FAMOUS, DE_NL_STREET_TOWN_PATTERN, PT_STREET_NUMERO_PATTERN } from "./redactionAddressWorld.js";
import { findArabicValues } from "./redactionArabic.js";
import { findMoreScriptValues, findPostcodesBesideTowns, findStreetsBesidePostcodes } from "./redactionMoreScripts.js";
import {
  ADDRESS_TAIL_PATTERN, ADDRESS_BLOCK_TERMINAL, STREET_BEFORE_BLOCK_PATTERN, CARD_LABELLED_PATTERN, BARE_REPLY_PATTERN, ASKED_FOR_PHONE, ASKED_FOR_POSTCODE, ASKED_FOR_ID, CORNER_PATTERN, PLACE_POSTCODE_PATTERN,
  IMEI_CUED_PATTERN, IMEI_GROUPED_PATTERN, SECRET_VENDOR_PATTERN, SIGNED_KEY_PATTERN,
  BR_CPF_PATTERN, BR_CNPJ_PATTERN, CARD_TWELVE_CUED_PATTERN, CL_RUT_PATTERN, MX_CURP_PATTERN, SG_NRIC_PATTERN, HK_ID_PATTERN, CN_RIC_PATTERN, IE_PPS_PATTERN,
  FR_NIR_PATTERN, BE_NN_PATTERN, MY_NRIC_PATTERN, PK_CNIC_PATTERN, MY_NUMBER_IS_PATTERN, KR_PASSPORT_CUED_PATTERN, PHONE_SHORT_CUED_PATTERN, CZ_RC_PATTERN, PT_CC_PATTERN, MU_NID_PATTERN, ES_NIE_LOWER_PATTERN,
  ACCOUNT_CUED_PATTERN, ACCOUNT_CUED_INTL_PATTERN, CARD_LABELLED_INTL_PATTERN, CARD_LABELLED_WORLD_PATTERN, CARD_WORD_RUN_PATTERN, CARD_NEAR_LABEL_PATTERN, NINO_CUED_PATTERN, PHONE_CUED_INTL_PATTERN, PIN_CUED_PATTERN, PASSWORD_LABELLED_PATTERN, USERNAME_LABELLED_PATTERN, USERNAME_NOT, ID_DOC_CUED_PATTERN, ROUTING_CUED_INTL_PATTERN, DOB_LABELLED_PATTERN, BIC_CUED_PATTERN, BIC_LABELLED_PATTERN, CVV_LABELLED_PATTERN, CUSTOMER_ID_CUED_PATTERN, ISO_COUNTRY_CODES, ADDRESS_PATTERN, ASSIGNED_SECRET_PATTERN, AUTH_HEADER_PATTERN, AU_POSTCODE_PATTERN,
  ADDRESS_CUED_PATTERN, WORLD_RECORD_ID_PATTERN, INSURANCE_ID_PATTERN, WORLD_STREET_PATTERN, ADDRESS_LABELLED_PATTERN, ADDRESS_LABEL_NOT_A_STREET, AZURE_CLIENT_SECRET_PATTERN, ID_LABEL_AFTER_PATTERN, JP_ADDRESS_PATTERN, JP_POSTCODE_PATTERN, USERNAME_WORLD_PATTERN, plausibleWorldUsername,
  SOUTH_ASIAN_ADDRESS_PATTERN, HAS_SOUTH_ASIAN_OR_ARABIC,
  ACCOUNT_CUED_WORLD_PATTERN,
  PASSWORD_WORLD_NEAR_PATTERN, DOOR_CODE_PATTERN, PHONE_CUED_WORLD_PATTERN, PHONE_NATIONAL_SHAPED_PATTERN, VAT_CUED_PATTERN, BUSINESS_ID_LABELLED_PATTERN, JA_ACCOUNT_PATTERN, ES_PHONE_PATTERN, WORLD_ID_LABELLED_PATTERN, CJK_ID_LABELLED_PATTERN, GLUED_FORM_ID_PATTERN, WORLD_ID_NEAR_PATTERN, ID_LOG_KEY_PATTERN,
  JP_ROMAJI_ADDRESS_PATTERN, PH_CRN_PATTERN, NOT_A_STREET_PATTERN, AUTH_HEADER_BARE_PATTERN, ZA_ID_PATTERN, SECRET_COMPARED_PATTERN, AU_MEDICARE_PATTERN, CARD_DOTTED_PATTERN, DE_SVNR_PATTERN, ELEVEN_DIGITS_PATTERN, ES_ID_PATTERN,
  FI_HETU_PATTERN, GROUPED_ID_PATTERN, IN_AADHAAR_PATTERN, IN_PAN_PATTERN, IT_CF_PATTERN, KR_RRN_PATTERN, SE_PNR_PATTERN,
  TH_TNIN_PATTERN, UK_DL_PATTERN, UK_NINO_PATTERN, US_MBI_PATTERN, CURL_USER_PATTERN, NAMED_SECRET_PATTERN, XML_SECRET_TAG_PATTERN, BARE_KEY_PATTERN, KEY_SPOKEN_PATTERN, COUNTRY_POSTCODE_PATTERN, MILITARY_ADDRESS_PATTERN, MILITARY_SHIP_PATTERN, CORNER_SECOND_PATTERN, PHONE_LABEL_AFTER_PATTERN, POSTCODE_CUED_INTL_PATTERN, CUED_ID_ACRONYM_PATTERN, CVV_CUED_PATTERN, EMAIL_ENCODED_PATTERN, MAC_ADDRESS_PATTERN,
  OBFUSCATED_EMAIL_PATTERN, PASSPORT_MRZ_PATTERN, EIRCODE_PATTERN, US_ZIP_AFTER_STATE_COMMA_PATTERN, EU_POSTCODE_PATTERN, NL_POSTCODE_PATTERN, PAN_PATTERN, PASSWORD_IS_PATTERN, PEM_PRIVATE_KEY_PATTERN, PO_BOX_PATTERN,
  URL_CREDENTIAL_PATTERN, CARD_PATTERN, CARD_BARE_SIXTEEN_PATTERN, CARD_RUN_PATTERN, CA_POSTCODE_PATTERN,
  CH_SSN_PATTERN, CH_SSN_BARE_PATTERN, CRYPTO_ADDRESS_PATTERN, CUED_ID_PATTERN, DOB_CUED_PATTERN, EMAIL_PATTERN,
  FAKE_HOST_WORDS, HOST_KEEP, IBAN_CUED_PATTERN, IBAN_LENGTHS, IBAN_PAPER_TAIL_PATTERN, IBAN_PATTERN, IBAN_SHAPED_PATTERN, IBAN_START_PATTERN,
  INTERNAL_HOST_PATTERN, INTERNAL_MARKERS, IPV6_PATTERN, PHONE_CUED_PATTERN, PHONE_PATTERN, PRIVATE_IP_PATTERN, IP_LABELLED_PATTERN, IP_AFTER_IP_PATTERN, IP_LABEL_MACHINE, IP_NOT_A_PERSON,
  IP_BRIDGED_PATTERN, API_KEY_SPOKEN_PATTERN, COOKIE_SPOKEN_PATTERN, USERNAME_SPOKEN_PATTERN, WORD_ENDING_PATTERN, PACKAGE_COMMAND_PATTERN,
  SECRET_PATTERN, SSN_CUED_LOOSE_PATTERN, SSN_CUED_INTL_PATTERN, SSN_CUED_PATTERN, SSN_PATTERN, SSN_SPACED_PATTERN,
  UK_POSTCODE_PATTERN, POSTCODE_LABELLED_PATTERN, POSTCODE_LABEL_GLUED_PATTERN, TW_POSTCODE_BEFORE_CITY_PATTERN, KO_POSTCODE_AFTER_ADDRESS_PATTERN, POSTCODE_LINE_PATTERN, PLACE_LINE_PATTERN, US_ZIP_CUED_PATTERN, US_ZIP_PATTERN, US_ZIP_PLUS4_PATTERN, VIN_PATTERN, PLATE_LABELLED_PATTERN, POSTCODE_AFTER_STREET_PATTERN,
  ZIP_AFTER_PLACE_PATTERN, ZIP_BESIDE_ADDRESS_PATTERN, PHONE_CUED_INDIC_PATTERN, ID_CUED_INDIC_PATTERN,
  RANDOM_TOKEN_PATTERN, NAME_HANDLE_PATTERN, NAME_DOT_PATTERN, NAME_NUMBER_PATTERN, WEAK_STREET_CUED_PATTERN, PHONE_SMALL_CUE_PATTERN, ACCOUNT_PAYMENT_PATTERN, APT_ALONE_PATTERN, END_LABEL_PATTERN, AR_CPA_PATTERN, NL_POSTCODE_ALONE_PATTERN, ID_POSSESSIVE_PATTERN, ID_UPPER_TOKEN_PATTERN, ADDRESS_NON_LATIN_PATTERN, HAS_NON_LATIN, ADDRESS_INTL_CUED_PATTERN, HAS_STREET_CUE_INTL, AUTH_LOG_IP_PATTERN, BIC_BARE_PATTERN, BANKING_CONTEXT, PIN_WORDED_PATTERN, PIN_VERB_PATTERN, CH_UID_PATTERN, EU_VAT_PATTERN, FR_TAX_GROUPED_PATTERN, PASSPORT_SHAPE_PATTERN, PT_ID_CUED_PATTERN, CVV_AFTER_PATTERN, CRYPTO_CUED_PATTERN, HANDLE_CUED_PATTERN, RECORD_ID_LABELLED_PATTERN, RECORD_ID_PREFIXED_PATTERN, RECORD_ID_SHAPED_PATTERN, RECORD_REF_PATTERN, USERNAME_QUOTED_PATTERN, SESSION_COOKIE_PATTERN, PASSWORD_FOR_PATTERN, PHONE_TRUNK_PATTERN, ORDER_CODE_PATTERN, ORDER_CODE_PERSONAL, BUILDING_CUED_PATTERN, NUMBER_ON_STREET_PATTERN, CN_RESIDENT_ID_PATTERN, ID_SANDWICH_PATTERN, PHONE_MIXED_PATTERN, STREET_NUMBERLESS_PATTERN, PIN_LOOSE_PATTERN, NUMBER_POSSESSIVE_PATTERN, ZIP_PLACE_WORD_PATTERN, POSTCODE_GLUED_PATTERN, ACCOUNT_BARE_PATTERN, BARE_EIGHT_NOT_AN_ACCOUNT, BARE_EIGHT_COUNTS, FR_PASSPORT_PATTERN, PHONE_ZERO_GROUPS_PATTERN,
} from "./redactionPatterns.js";
import { acceptLearned, learnedCuePatterns, type LearnedCue } from "./redactionLearned.js";

/** The learned labels, compiled once. */
const LEARNED = learnedCuePatterns();

/**
 * Stage 2: structured identifiers the user typed, whoever they belong to.
 *
 * Stage 1 only knows the values on the caller's own profile. This finds the
 * ones with a shape — an email, a phone number, a card, a national insurance
 * or social security number — anywhere in what the user wrote, including the
 * ones belonging to other people. No model is involved, so it costs a regex
 * pass and nothing else.
 *
 * The scan runs over the user's own text only, never over the assembled system
 * prompt: the personality, the formatting guide and the brain corrections are
 * ours, and aliasing an example address inside our own instructions would
 * quietly change what the model was told to do.
 *
 * The shapes themselves are in redactionPatterns, and are deliberately narrow
 * for the reason given there. What is left here is what happens to a match:
 * the checksums that decide whether one is real, and the stand-ins.
 */

/** Street names for the stand-in addresses. Ordinary and unremarkable, for the
 *  same reason the names are: a model reasons about a plausible address and
 *  balks at an obviously fake one. */
const FAKE_STREETS = [
  "Wexford", "Alderney", "Brookmere", "Carlisle", "Denholm", "Ellersby",
  "Fairmount", "Granville", "Harlow", "Inverness", "Kelvinside", "Lockhart",
  "Marchmont", "Northgate", "Oakbourne", "Pembroke", "Ravensworth", "Selkirk",
  "Thornbury", "Uxbridge", "Vandermeer", "Westbrook", "Yarrow", "Ashcombe",
];

const FAKE_STREET_WORDS = ["Street", "Road", "Avenue", "Lane", "Drive", "Close", "Way", "Court"];

/**
 * ISO 13616's mod-97 check. Move the first four characters to the end, turn
 * every letter into two digits (A=10 … Z=35), and the whole thing read as one
 * enormous number must leave remainder 1.
 *
 * Computed digit by digit rather than with BigInt: an IBAN can be 34
 * characters, which becomes a 68-digit number, and the running remainder is
 * both exact and cheap where the naive parse would silently lose precision.
 */
function iban97(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
  if (compact.length < 15 || compact.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) return false;

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const part = /[A-Z]/.test(ch)
      ? String(ch.charCodeAt(0) - 55)
      : ch;
    for (const digit of part) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

/** A stand-in that passes the same check, in the same country and the same
 *  length — a model handed an IBAN it can tell is malformed will say so
 *  instead of answering the question that was asked about it. */
/**
 * Luhn, and then the thing Luhn cannot see.
 *
 * "000000000000935" passes the checksum and is a padded reference number in
 * a real invoice, not a card — no issuer has ever allocated a number that
 * opens with eleven zeros. A leading zero at all is rare enough (no major
 * network uses one) that two in a row is the line.
 */
function plausibleCard(value: string, before?: string, after?: string): boolean {
  // Not a run of digits welded onto a word. A Wall Street Journal article
  // is "SB1008803774562546920", which passes Luhn, and hundreds of them sat
  // in the Enron corpus inside links people had pasted.
  //
  // Inside a URL, and only that.
  //
  // The first attempt rejected any run welded onto a word, which also
  // rejected "body.pay4111111111111111" — a card concatenated into a field
  // path, which is the single most important finding the gateway makes and
  // which audit.test requires. A link is different: it is a whole token
  // nobody typed a card into, and a scheme with no whitespace after it is
  // what says so.
  if (before && /\b(?:https?:\/\/|www\.)\S*$/.test(before)) return false;
  const digits = value.replace(/\D/g, "");
  /* The sentence says it is a card: "your credit card details (0098…)",
     "use the 0634… card", "7212… issued by Mastercard", "1870… Use CVV 522".
     Then the issuer's opening digit is not needed to tell it from an order
     number, and the two rules below that exist only to tell them apart — no
     leading 00, an opening 2 to 6 — stand aside. Luhn and the grouping still
     decide. On the ai4privacy practice set, nine of the twenty Luhn-valid
     cards were missed for their first digit alone, every one named as a card
     in the same sentence. */
  const cued = CARD_CUE_BEFORE.test(before ?? "") || CARD_CUE_AFTER.test(after ?? "");
  if (digits.startsWith("00") && !cued) return false;
  // A single repeated digit passes Luhn surprisingly often and is always a
  // placeholder: 4444…, 0000…, 1111 1111 1111 1111 is the test card everyone
  // knows, and the golden samples keep that one on purpose.
  if (/^(\d)\1+$/.test(digits)) return false;
  // Grouped the way a card is printed, or not grouped at all: fours with a
  // short last group, or Amex's 4-6-5 and Diners' 4-6-4. "19 20 21 22 23 24
  // 25" is a week of a calendar, and Python's documentation prints several.
  const groups = value.split(/[ -]+/).map((g) => g.length);
  if (groups.length > 1) {
    const fours = groups.slice(0, -1).every((n) => n === 4) && groups[groups.length - 1] <= 4;
    const amex = groups.join("-") === "4-6-5" || groups.join("-") === "4-6-4";
    if (!fours && !amex) return false;
  }
  // The digits of a decimal, a negative number or a hex literal are not a
  // card: "0.35935114681123076", "me_hash = -368181376027291943".
  if (before && /(?:\d\.|-|0x)$/.test(before)) return false;
  // A block id: HDFS names every block "blk_" and nineteen digits, and one in
  // ten passes Luhn (Loghub). A card is never written after an underscore.
  if (before && /_$/.test(before)) return false;
  // Nor in a row of figures: "child of command 2489 451683 3223 boot_cmd"
  // is a command, a node count and a duration (Loghub HPC).
  if (/ /.test(value) && !cued && before && /\d[ \t]+$/.test(before)) return false;
  // Payment cards open with 2 to 6 (Mastercard's 2-series, Amex and Diners'
  // 3, Visa's 4, Mastercard and Maestro's 5, Discover and UnionPay's 6). A
  // fifteen-digit thread id in a Python traceback opens with 1 and passes Luhn
  // one time in ten.
  // The exception is UATP, the airline card: fifteen digits opening with 1,
  // taken only when the sentence says it is a card.
  if (!/^[2-6]/.test(digits) && !cued && !(/^1\d{14}$/.test(digits) && /\b(?:card|cc|credit|debit|uatp)\b[^.\n]{0,20}$/i.test(before ?? ""))) return false;
  return luhn(digits);
}

/** The words that say a number is a payment card, within its sentence: a
 *  brand, "card", or the security code printed beside it. No digits between,
 *  so the word belongs to this number and not to one before it. */
const CARD_WORD = String.raw`\b(?:cards?|cc|visa|master\s?card|amex|american\s+express|discover|jcb|maestro|unionpay|diners|cvv2?|cvc2?)\b`;
const CARD_CUE_BEFORE = new RegExp(String.raw`${CARD_WORD}[^.\n\d]{0,40}$`, "i");
const CARD_CUE_AFTER = new RegExp(String.raw`^[^.\n\d]{0,30}?${CARD_WORD}`, "i");

/** A word that names a sixteen-digit number as a reference rather than a
 *  card, in the few words before it: "Order 0751962800711642", "ticket …",
 *  "invoice …". */
const CVV_AFTER_CARD = /^(?:\s*,\s*|\s*&\s*|\s+(?:and|or|plus|with|accompanied by)\s+)(?:(?:the|its|associated|cvv|cvc|code)\s+){0,2}(\d{3})(?![\p{L}\p{N}.,:\/-]|[.,]\d)/iu;
const CVV_BEFORE_CARD = /(?<![\p{L}\p{N}.,:$€£\/-])(\d{3})(?:\s*,\s*|\s+(?:and|or|&)\s+)$/iu;
const BARE_SIXTEEN_REFERENCE =/\b(?:orders?|ticket|ref(?:erence)?|invoice|tracking|shipment|parcel|booking|confirmation|case|po|transaction|txn|serial|imei|batch|lot|isbn|ean|gtin|barcode|id)\b[^.!?\n\d]{0,25}$/i;

/**
 * Whether a token reads as random rather than as words — a password typed into
 * a sentence. Measured on ai4privacy's practice set and against the Python and
 * Kubernetes documentation, where identifiers are what a loose rule takes:
 * camelCase and PascalCase words, PyErr_SetString, AWS_EFS_CSI_Driver.
 *
 * A word is a run of two or more lower-case letters; a random token is mostly
 * runs of one — "Y2rWliOhf8Ir" is Y,2,r,W,li,O,hf,8,I,r. Two capitals and two
 * small letters at least, and a digit or an underscore, so a long word in
 * capitals is not one.
 */
export function randomToken(t: string): boolean {
  // A date format: "yyyyMMdd_HHmmss" (WildChat).
  if (/^(?:y{2,4}|M{1,4}|d{1,2}|H{1,2}|h{1,2}|m{1,2}|s{1,2}|S{1,3}|[-_.:T])+$/.test(t)) return false;
  if (codeName(t)) return false;
  const up = (t.match(/[A-Z]/g) ?? []).length;
  const lo = (t.match(/[a-z]/g) ?? []).length;
  const di = (t.match(/\d/g) ?? []).length;
  // jumbled is for letters standing alone; an underscore makes it code's to
  // judge below ("PyOS_vsnprintf", "_CrtDbgReport").
  if (up < 2 || lo < 2 || di + up < 4) return !t.includes("_") && jumbled(t);
  if (di === 0 && !t.includes("_")) return jumbled(t);
  // Identifiers joined by underscores are made of words and acronyms.
  if (t.split("_").some((p) => /^(?:[A-Z][a-z]{2,}|[A-Z]{2,}|Py[A-Z]\w*|Py|[a-z]{3,})$/.test(p))) return false;
  // And of PascalCase words, without a digit: HealthApp's "HiH_HiAppUtil" is
  // a class name in a log (Loghub).
  // Words have vowels: "qvKKn__BcDq_" and "cS_CvUkdgYld" are passwords.
  if (di === 0 && t.split("_").some((p) => {
    const parts = p.match(/[A-Z][a-z]*/g) ?? [];
    return parts.length >= 2 && parts.join("") === p && parts.every((w) => w.length >= 2 && /[aeiou]/i.test(w));
  })) return false;
  // A name made of capitalised words and a version: "MobileNetV3" (WildChat).
  // Words, not syllables: "Gns5ftAilMbx" and "mySmvOvi7Fph" are passwords.
  const named = t.match(/[A-Z][a-z]{2,}/g) ?? [];
  const unworded = t.replace(/[A-Z][a-z]{2,}/g, "");
  if (named.length >= 2 && named.every((w) => /[aeiouy]/.test(w) && /[^aeiouy]/.test(w.slice(1))) && named.some((w) => w.length >= 5) && unworded.length <= 3) return false;
  const runs = t.match(/[A-Z]+|[a-z]+|\d+|_+/g) ?? [];
  const single = runs.filter((r) => r.length === 1).length;
  const words = runs.filter((r) => /^[a-z]{3,}$/.test(r)).length;
  return (single >= 4 && single / runs.length >= 0.5 && words <= 1) || jumbled(t);
}

/**
 * A name in code, made of words and numbers: "MethodRefSig_294",
 * "Int17Matrix3D", "EfficientNetV2B0", "DestinationIsIpv6" (WildChat, pasted
 * C, C++, Python and logs). A part reads as a word when it has a vowel after
 * its first letter and no run of consonants English does not write; a
 * password's parts mostly do not — "Iahmz", "Jjv", "Ukdg", "Mbx".
 */
const CODE_ABBREVIATION = /^(?:Int|Str|Ptr|Src|Dst|Msg|Cfg|Ctx|Std|Buf|Cmd|Btn|Lbl|Txt|Img|Pkg|Lib|Env|Arg|Num|Val|Obj|Idx|Len|Max|Min|Sum|Avg|Tmp|Var|Db|Fn|Http|Https|Html|Xml|Json|Sql|Url|Css|Rgb|Png|Jpg|Gps|Ssl|Tls|Ssh|Ftp|Tcp|Udp|Dns|Sdk|Gpu|Cpu)$/;
const CLUSTER = /dth|nts|rts|lds|rds|mps|str|ght|sch|nch|nst|ntr|ndr|thr|chr|spr|scr|rst|mpl|ngl|nds|rch|tch|ckl|ncl|ngs|nth|lth|rth|pth|ndl|rtr|ctr|xtr|phr|shr/;
function codeName(t: string): boolean {
  const parts = t.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+|_+/g) ?? [];
  if (parts.join("") !== t) return false;
  const lettered = parts.filter((p) => /[A-Za-z]/.test(p));
  const total = lettered.reduce((n, p) => n + p.length, 0);
  if (!total) return false;
  // Code keeps its case: every word after the first starts with a capital,
  // unless an underscore starts it, and no letter stands alone in lower case.
  // "RohuaBop5iGb" and "0e9SpaIOfahj" break both; "Int17Matrix3D" neither.
  // A one-letter prefix that opens the name is a convention: "xWidthInMs".
  if (parts.some((p, i) => /^[a-z]/.test(p) && ((p.length === 1 && !(i === 0 && /^[A-Z][a-z]{2,}/.test(parts[1] ?? ""))) || (i > 0 && parts[i - 1] !== "_" && parts.slice(0, i).some((q) => /[A-Za-z]/.test(q)))))) return false;
  const wordLike = (p: string) => {
    const s = p.toLowerCase();
    if (/[^aeiouy]{4,}/.test(s) || (/[^aeiouy]{3}/.test(s) && !CLUSTER.test(s))) return false;
    return /[aeiouy]/.test(s.slice(1));
  };
  // A word of four letters or more carries it, an acronym never does ("QYXK"
  // is no word), and the words must be most of the letters: "Byles5GlZZW9"
  // and "tDElowf7kf9g" are half a word and half noise.
  const isWord = (p: string) => !/^[A-Z]+$/.test(p) && wordLike(p);
  if (!lettered.some((p) => p.length >= 5 && isWord(p))) return false;
  if (lettered.some((p) => p.length >= 4 && !/^[A-Z]+$/.test(p) && !wordLike(p) && !CODE_ABBREVIATION.test(p))) return false;
  // Words are most of the letters, and at least half the whole name, digits
  // and all, less a trailing "_294": "93Q2Mcaql7P_" is one word in noise.
  const words = lettered.filter((p) => (p.length >= 3 && isWord(p)) || CODE_ABBREVIATION.test(p) || /^(?:In|On|Is|At|Of|To|By|Id|As|Or|If|Up|No|Do|My|Be|It|An)$/.test(p)).reduce((n, p) => n + p.length, 0);
  return words / total >= 0.6 && words / t.replace(/_\d+$/, "").length >= 0.5;
}

/**
 * Letters in both cases that do not make words: "PVJjvBMcjGna",
 * "IahmzBuRKuSp", "VMFdJIXCR6en" — a fifth of the passwords ai4privacy's
 * practice set still let through had no digit and no symbol to give them
 * away, or runs too long for randomToken's count of single letters.
 *
 * Code is made of words: "getBinderPackageName", "XMLHttpRequest",
 * "AudioManager". So a part is a word when it has a vowel (an acronym of three
 * capitals before a word counts too), and a token is jumbled when its words
 * cover at most half its letters and its case changes three times or more.
 */
export function jumbled(t: string, minLength = 10): boolean {
  if (t.length < minLength || t.length > 40) return false;
  const letters = t.replace(/[^A-Za-z]/g, "");
  if ((letters.match(/[A-Z]/g) ?? []).length < 3 || (letters.match(/[a-z]/g) ?? []).length < 3) return false;
  let changes = 0;
  for (let i = 1; i < letters.length; i += 1) if (/[A-Z]/.test(letters[i]) !== /[A-Z]/.test(letters[i - 1])) changes += 1;
  if (changes < 3) return false;
  // Letters paired with their capitals are a list of format codes,
  // "bBhHiIlLqQ" in Python's struct documentation.
  if (/^(?:([a-z])(?!\1)[A-Z])+$/.test(t) && [...t.matchAll(/([a-z])([A-Z])/g)].every((m) => m[1].toUpperCase() === m[2])) return false;
  // A word in mocking case keeps a word's vowels: "UNiveRSAl HeaLtHCArE"
  // (oasst2). Random letters have about one in four.
  if ((letters.match(/[aeiouy]/gi) ?? []).length / letters.length >= 0.4) return false;
  const wordy = (t.match(/[A-Z]{3,}(?=[A-Z][a-z])|[A-Z]?[a-z]{2,}/g) ?? [])
    .filter((w) => /^[A-Z]{3,}$/.test(w) || (w.length >= 3 && /[aeiouy]/i.test(w) && !/[^aeiouy]{5,}/i.test(w)))
    .reduce((n, w) => n + w.length, 0);
  return wordy / letters.length <= 0.5;
}

/** Words that take a number or a member and are things, not people: products,
 *  places in a game, units of a document, parts of a program. */
const NOT_A_HANDLE = /^(?:Blake|Roman|Council|Dow|Cal|Windows|Win|Python|Office|Covid|Gate|Level|Player|Agent|Area|Route|Apollo|Boeing|Airbus|Galaxy|Pixel|Xbox|Series|Model|Version|Phase|Stage|Day|Week|Year|Chapter|Part|Room|Floor|Team|Group|Unit|Test|Case|Sample|Item|Product|Server|Node|Host|User|Admin|Client|Element|Field|Column|Row|Table|Sheet|Page|Step|Task|Image|File|Folder|Track|Episode|Season|Book|Volume|Section|Figure|Slide|Lesson|Module|Class|Grade|Form|Option|Answer|Question|Example|Exercise|Problem|Note|Box|Button|Label|Text|Input|Output|Value|Var|Func|Function|Method|Object|Array|List|Map|Set|Type|Struct|Enum|Iphone|Ipad|Android|Ios|Mac|Linux|Ubuntu|Debian|Fedora|Java|Php|Ruby|Rust|Swift|Kotlin|Scala|Perl|Lua|Mysql|Postgres|Redis|Mongo|Node|React|Angular|Vue|Django|Flask|Rails|Spring|Laravel|Unity|Unreal|Godot|Blender|Maya|Excel|Word|Outlook|Teams|Zoom|Slack|Discord|Steam|Nintendo|Playstation|Ps|Halo|Fallout|Doom|Quake|Diablo|Warcraft|Starcraft|Overwatch|Fifa|Madden|Tekken|Mortal|Final|Resident|Battlefield|Witcher|Mass|Dark|Elden|Minecraft|Roblox|Fortnite|Pokemon|Zelda|Mario|Sonic|Metroid|Gpt|Llama|Claude|Gemini|Mistral|Falcon|Bert|Resnet|Vgg|Yolo|Efficientnet|Mobilenet|Densenet|Inception|Xception|Lstm|Gru|Conv|Dense|Layer|Epoch|Batch|Iteration|Sensor|Pin|Port|Channel|Motor|Servo|Relay|Led|Timer|Counter|Register|Address|Bank|Block|Sector|Cluster|Pool|Zone|Region|Vpc|Subnet|Sprint|Release|Build|Patch|Update|Fix|Bug|Issue|Ticket|Story|Epic|Feature|Branch|Commit|Tag|Label|Draft|Plan|Tier|Rank|Mode|Map|Arena|World|Universe|Planet|Star|Galaxy|Sector|District|Ward|Block|Lot|Plot|Field|Pitch|Court|Lane|Line|Bus|Train|Flight|Car|Truck|Van|Bike|Ship|Boat|Jet|Tank|Gun|Rifle|Pistol|Sword|Shield|Armor|Helmet|Potion|Spell|Skill|Perk|Badge|Medal|Award|Prize|Trophy|Cup|League|Division|Squad|Unit|Wave|Round|Match|Game|Set|Leg|Lap|Heat|Final|Semi|Quarter)$/i;

/**
 * Whether a run of capitals and digits reads as somebody's identifier rather
 * than a thing's code. After a possessive ("your AT8126685") a letter and a
 * digit are enough, or eight digits that are not a date; alone it must
 * alternate — letters and digits taking turns three times or more, at least
 * three letters and two digits ("C2TZXGY7LR"). Never hex alone (a hash or an
 * address), a year range, or a product's model ("RTX3080", "GTX1660").
 */
function idLike(value: string, owned: boolean): boolean {
  const letters = (value.match(/[A-Z]/g) ?? []).length;
  const digits = (value.match(/\d/g) ?? []).length;
  if (/^\d+$/.test(value)) return owned && !/^(?:19|20)\d{6}$/.test(value) && !/^(\d)\1+$/.test(value);
  if (/^[0-9A-F]+$/.test(value) && !owned) return false;
  // A chemical formula, and hex with its prefix: "CH3CH2OH", "C19H34O2",
  // "NH4H4PO4", "0X80076ED" (WildChat, Loghub).
  if ((/^(?:[CHONPSKFIB]\d*)+$/.test(value) && (value.match(/[A-Z]/g) ?? []).length >= 2) || /^0X/.test(value)) return false;
  if (/^(?:RTX|GTX|RX|SM|GT|MX|ISO|IEEE|RFC|ASCII|UTF|MP|USB|HDMI|DDR|LPDDR|PCIE|SATA|NVME|CPU|GPU|COVID|SARS|H\d)\d/.test(value)) return false;
  const changes = (value.match(/[A-Z](?=\d)|\d(?=[A-Z])/g) ?? []).length;
  if (owned) return letters >= 1 && digits >= 2 && value.length >= 7;
  return letters >= 3 && digits >= 2 && changes >= 3;
}

/** An IBAN, or a bank code's own name, within reach of a BIC with no digit. */
const NEAR_A_BANK_CODE = /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b|\b(?:swift|bic|bank\s+(?:code|details|identification)|banking\s+details|bankleitzahl|code\s+banque|codice\s+banca)\b/i;

/** Streets, squares and lines known everywhere by name (real prompts, Enron). */
const FAMOUS_STREETS = /^(?:Wall Street|Times Square|Tiananmen Square|Red Square|Trafalgar Square|Fertile Crescent|Arctic Circle|Antarctic Circle|Park Avenue|Fifth Avenue|Madison Avenue|Pennsylvania Avenue|Main Street|Abbey Road|Downing Street|Baker Street|Oxford Street|Bond Street|Fleet Street|Harley Street|Carnaby Street|Penny Lane|Sunset Boulevard|Hollywood Boulevard|Bourbon Street|Beale Street|Lombard Street|Rodeo Drive|Mulholland Drive|Sesame Street|Coronation Street|Privet Drive|Elm Street|Wisteria Lane|Electric Avenue|Easy Street|Silk Road|Indian Wells|Copley Square|Pioneer Square|Union Square|Washington Square|Harvard Square|Davis Square)$/;

/** Words that open a sentence, which a missing space glues to the word before. */
const SENTENCE_OPENERS = new Set([
  "Since", "After", "Before", "Following", "Multiple", "Early", "Late", "Hash", "Because", "Even", "According", "When", "While",
  "However", "The", "This", "That", "These", "Those", "Then", "There", "Also", "But", "And", "For", "Here", "Now", "Some", "Many",
  "Most", "Each", "Every", "Both", "Such", "Other", "Another", "First", "Second", "Third", "Last", "Next", "New", "Old", "Today",
  "Yesterday", "Tomorrow", "What", "Why", "How", "Who", "Where", "Which", "Its", "His", "Her", "Their", "Our", "Your", "My", "We",
  "They", "She", "He", "It", "In", "On", "At", "By", "With", "From", "As", "If", "So", "Yet", "Still", "Thus", "Hence", "Instead",
  "Meanwhile", "Later", "Finally", "Overall", "Currently", "Located", "Born", "Known", "During", "Under", "Over", "Between", "Among",
]);

/** A user name made of a name, not of ordinary words. See NAME_HANDLE_PATTERN. */
export function nameHandle(t: string): boolean {
  return t.split(/[_.]/).map((p) => p.replace(/\d+$/, "")).every((p) =>
    !COMMON_CAPITALISED.has(p) && !isCommonLowercaseWord(p.toLowerCase()) && !HANDLE_NOT_A_NAME.has(p.toLowerCase()));
}

/** Words that joined by an underscore are a property or a setting, not a
 *  person: Unicode's General_Category, Hex_Digit, Extended_Pictographic in
 *  Python's re and unicodedata documentation, a locale's English_United, and
 *  Enron's Energy_Use — the first ones the handle rule took that were not
 *  user names. */
const HANDLE_NOT_A_NAME = new Set([
  "case", "general", "category", "hex", "digit", "join", "control", "pattern", "syntax", "regional",
  "indicator", "extended", "pictographic", "ignorable", "english", "united", "energy", "use", "default",
  "value", "type", "name", "data", "user", "admin", "test", "config", "level", "mode", "max", "min",
]);

/** Ethereum addresses that are public by construction: the contracts every
 *  tutorial calls and the default accounts of the local test chains, whose
 *  keys are printed in their documentation. Lower case. */
const PUBLIC_ETHEREUM = new Set([
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
  "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", // UNI
  "0x1f98431c8ad98523631ae4a59f267346ea31f984", // Uniswap v3 factory
  "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap v3 swap router
  "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6", // Uniswap v3 quoter
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap v2 router
  "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
  "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
  "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", // Hardhat and Anvil account 0
  "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", // Hardhat and Anvil account 1
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", // Hardhat and Anvil account 2
  "0x627306090abab3a6e1400e9345bc60c78a8bef57", // Truffle and Ganache account 0
  "0xf17f52151ebef6c7334fad080c5704d77216b732", // Truffle and Ganache account 1
]);

function fakeIban(source: string, hex: string, salt: number): string {
  const compact = source.replace(/\s+/g, "").toUpperCase();
  // A domestic account number has no country code — see ACCOUNT_CUED_PATTERN,
  // which reports one under this kind. Taking its first two digits as a
  // country and running the IBAN check over the rest produces a stand-in of
  // the right length and the wrong species. Same length, same alphabet.
  if (/^\d+$/.test(compact)) {
    let out = "";
    for (let i = 0; i < compact.length; i += 1) {
      out += String((parseInt(hex.charAt(i % hex.length), 16) + salt + i) % 10);
    }
    return out;
  }
  // A BIC — see BIC_CUED_PATTERN — is six letters and two or five letters or
  // digits, and has no check digits. Run through the IBAN branch it came back
  // as "UH07 1234 567", an IBAN-looking stand-in for a bank code. Same length,
  // letters where the bank and country are, the rest as the original had it.
  if (/^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/.test(compact)) {
    let out = "";
    for (let i = 0; i < compact.length; i += 1) {
      const n = parseInt(hex.charAt(i % hex.length), 16) + salt + i;
      out += /\d/.test(compact[i]) ? String(n % 10) : String.fromCharCode(65 + (n % 26));
    }
    return out;
  }
  const country = compact.slice(0, 2);
  let body = "";
  for (let i = 0; i < compact.length - 4; i++) {
    body += String((parseInt(hex.charAt(i % hex.length), 16) + salt + i) % 10);
  }
  for (let check = 2; check < 99; check++) {
    const candidate = `${country}${String(check).padStart(2, "0")}${body}`;
    if (iban97(candidate)) {
      return candidate.replace(/(.{4})(?=.)/g, "$1 ");
    }
  }
  return `${country}00${body}`;
}

/**
 * The check digit every real card number carries. A 16-digit order reference
 * passes the length test and fails this one, which is the difference between
 * redacting cards and redacting any long number a user happens to paste.
 */
function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let value = digits.charCodeAt(i) - 48;
    if (value < 0 || value > 9) return false;
    if (double) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Builds a card number that is realistic all the way down, check digit
 *  included — a model asked about a card it can tell is malformed will say so
 *  instead of answering the question. */
function fakeCard(hex: string, salt: number): string {
  let body = "4";
  for (let i = 0; i < 14; i++) {
    body += String((parseInt(hex.charAt(i % hex.length), 16) + salt + i) % 10);
  }
  for (let check = 0; check < 10; check++) {
    if (luhn(body + check)) return `${body}${check}`.replace(/(\d{4})(?=\d)/g, "$1 ");
  }
  return `${body}0`;
}

const MONTHS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

/**
 * A date of birth, as another date of birth.
 *
 * Returns undefined for anything that is not written like a date, so the
 * caller falls through to the character swap that serves the rest of the
 * kind. Only the values DOB_CUED_PATTERN can match are handled, which is why
 * the three forms below are the whole list.
 *
 * What is preserved is how it was written -- the separator, the zero padding,
 * whether the month was a word and whether that word was shortened, the
 * comma, a two-digit year. What changes is the day, the month and the year,
 * so nothing of the real date survives. The day stops at 28 because February
 * exists, and the year lands between 1940 and 2005 so the person the model is
 * told about is an adult and not a Tudor.
 */
function fakeDate(value: string, hex: string, salt: number): string | undefined {
  const n = (at: number, mod: number) => (parseInt(hex.slice(at, at + 2), 16) + salt) % mod;
  const day = n(0, 28) + 1;
  const month = n(2, 12);
  /* Not the year it replaces, however the draw lands. The day and the month
     may coincide and tell a reader nothing, but the year is the age, and a
     stand-in that keeps it has hidden the date and disclosed the thing the
     date was being asked about. Checked against both spellings, because a
     two-digit year is the same fact written shorter. */
  const real = /\d{4}/.exec(value)?.[0] ?? /(?<!\d)\d{2}(?!\d)\s*$/.exec(value)?.[0];
  let year = 1940 + n(4, 66);
  while (String(year) === real || String(year % 100).padStart(2, "0") === real) year = 1940 + ((year - 1940 + 7) % 66);
  const pad = (v: number, like: string) => String(v).padStart(like.length === 2 ? 2 : 1, "0");
  const named = (like: string) => {
    const full = MONTHS[month];
    const word = like.length <= 3 ? full.slice(0, 3) : full;
    return like === like.toUpperCase() ? word.toUpperCase()
      : like === like.toLowerCase() ? word.toLowerCase()
      : word;
  };

  // 14/03/1988, 1988-03-14, 14.3.88 -- separators and padding kept, and the
  // year stays in the position it was written in.
  const numeric = /^(\d{1,4})([/.-])(\d{1,2})\2(\d{1,4})$/.exec(value);
  if (numeric) {
    const [, a, sep, b, c] = numeric;
    const yearFirst = a.length === 4;
    const shown = (full: number, like: string) =>
      like.length === 2 ? String(full % 100).padStart(2, "0") : String(full);
    /* Written in digits, 03/04 is the third of April here and the fourth of
       March in America, and nothing in the string says which. So the day is
       kept to twelve as well: whichever way the model reads the stand-in, it
       reads a real date. */
    const safeDay = (day % 12) + 1;
    return yearFirst
      ? [shown(year, a), pad(month + 1, b), pad(safeDay, c)].join(sep)
      : [pad(safeDay, a), pad(month + 1, b), shown(year, c)].join(sep);
  }

  // 14 March 1988, 14 Mar 1988.
  const dayFirst = /^(\d{1,2})(\s+)([A-Za-z]+)(\s+)(\d{4})$/.exec(value);
  if (dayFirst) {
    const [, d, s1, word, s2] = dayFirst;
    return `${pad(day, d)}${s1}${named(word)}${s2}${year}`;
  }

  // March 14, 1988 -- with or without the comma.
  const monthFirst = /^([A-Za-z]+)(\s+)(\d{1,2})(,?)(\s+)(\d{4})$/.exec(value);
  if (monthFirst) {
    const [, word, s1, d, comma, s2] = monthFirst;
    return `${named(word)}${s1}${pad(day, d)}${comma}${s2}${year}`;
  }

  // The rest DOB_CUED_PATTERN takes: without a year ("March 14"), a month
  // and a year ("March 1985"), shortened with a full stop ("14 Mar. 1985"),
  // dashed ("14-Mar-1985"), or in another language ("14. März 1985", "14 de
  // marzo de 1985"). The month word becomes another month, the year another
  // year and the day another day, and everything between is left as written.
  if (/^[\p{L}\d .,-]+$/u.test(value) && /\p{L}{3}/u.test(value)) {
    let out = value.replace(/\p{L}{3,}/u, (word) => named(word));
    out = out.replace(/(?<!\d)\d{4}(?!\d)/, String(year));
    out = out.replace(/(?<!\d)\d{1,2}(?!\d)/, (d) => pad(day, d));
    return out;
  }

  return undefined;
}

export type StructuredKind = "secret" | "email" | "card" | "iban" | "ssn" | "govid" | "phone" | "address" | "postcode" | "host";

/**
 * Everything with a recognisable shape in `text`, longest first.
 *
 * Order is not cosmetic. A card and a phone number are both runs of digits,
 * and a 16-digit card contains things that look like phone numbers; matching
 * cards first and then skipping any span already claimed is what stops one
 * value being carved into three.
 */
/* Exported for the eval harness in redaction.eval.test.ts, which measures
   recall and precision per kind against a labelled corpus. Nothing else
   imports it — the request path calls it directly below. */
export { normaliseDigits, foldForScan } from "./redactionFold.js";

/**
 * Whether the text after "password:" is a credential or a sentence.
 *
 * Eight characters or more is taken as a credential whatever it is made of —
 * the same floor actionScan uses. Shorter than that it needs a digit or a
 * symbol in it: "hunter2" is a password, "please" (as in "password: please
 * ask Dave") is not. Placeholders that say there is nothing there are left
 * alone.
 */
function plausibleAssignedSecret(value: string): boolean {
  if (!plausibleSecretValue(value)) return false;
  if (value.length >= 8) return true;
  return /[^A-Za-z]/.test(value);
}

/**
 * What no credential looks like, whatever label is in front of it.
 *
 * A mask, a placeholder, a template variable, or code that reads the secret
 * from somewhere else: `os.environ['DB_PASSWORD']`, `${API_KEY}`,
 * `{{ .Values.secret }}`, `YOUR_API_KEY`. Redacting those protects nobody and
 * swaps the one word that says where the real value lives for a random one.
 */
function plausibleSecretValue(value: string): boolean {
  if (/^(?:\*+|x+|\.+|<[^>]*>?|n\/?a|none|null|nil|undefined|redacted|required|optional|changeme|empty|true|false|secret|password)$/i.test(value)) return false;
  // The next key, not a value: "pwd\n   :synopsis:", "metadata:\n  name:".
  // And a reStructuredText substitution, "|param_doc_passwd|", which is the
  // name of a paragraph of documentation.
  if (/^[A-Za-z_][\w.-]*:$/.test(value) || /^\|[\w.-]+\|$/.test(value)) return false;
  // Code that reads the secret from somewhere else, judged on the whole
  // value rather than on any bracket in it: a password may contain braces,
  // and detect-secrets' own test password is "m{{h}o)p${e]nob(ody[finds…".
  if (/^[\w.$]+[(\[]|\$\{[A-Za-z_]\w*(?:\}|$)|^\{\{|^\$|^%|^@|^[(\[{&]|^(?:os|process|env|config|settings|self|this|ENV)\.|^getenv|^secrets?\./.test(value)) return false;
  // An identifier in capitals: an environment variable's name, not its value.
  if (/^[A-Z][A-Z0-9]*_[A-Z0-9_]+$/.test(value)) return false;
  // A domain or a path with no digit in it: \`topologyKey: "kubernetes.io/hostname"\`.
  if (!/\d/.test(value) && /^[\w-]+(?:\.[\w-]+)+(?:\/[\w.-]*)*$/.test(value)) return false;
  if (value.startsWith("~")) return false;
  // A form field read in code, or the code that pastes it into a query:
  // "password = textBox2.Text", "password= '" + textBox2.Text + "'" (WildChat).
  if (/^[A-Za-z_]\w*\.(?:Text|Value|Password|Content|value|text)$/.test(value) || /^["']\s*\+|\+\s*["']$/.test(value)) return false;
  // A command-line flag, a path, or a name that says it is a password rather
  // than being one: "--discovery-token-ca-cert-hash", "path/to/id_rsa",
  // "--password=kubepassword", "[--password=basic_password]".
  if (/^--?[a-z]/.test(value)) return false;
  if (!/\d/.test(value) && /^[\w.~-]+(?:\/[\w.~-]+)+\/?$/.test(value)) return false;
  if (!/\d/.test(value) && /(?:pass(?:word)?|secret|token|key)$/i.test(value)) return false;
  if (/[\])]$/.test(value) && !/[\[(]/.test(value)) return false;
  // Code, which is most of what a developer pastes. Running the scanner over
  // this repository's own 900 source files took every one of these:
  //   privateKey: CryptoKey            a type
  //   password: Promise<string>        a generic type
  //   secret: hook.secret              a property read
  //   SEEN_KEY = "secureai.seenChatIntro"   a storage key's name
  //   "invalid_api_key": "not_signed_in"    an error code
  //   APP_SECRET: "test-secret"        a test placeholder
  //   call(idToken, "/v1/policy")      a path
  if (/^[A-Za-z_$][\w$.]*<|^</.test(value) || value.startsWith("/")) return false;
  // A type annotation or a literal: \`secret: string)\`, \`passcode === null\`.
  if (/^(?:string|number|boolean|any|unknown|void|object|never|bigint|symbol|null|undefined|true|false|nil|none)\b(?![\w-])/i.test(value)) return false;
  // Shortened in documentation: "sai_...", "abc…".
  if (/(?:\.\.\.|…)$/.test(value)) return false;
  // Capitals and lower case with no digit can still be generated: a word
  // has its lower-case letters in runs, and "SSVmFDNCFfOHKXQAEckx" has two
  // lone ones between capitals, which no identifier does.
  const random = value.length >= 16 && (value.match(/(?<=[A-Z])[a-z](?=[A-Z])/g) ?? []).length >= 2;
  if (!/\d/.test(value) && !random) {
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return false;
    if (/^[A-Z]+[a-z]+(?:[A-Z]+[a-z]*)*$/.test(value)) return false;
    if (/^[a-z]+(?:[A-Z][a-z]*)+$/.test(value)) return false;
    if (/^[a-z]+(?:_[a-z]+)+$/.test(value)) return false;
  }
  if (/^(?:U?[Ii]nt(?:8|16|32)|Float(?:32|64)|BigU?[Ii]nt64)(?:Clamped)?Array$/.test(value)) return false;
  if (value.startsWith("-----")) return false;
  // "test-secret", "your_api_key": a word after the prefix, not a key. Lob's
  // real keys open with test_ and live_ and carry hex after it.
  if (/^(?:test|dummy|fake|example|sample|placeholder|your|my)[-_][a-z_-]*$/i.test(value)) return false;
  if (/fake|dummy|placeholder|changeme|redacted/i.test(value)) return false;
  // A quoted value may contain spaces — a passphrase — but a sentence is a
  // form's validation message: { password: "Password is required" }.
  if (/\s/.test(value) && /\b(?:is|are|must|should|required|enter|your|please|invalid|characters?|match|incorrect|too|least|the)\b/i.test(value)) return false;
  if (!/[A-Za-z0-9]/.test(value)) return false;
  return true;
}

/** How often a value switches between lower case, upper case and digits
 *  from one character to the next. A generated key does it on most
 *  characters; a slug made of words ("update-2024-final") hardly at all. */
function classChanges(value: string): number {
  const cls = (c: string) => (/[a-z]/.test(c) ? 1 : /[A-Z]/.test(c) ? 2 : /\d/.test(c) ? 3 : 0);
  let changes = 0;
  for (let i = 1; i < value.length; i++) {
    const a = cls(value[i - 1]), b = cls(value[i]);
    if (a && b && a !== b) changes++;
  }
  return changes;
}

/** A value after a name like `adobeToken`: generated-looking, which a word or
 *  an identifier is not. Twenty characters of anything, or eight with both a
 *  letter and a digit in them. */
function plausibleNamedSecret(value: string): boolean {
  if (!plausibleSecretValue(value)) return false;
  if (/^https?:\/\//.test(value)) return false;
  if (/^[a-z]+(?:[A-Z][a-z]+)*$/.test(value) || /^[a-z]+(?:[_-][a-z]+)+$/.test(value)) return false;
  // A slug with a version on it is a storage key's name: "sai-dashboard-cards-v2".
  if (/^[a-z]+(?:[-_][a-z]+)+[-_.]v?\d{1,3}$/.test(value)) return false;
  // What Android and macOS print for a token object (Loghub): "Token{a64f992",
  // "android.os.BinderProxy@2bd79ce", "com.apple.xpc.activity/4505:", and a
  // notification key "0|com.tencent.mobileqq|121|null|10111".
  if (/^[A-Z]\w*\{|^[a-z]+(?:\.[a-z]\w*){2,}|\|/.test(value)) return false;
  return value.length >= 20 || (/\d/.test(value) && /[A-Za-z]/.test(value));
}

/** "The password is MyP@ssw0rd!" — must carry a digit or a symbol, which
 *  "the password is required" and "the password is incorrect" do not. */
function plausiblePasswordIs(value: string): boolean {
  // Judged without the quotes around it: "(chosen password is `foo`)" is a
  // word in backticks, and the backticks were the whole of its "symbol".
  const inner = value.replace(/^([`'"])(.+)\1$/s, "$2");
  // Or letters alone, jumbled: "password: PVJjvBMcjGna".
  return plausibleSecretValue(value) && (/[^A-Za-z]/.test(inner) || jumbled(inner, 8)) && /[A-Za-z0-9]/.test(inner)
    // A word and the end of its sentence, or a sentence's punctuation and
    // what follows it: "choosing a password manager?", and the code line
    // "wrong or missing password?\n{e}" (real prompts, oasst2).
    // A made one in mixed case keeps its question mark: "and password
    // ezSPwDtcKaVR?" is the end of a question about it.
    && !/^\p{Ll}+[?!.,:;]$/u.test(inner) && !/^[?!.,;:]/.test(inner);
}

/**
 * What a phone number never looks like, found by running the scanner over
 * Python's and Kubernetes' documentation: a run of zeros
 * ("0000000000000000"), the counting digits ("0123456789"), the inside of a
 * hex literal or a Unicode escape ("0x000000000041b717", "\\U00008000"), and
 * the digits after a decimal point ("2.7182818285").
 */
/** "06 12 34 56 78 06 98 76 54 32": a French number in a run of digit pairs
 *  whose length is a whole number of phones, each one opening with 0. */
function frenchPhonesSideBySide(value: string, before?: string, after?: string): boolean {
  if (!/^0\d(?: \d\d){4}$/.test(value)) return false;
  const pairsBefore = before?.match(/(?:(?<!\d)\d\d[ \t]+)+$/)?.[0].match(/\d\d/g) ?? [];
  const pairsAfter = after?.match(/^(?:[ \t]+\d\d(?![\p{L}\d]))+/u)?.[0].match(/\d\d/g) ?? [];
  if ((pairsBefore.length + pairsAfter.length) % 5 !== 0) return false;
  const run = [...pairsBefore, ...value.split(" "), ...pairsAfter];
  return run.every((pair, i) => i % 5 !== 0 || pair.startsWith("0"));
}

function plausiblePhone(value: string, before?: string, after?: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (/^(\d)\1+$/.test(digits)) return false;
  // Only of a bare run: "+82 10-2000-0000" and "+60 12-345 6789" are real
  // numbers written the way their countries write them.
  if (/^\d+$/.test(value) && (/0{6,}/.test(digits) || digits.includes("0123456789") || digits.includes("1234567890"))) return false;
  if (before && /(?:0x[0-9A-Fa-f]*|\\[uUxX][0-9A-Fa-f]*|\d\.)$/.test(before)) return false;
  if (after && /^(?:[A-Fa-f]\w|\.\d)/.test(after)) return false;
  // A hexdump's offset column and the word after it: "0000000 203b 6f4d"
  // (a real prompt, oasst2). A hex letter glued to the last digit means the
  // run did not end there.
  if (after && /^[A-Fa-f](?![\p{L}\p{N}])/u.test(after)) return false;
  if (before && /\b(?:https?:\/\/|www\.)\S*$/.test(before)) return false;
  // Five pairs of digits is how France writes a phone number, "01 23 45 67
  // 89", and how a lottery draw is listed: "STARS 05 10 01 15 19 24 33
  // STARS 07 08". In real prompts (WildChat, 2026-10-23) 80 of 400 phones
  // taken were draws asked about. A run of pairs that goes on past the five,
  // or is followed by the stars of a EuroMillions line, is a table of
  // numbers. Two phones written side by side are a run too, of ten pairs:
  // so the run's length decides, and a whole number of phones stays phones.
  // A pair with a letter after it is not one ("24h/24").
  if (/^\d\d(?: \d\d){4}$/.test(value)) {
    const pairsBefore = (before?.match(/(?:(?<!\d)\d\d[ \t]+)+$/)?.[0].match(/\d\d/g) ?? []).length;
    const pairsAfter = (after?.match(/^(?:[ \t]+\d\d(?![\d\p{L}]))+/u)?.[0].match(/\d\d/g) ?? []).length;
    if ((5 + pairsBefore + pairsAfter) % 5 !== 0) return false;
    if (after && /^[ \t]+(?:stars?|[ée]toiles?|estrellas?|stelle|sterne|lucky\s+stars?)\b/i.test(after)) return false;
  }
  // Ten bare digits opening with 1 are a Unix timestamp ("exp": 1703232949),
  // not a phone: no North American area code opens with 1, and elsewhere a
  // national number opens with its trunk digit. 2147483647 and 4294967296 are
  // only ever integer limits.
  if (/^\d{10}$/.test(value) && (value.startsWith("1") || ["2147483647", "2147483648", "4294967295", "4294967296"].includes(value))) return false;
  // Found in the Python and Kubernetes documentation, none of them a phone:
  // "+063415" and "+010000" are UTC offsets, "+000000120" a padded field and
  // "+3.140000" a formatted float. No country code opens with 0, and no
  // international number is shorter than seven digits.
  if (value.startsWith("+") && (/^\+0/.test(value) || digits.length < 7 || /^\+\d{1,2}\.\d/.test(value))) return false;
  // The tail of a hash: "1b9242684415". Only a hex run with a digit and a
  // letter in it; a lone letter is "H(011)3909872" (home) or the front of a
  // German health insurance number, and "is415-555-0132" is a missing space.
  const glued = before?.match(/[0-9A-Za-z]+$/)?.[0];
  if (glued && /^[0-9a-f]+$/i.test(glued) && /\d/.test(glued) && /[a-f]/i.test(glued)) return false;
  // A date: "0001-01-01".
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  // One number in a run of them: "233 377 610 987 1597" is Fibonacci and
  // "000 001 010 011 100" is a product of ranges.
  //
  // A number with a letter on it is a unit, not one of the run: "01 23 45 67
  // 89 24h/24", "… 7j/7" are a French phone and its opening hours. And two
  // French phones side by side, "06 12 34 56 78 06 98 76 54 32", are a run
  // of pairs whose length is a whole number of phones.
  if (/^[\d ]+$/.test(value)) {
    // A unit is a short tag on the digits, "24h", "7j": "113d3a99c3…" in a
    // log is a hex id and still one of the run.
    const numberBefore = !!before && /(?<![\p{L}\d])\d+[ \t]$/u.test(before);
    const numberAfter = !!after && /^[ \t]\d/.test(after) && !/^[ \t]\d+\p{L}{1,3}(?![\p{L}\d])/u.test(after);
    if ((numberBefore || numberAfter) && !frenchPhonesSideBySide(value, before, after)) return false;
  }
  // An argument in code: "ip_address(3221225985)", "seed=3652260728".
  if (/^\d+$/.test(value) && ((before && /[(=]\s*$/.test(before)) || (after && /^\s*[)>]/.test(after)))) return false;
  // From real logs (Loghub): a counter a machine names — "Seq 2119064372,
  // Ack 3325040593", "taskID[2019353677]" — and an id glued on with an
  // underscore, "CBS Session: 30546354_3176343857". And "00" is the
  // international prefix only with a whole number behind it: "iar 00106228
  // dear 0244c1ec" is a register.
  // "cup2key=7:2988503627" is a value after its own version. An id label is
  // not on the list: "BANK ID: 012345678" is somebody's, and still hidden.
  if (/^\d+$/.test(value) && before && (/(?<![\p{L}\p{N}])\d+_$|=\d+:$/u.test(before) || /(?:\b(?:seq|ack|win|pid|tid|size|len|offset|count|thread|timeout|elapsed|bytes)\s*[:=#]?|[a-z]ID\[)\s*$/i.test(before))) return false;
  // A decimal and an IPv4 address are not phones: "loss = 277167.4375",
  // "148.196.50.56" in a table of connections (WildChat).
  if (/^\d{1,7}\.\d{1,4}$/.test(value) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return false;
  // Both only beside a hex word: "00004637" alone is an account number.
  if (/^00/.test(digits) && (digits.length < 10 || /^0{4}/.test(digits)) && /(?<![\p{L}\p{N}])(?=[0-9a-f]{4}(?:[0-9a-f]{4})?(?![\p{L}\p{N}]))\d*[a-f]/u.test(`${before ?? ""} ${after ?? ""}`)) return false;
  return true;
}

/** A number the words in front say is an order, an invoice or a ticket —
 *  "Order 123-456-7890 has shipped" is the shape of a phone number and is not one. */
function notAReference(_value: string, before?: string): boolean {
  return !/\b(?:order|invoice|inv|ref(?:erence)?|ticket|case|tracking|confirmation|booking|shipment|po|sku|part|serial|model)\s*(?:no\.?|number|num|#|id)?\s*[:#]?\s*$/i.test(before ?? "");
}

/**
 * "2 Supreme Court Reports", "the 1928 Labour Court Act", "the Federal Court 18"
 * — a number, a name and the word Court, which is every numbered branch of
 * ADDRESS_PATTERN. The name in front says it is a court, and none of these
 * is a street anybody lives on.
 */
function notACourt(value: string): boolean {
  return !/\b(?:Supreme|Federal|Labour|Labor|Constitutional|Regional|District|County|Crown|High|Appeals?|Magistrates[’']?|Assize|Administrative|Criminal|Civil|Family|Military|Security|Commercial|Circuit|Superior|Tax|Employment|Juvenile|Probate|Municipal|Cassation|Arbitration|International|European)\s+Court(?:\s+\d+)?\.?$/.test(value);
}

/* ── National identity numbers: the checks ────────────────────────────────
   Each is the published algorithm for its number, checked against the valid
   and invalid values in Microsoft Presidio's recognizer tests. See the note
   above ES_ID_PATTERN for why these may stand without a cue when no other
   bare number may. */

const onlyDigits = (v: string) => v.replace(/\D/g, "");

function validDate(yy: number, mm: number, dd: number, century = 2000): boolean {
  if (mm < 1 || mm > 12 || dd < 1) return false;
  return dd <= new Date(Date.UTC(century + yy, mm, 0)).getUTCDate();
}

/** Spanish DNI/NIF and NIE: the letter is the number mod 23. */
function spanishId(value: string): boolean {
  const m = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(value.toUpperCase().replace(/[ -]/g, ""));
  // "U-0000007F" is a Unicode code point that happens to pass: no DNI opens with four zeros.
  if (!m || /^0000/.test(m[2])) return false;
  const n = Number(`${m[1] ? "XYZ".indexOf(m[1]) : ""}${m[2]}`);
  return "TRWAGMYFPDXBNJZSQVHLCKE"[n % 23] === m[3];
}

/** Brazil's CPF: two mod-11 check digits over the nine before them. */
function brazilCpf(value: string): boolean {
  const d = onlyDigits(value);
  if (/^(\d)\1{10}$/.test(d)) return false;
  const check = (n: number) => ((([...d.slice(0, n)].reduce((t, c, i) => t + Number(c) * (n + 1 - i), 0) * 10) % 11) % 10);
  return check(9) === Number(d[9]) && check(10) === Number(d[10]);
}

/** Brazil's CNPJ: two mod-11 check digits with the Receita's weights. */
function brazilCnpj(value: string): boolean {
  const d = onlyDigits(value);
  if (/^(\d)\1{13}$/.test(d)) return false;
  const check = (n: number) => {
    const r = [...d.slice(0, n)].reduce((t, c, i) => t + Number(c) * [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2][13 - n + i], 0) % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return check(12) === Number(d[12]) && check(13) === Number(d[13]);
}

/** Chile's RUT: weights 2 to 7 from the right, mod 11, where 10 is K. */
function chileRut(value: string): boolean {
  const body = onlyDigits(value.slice(0, -1));
  const sum = [...body].reverse().reduce((t, c, i) => t + Number(c) * (2 + (i % 6)), 0);
  const r = 11 - (sum % 11);
  return (r === 11 ? "0" : r === 10 ? "K" : String(r)) === value.slice(-1).toUpperCase();
}

/** Mexico's CURP: a real birth date, and a weighted check digit over the first seventeen. */
function mexicoCurp(value: string): boolean {
  const century = /\d/.test(value[16]) ? 1900 : 2000;
  if (!validDate(Number(value.slice(4, 6)), Number(value.slice(6, 8)), Number(value.slice(8, 10)), century)) return false;
  const chars = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
  const sum = [...value.slice(0, 17)].reduce((t, c, i) => t + chars.indexOf(c) * (18 - i), 0);
  return (10 - (sum % 10)) % 10 === Number(value[17]);
}

/** Singapore's NRIC and FIN: weighted digits, an offset for T and G, and a letter table per series. */
function singaporeNric(value: string): boolean {
  const sum = [2, 7, 6, 5, 4, 3, 2].reduce((t, w, i) => t + w * Number(value[i + 1]), 0) + (/[TG]/.test(value[0]) ? 4 : 0);
  const table = /[ST]/.test(value[0]) ? "JZIHGFEDCBA" : "XWUTRQPNMLK";
  return table[sum % 11] === value[8];
}

/** Hong Kong's HKID: letters and digits weighted 9 down to 2, mod 11, where 10 is A. */
function hongKongId(value: string): boolean {
  const m = /^([A-Z]{1,2})(\d{6})\((.)\)$/.exec(value);
  if (!m) return false;
  const letters = m[1].length === 1 ? [36, m[1].charCodeAt(0) - 55] : [...m[1]].map((c) => c.charCodeAt(0) - 55);
  const sum = [...letters, ...[...m[2]].map(Number)].reduce((t, x, i) => t + x * (9 - i), 0);
  const r = (11 - (sum % 11)) % 11;
  return (r === 10 ? "A" : String(r)) === m[3];
}

/** China's resident identity number: a birth date and an ISO 7064 MOD 11-2 check character. */
function chinaRic(value: string): boolean {
  const v = value.toUpperCase();
  if (!/^(?:18|19|20)$/.test(v.slice(6, 8))) return false;
  if (!validDate(Number(v.slice(8, 10)), Number(v.slice(10, 12)), Number(v.slice(12, 14)), Number(v.slice(6, 8)) * 100)) return false;
  const sum = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2].reduce((t, w, i) => t + w * Number(v[i]), 0);
  return "10X98765432"[sum % 11] === v[17];
}

/** Ireland's PPS number: seven digits weighted 8 to 2, the second letter weighted 9, mod 23. */
function irishPps(value: string): boolean {
  // The 2013 format's second letter (A, B or H) counts; the old format's
  // (W, T or X) was only a marker.
  const extra = value.length === 9 && /[ABH]/.test(value[8]) ? (value.charCodeAt(8) - 64) * 9 : 0;
  const sum = [...value.slice(0, 7)].reduce((t, c, i) => t + Number(c) * (8 - i), 0) + extra;
  return "WABCDEFGHIJKLMNOPQRSTUV"[sum % 23] === value[7];
}

/** France's NIR: a real month (or 20 and over, for a birth not recorded), and 97 minus the number mod 97 as the key. Corsica's 2A and 2B count as 19 and 18. */
function frenchNir(value: string): boolean {
  const v = value.replace(/ /g, "");
  const body = v.slice(0, 13).replace("2A", "19").replace("2B", "18");
  return 97 - Number(BigInt(body) % 97n) === Number(v.slice(13));
}

/** Belgium's national number: 97 minus the first nine digits mod 97, with a 2 in front of them for births from 2000. */
function belgianNn(value: string): boolean {
  const d = onlyDigits(value);
  const check = Number(d.slice(9));
  return 97 - (Number(d.slice(0, 9)) % 97) === check || 97 - (Number(`2${d.slice(0, 9)}`) % 97) === check;
}

/** Czech and Slovak rodné číslo: a birth date (month plus 50 for women, plus 20 for the overflow series), and since 1954 ten digits divisible by 11. */
function czechRc(value: string): boolean {
  const d = onlyDigits(value);
  let month = Number(d.slice(2, 4));
  if (month > 70) month -= 70;
  else if (month > 50) month -= 50;
  else if (month > 20) month -= 20;
  const yy = Number(d.slice(0, 2));
  const century = d.length === 9 ? 1900 : yy < 54 ? 2000 : 1900;
  if (!validDate(yy, month, Number(d.slice(4, 6)), century)) return false;
  return d.length === 9 || (Number(d.slice(0, 9)) % 11) % 10 === Number(d[9]);
}

/** Portugal's Cartão de Cidadão: the Luhn rule run over digits and letters, where only a doubled value loses 9. */
function portugueseCc(value: string): boolean {
  const v = value.replace(/ /g, "");
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const sum = [...v].reverse().reduce((t, c, i) => {
    const n = alphabet.indexOf(c);
    if (i % 2 === 0) return t + n;
    return t + (n * 2 > 9 ? n * 2 - 9 : n * 2);
  }, 0);
  return sum % 10 === 0;
}

/** Mauritius's NID: a birth date, and a mod-17 check character over the first thirteen. */
function mauritiusNid(value: string): boolean {
  if (!validDate(Number(value.slice(5, 7)), Number(value.slice(3, 5)), Number(value.slice(1, 3)))) return false;
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const sum = [...value.slice(0, 13)].reduce((t, c, i) => t + (14 - i) * alphabet.indexOf(c), 0);
  return alphabet[(17 - (sum % 17) + 17) % 17] === value[13];
}

/** Finnish henkilötunnus: DDMMYY, century sign, serial, mod-31 check character. */
function finnishId(value: string): boolean {
  const m = /^(\d{2})(\d{2})(\d{2})([-+A-FU-Y])(\d{3})(.)$/.exec(value.toUpperCase());
  if (!m) return false;
  const century = m[4] === "+" ? 1800 : /[-U-Y]/.test(m[4]) ? 1900 : 2000;
  if (!validDate(Number(m[3]), Number(m[2]), Number(m[1]), century)) return false;
  return "0123456789ABCDEFHJKLMNPRSTUVWXY"[Number(m[1] + m[2] + m[3] + m[5]) % 31] === m[6];
}

/** Swedish personnummer: a real date (day + 60 for a coordination number), Luhn on the last ten. */
function swedishId(value: string): boolean {
  const ten = onlyDigits(value).slice(-10);
  const day = Number(ten.slice(4, 6));
  if (!validDate(Number(ten.slice(0, 2)), Number(ten.slice(2, 4)), day > 60 ? day - 60 : day)) return false;
  return luhn(ten);
}

/** Polish PESEL: weighted check digit, and a birth date with the century folded into the month. */
function polishPesel(d: string): boolean {
  const sum = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3].reduce((t, x, i) => t + x * Number(d[i]), 0);
  if ((10 - (sum % 10)) % 10 !== Number(d[10])) return false;
  const month = Number(d.slice(2, 4));
  const century = [1900, 2000, 2100, 2200, 1800][Math.floor(month / 20)];
  return validDate(Number(d.slice(0, 2)), month % 20, Number(d.slice(4, 6)), century);
}

/** Turkish TC kimlik no: first digit not zero, and two check digits. */
function turkishId(d: string): boolean {
  if (d[0] === "0") return false;
  const n = [...d].map(Number);
  const odd = n[0] + n[2] + n[4] + n[6] + n[8];
  const even = n[1] + n[3] + n[5] + n[7];
  if ((((odd * 7 - even) % 10) + 10) % 10 !== n[9]) return false;
  return n.slice(0, 10).reduce((a, b) => a + b, 0) % 10 === n[10];
}

/** Eleven bare digits are taken only as a PESEL or a kimlik no that checks out. */
/** Greece's AMKA: a birth date DDMMYY and a Luhn check. */
function greekAmka(d: string): boolean {
  const [dd, mm, yy] = [Number(d.slice(0, 2)), Number(d.slice(2, 4)), Number(d.slice(4, 6))];
  return (validDate(yy, mm, dd, 1900) || validDate(yy, mm, dd, 2000)) && luhn(d);
}

/** Norway's fødselsnummer: a birth date (plus 40 on the day for a D-number, on the month for an H-number) and two mod-11 check digits. */
function norwegianFnr(d: string): boolean {
  const check = (weights: number[]) => (11 - (weights.reduce((t, w, i) => t + w * Number(d[i]), 0) % 11)) % 11;
  if (check([3, 7, 6, 1, 8, 9, 4, 5, 2]) !== Number(d[9]) || check([5, 4, 3, 2, 7, 6, 5, 4, 3, 2]) !== Number(d[10])) return false;
  let day = Number(d.slice(0, 2));
  let month = Number(d.slice(2, 4));
  if (day >= 80) return false;
  if (day > 40) day -= 40;
  if (month > 40) month -= 40;
  return validDate(Number(d.slice(4, 6)), month, day, 1900) || validDate(Number(d.slice(4, 6)), month, day, 2000);
}

/** Estonia's isikukood and Lithuania's asmens kodas: sex and century, a birth date, and a two-pass mod-11 check. */
function balticId(d: string): boolean {
  if (!/^[1-8]/.test(d)) return false;
  if (!validDate(Number(d.slice(1, 3)), Number(d.slice(3, 5)), Number(d.slice(5, 7)), 1800 + Math.floor((Number(d[0]) - 1) / 2) * 100)) return false;
  let check = [...d.slice(0, 10)].reduce((t, c, i) => t + ((i % 9) + 1) * Number(c), 0) % 11;
  if (check === 10) check = [...d.slice(0, 10)].reduce((t, c, i) => t + (((i + 2) % 9) + 1) * Number(c), 0) % 11;
  return check % 10 === Number(d[10]);
}

/** Eleven digits with nothing around them: only a format that proves itself — a birth date and a check digit at least. */
function elevenDigitId(value: string): boolean {
  const d = onlyDigits(value);
  return polishPesel(value) || turkishId(value) || greekAmka(d) || norwegianFnr(d) || balticId(d)
    || (Number(d.slice(2, 4)) <= 12 && belgianNn(d));
}

/** Romania's CNP: sex and century, a birth date, a county, and a weighted mod-11 check. */
function romanianCnp(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 13 || !/^[1-8]/.test(d)) return false;
  const century = { 1: 1900, 2: 1900, 3: 1800, 4: 1800, 5: 2000, 6: 2000 }[Number(d[0])] ?? 1900;
  if (!validDate(Number(d.slice(1, 3)), Number(d.slice(3, 5)), Number(d.slice(5, 7)), century)) return false;
  const county = Number(d.slice(7, 9));
  if (county < 1 || (county > 52 && county !== 70)) return false;
  const sum = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9].reduce((t, w, i) => t + w * Number(d[i]), 0) % 11;
  return (sum === 10 ? 1 : sum) === Number(d[12]);
}

/** Thai national ID: thirteen digits, a province code in the second and third (10–96), mod-11 check. */
function thaiId(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 13) return false;
  const sum = [...d.slice(0, 12)].reduce((t, c, i) => t + Number(c) * (13 - i), 0);
  if (Number(d.slice(1, 3)) < 10 || Number(d.slice(1, 3)) > 96) return false;
  return (11 - (sum % 11)) % 10 === Number(d[12]);
}

/** Korean RRN / FRN: a birth date and a sex-and-century digit. Numbers issued
 *  since 2020 dropped the check digit, so the written form with its hyphen is
 *  taken on the date alone; thirteen unbroken digits still need the check. */
function koreanId(value: string): boolean {
  const d = onlyDigits(value);
  if (!validDate(Number(d.slice(0, 2)), Number(d.slice(2, 4)), Number(d.slice(4, 6)))) return false;
  if (value.includes("-")) return true;
  const sum = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5].reduce((t, x, i) => t + x * Number(d[i]), 0);
  return (11 - (sum % 11)) % 10 === Number(d[12]);
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/** Aadhaar: twelve digits, not opening with 0 or 1, a Verhoeff check, and not one digit repeated. */
function aadhaar(value: string): boolean {
  const d = onlyDigits(value);
  if (/^(\d)\1+$/.test(d)) return false;
  let c = 0;
  [...d].reverse().forEach((ch, i) => { c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(ch)]]; });
  return c === 0;
}

/** German Sozialversicherungsnummer: the initial becomes its two-digit place
 *  in the alphabet, and a weighted digit-sum over the twelve gives the last. */
function germanSvnr(value: string): boolean {
  const m = /^(\d{8})([A-Z])(\d{2})(\d)$/.exec(value);
  if (!m) return false;
  const digits = m[1] + String(m[2].charCodeAt(0) - 64).padStart(2, "0") + m[3];
  const w = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1];
  const sum = w.reduce((t, x, i) => { const p = x * Number(digits[i]); return t + Math.floor(p / 10) + (p % 10); }, 0);
  return sum % 10 === Number(m[4]);
}

/** South African ID: YYMMDD, a gender sequence, a citizenship digit,
 *  and Luhn over all thirteen. Citizenship is 0 (citizen), 1 (permanent
 *  resident) or 2 (refugee). It was caught as a card until cards had to
 *  open with 2 to 6; it now has its own check. */
function southAfricanId(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 13) return false;
  if (romanianCnp(d)) return true;
  if (!/^[012]$/.test(d[10])) return false;
  return validDate(Number(d.slice(0, 2)), Number(d.slice(2, 4)), Number(d.slice(4, 6))) && luhn(d);
}

/** Australian Medicare: a weighted check on the first eight digits. */
function medicare(value: string): boolean {
  const d = onlyDigits(value);
  const sum = [1, 3, 7, 9, 1, 3, 7, 9].reduce((t, x, i) => t + x * Number(d[i]), 0);
  return sum % 10 === Number(d[8]);
}

/** A chat export's date and time, then a dash and who spoke. */
const CHAT_TIMESTAMP_PATTERN = /\[?(?:\d{4}\.[ ]?\d{1,2}\.[ ]?\d{1,2}\.?|\d{1,2}[./]\d{1,2}[./](?:\d{4}|\d{2})\.?),?[ \t]+\d{1,2}:\d{2}(?::\d{2})?(?:[ \t]*[AaPp][Mm])?\]?(?=[ \t]*(?:[-–][ \t]*)?[^\s\d][^:\n]{0,30}:)/gu;

/** The kinds that are numbers, or a few letters and numbers. */
const NUMBER_KINDS = new Set<StructuredKind>(["card", "phone", "iban", "ssn", "govid", "postcode"]);

/** Words after "via", "place" and the rest that make no street: see WORLD_STREET_PATTERN's scan. */
const NOT_A_STREET_NAME = new Set([
  "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December",
  "Apt", "Royal", "The", "Email", "Zoom", "Teams", "Slack", "WhatsApp", "Google", "Facebook", "Twitter", "Phone", "Text", "Section",
  "Article", "Chapter", "Step", "Page", "Room", "Level", "Gate", "Terminal", "Platform", "Route", "Highway", "Interstate",
]);

/**
 * Whether a match sits inside a hash or a UUID — a run of lower-case hex with
 * letters in it, twelve characters or more, or the 8-4-4-4-12 shape in any
 * case. Neither is ever somebody's phone, card or account, and both are what
 * developers paste: a commit "bf2444630449" was taken as the phone number
 * 2444630449, a request id "db23ad50-3239-f77f-…" as an IBAN, and a forty-
 * character hash as the card in its middle (bench/formats). Upper-case hex
 * is not counted — an IBAN like DE89370400440532013000 is all hex characters.
 * Secrets are not among the kinds checked: a hex token after "Bearer" is one.
 */
function insideHexToken(text: string, start: number, end: number): boolean {
  // The token each end of the match falls in: a match can run past a hash
  // into the next word ("…84acc446284c port"), and starting inside one is
  // enough.
  // No further than a hash or a UUID can run either side: unbounded, a page
  // of "1-1-1-…" was walked end to end for every match on it (scanner-safety).
  const tokenAt = (i: number) => {
    let a = i;
    let b = i;
    while (a > 0 && i - a < 80 && /[0-9A-Za-z-]/.test(text[a - 1])) a -= 1;
    while (b < text.length && b - i < 80 && /[0-9A-Za-z-]/.test(text[b])) b += 1;
    return text.slice(a, b);
  };
  const hex = (token: string) =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)
    || (/^[0-9a-f]{12,}$/.test(token) && /[a-f]/.test(token) && /\d/.test(token));
  return hex(tokenAt(start)) || hex(tokenAt(Math.max(start, end - 1)));
}

/** A phone word close before a number, in the languages the labels know. */
const PHONE_WORD_BEFORE = /(?:phone|tel(?:ephone)?|mobile|cell|whats\s?app|t[ée]l[ée]phone|tel[ée]fono|telefon(?:o|nummer)?|telefoon(?:nummer)?|m[óo]vil|cellulare|handy|portable|फ़?ोन|मोबाइल|ఫోన్|మొబైల్)[^\n\d.]{0,20}$/iu;

/** nnn nnn nnn: a Canadian SIN (Luhn, never opening with 0 or 8) or an Australian TFN (weighted mod 11). */

function groupedId(value: string): boolean {
  const d = onlyDigits(value);
  if (/^(\d)\1+$/.test(d)) return false;
  if (!/^[08]/.test(d) && luhn(d)) return true;
  return [1, 4, 3, 7, 5, 8, 6, 9, 10].reduce((t, x, i) => t + x * Number(d[i]), 0) % 11 === 0;
}

/** Words that number things other than houses, for the one rule that has
 *  only numbers on both sides of a name to go on: "Invoice 4411 Item 12,
 *  Paid", "Season 2 Episode 5, Netflix". */
const NOT_A_LABELLED_STREET = /\b(?:Item|Items|Order|Invoice|Ticket|Case|Issue|Product|Qty|No|Nr|Number|Vol|Volume|Episode|Season|Round|Game|Match|Player|Rule|Article|Art|Clause|Paragraph|Para|Column|Col|Slide|Question|Task|Sprint|Release|Build|Patch|Update|Beta|Alpha|Pro|Max|Plus|Mini|Ultra|Air|Gen|Mark|Mk|Type|Size|Pack|Bottle|Iteration|Test|Exam|Lab|Lesson|Module|Grade|Class|Level|Tier|Step|Point|Points|Note|Notes|Exhibit|Annex|Appendix|Schedule|Form|Rev|Revision|Edition|Ed|Draft|Option|Plan|Account|Acct|Ref|Reference|Id|ID|Code|Pin|PIN|Port|Channel|Track|Disc|Disk|Batch|Lot|Job|Run|Shift|Bay|Gate|Seat|Table)\b/;


/**
 * Code read as a password, from real prompts that paste a login form or a
 * database URL (WildChat, 2026-10-23): a call, "PasswordField('password',
 * validators=…)"; a template, "}@{host}/{database}"; a type, "str):"; an HTML
 * attribute closing its tag, "required>"; and the word itself before a
 * comment, "password', // замените на свой пароль". Real passwords carry
 * symbols too ("P}fX2+dX8B5q#", "N;w=DF.RXJK2"), so only these shapes.
 */
function codeNotASecret(value: string): boolean {
  return /^[A-Za-z_]\w{3,}\(\s*['"]/.test(value)
    || /\{[a-z_]{2,}\}/.test(value)
    || /^(?:str|int|bool|float|bytes|dict|list)\)?:?$/.test(value)
    || /^(?:required|disabled|autofocus|readonly)\/?>$/.test(value)
    || /['"],?\s*(?:\/\/|#)\s/.test(value);
}

/** An encyclopedia's opening, read around a birth date: see `encyclopedic` in findStructured. */
const ARTICLE_BORN_BEFORE = /\((?:[^()\n]{0,100}[;,]\s*)?born\s+(?:on\s+)?$/i;
const ARTICLE_NAME_BEFORE = /(?:^|[\s"“(])\p{Lu}[\p{L}'’.-]+(?:\s+\p{Lu}[\p{L}'’.-]*){1,4}\s*\([^()\n]*$/u;
// American, Canadian, Italian, Japanese, English, Dutch, Czech, Pakistani,
// Icelandic: a nationality ends one of these ways. Greek and Swiss do not,
// and stay hidden, which is the safe way to be wrong. The scan shows forty
// characters after the date, so a long opening can cut the word short
// ("…, is a Portugue"): a word that runs to the edge is read as far as it goes.
const ARTICLE_NATIONALITY_AFTER = new RegExp(
  String.raw`^\s*(?:(?:[,;]|\s+in\s)[^()\n]{0,60})?\)\s*(?:,[^()\n]{1,60},\s*)?(?:is|was)\s+(?:an?|the)\s+`
  + String.raw`(?:(?:former|retired|professional|semi-professional|amateur)\s+){0,2}\p{Lu}\p{Ll}+(?:(?:an|ese|ish|ch|i|ic)(?![\p{L}])|(?<=\p{Lu}\p{Ll}{5,})$)`,
  "u",
);

export function findStructured(
  input: string,
  /** Labels on trial, beside the shipped LEARNED_CUES: the learning bench
   *  scores a candidate by what the whole engine does with it, guards and
   *  all, not by its pattern alone. Never passed in production. */
  trialCues?: readonly LearnedCue[],
): Array<{ kind: StructuredKind; value: string }> {
  const found: Array<{ kind: StructuredKind; value: string }> = [];
  const claimed: Array<[number, number]> = [];
  // Patterns read this; values are taken from `text`. See foldForScan.
  const { scan: scanText, from, to } = foldForScan(input);
  /* `text` is the original as the scan sees it: indexed like scanText, and
     sliced out of the input. Every span below is a span of scanText. */
  const at = (i: number) => (i >= from.length ? input.length : from[Math.max(0, i)]);
  const text = {
    length: scanText.length,
    slice: (start: number, end: number = scanText.length) => {
      const a = Math.max(0, Math.min(start, scanText.length));
      const b = Math.max(a, Math.min(end, scanText.length));
      return b === a ? "" : input.slice(at(a), to[b - 1]);
    },
  };

  /*
   * Which characters are claimed, so "does this overlap anything?" costs the
   * length of the match rather than the number of values found so far.
   * Asking `claimed` itself made the scan quadratic: two thousand "What is
   * your phone number?" / "560 1234" pairs gave two thousand claims, every
   * four-digit postcode candidate was compared with all of them, and the page
   * took a quarter of a second of Worker CPU (scanner-safety, "questions and
   * replies"). A span is only ever added or widened, never narrowed, so marking
   * each one as it is claimed keeps this exact. An empty span marks nothing,
   * and the old comparison still sees one strictly inside a match, so while
   * any exist the comparison is used as before.
   */
  const taken = new Uint8Array(Math.max(text.length, scanText.length) + 1);
  let emptyClaims = 0;
  const mark = ([from, to]: readonly [number, number]) => {
    if (to > from) taken.fill(1, from, to); else emptyClaims += 1;
  };
  const overlaps = (start: number, end: number) =>
    end > start && emptyClaims === 0
      ? taken.subarray(start, end).includes(1)
      : claimed.some(([from, to]) => start < to && end > from);
  const claim = (span: [number, number]) => {
    claimed.push(span);
    mark(span);
  };
  // The date and time a chat export puts before each message, taken first so
  // nothing reads it as a phone: "2026. 10. 13. 19:40 - Kati:", "14.10.26.
  // 18:22 - Sanja:", "15.10.2026, 18:30 - Roxana:" (realistic5, 2026-10-24).
  // Marked, not claimed: `claimed` runs beside `found`, one span a value, and
  // the flat-number rule reads found[i] for claimed[i].
  for (const m of scanText.matchAll(CHAT_TIMESTAMP_PATTERN)) mark([m.index ?? 0, (m.index ?? 0) + m[0].length]);

  /**
   * `group` picks which part of the match is the value. The cued patterns
   * match "passport number X" but only X may be replaced — redacting the cue
   * as well would delete the very word that tells the model what it is looking
   * at, and the answer would be about an unlabelled string.
   */
  /* The runs of lines `test` finds something in. A pattern that never
     crosses a line break — `lines` in scan's options — is tried on these
     alone: in a long document most lines have no Devanagari, no "Brgy" and
     no Greek, and a pattern that starts at every capital or digit was most
     of the time a 2,000-message document took (2026-10-26). */
  const runsByTest = new Map<RegExp, Array<[number, number]>>();
  const linesWhere = (test: RegExp): Array<[number, number]> => {
    let runs = runsByTest.get(test);
    if (runs) return runs;
    runs = [];
    for (let a = 0; a <= scanText.length;) {
      const nl = scanText.indexOf("\n", a);
      const b = nl === -1 ? scanText.length : nl;
      if (test.test(scanText.slice(a, b))) {
        const last = runs[runs.length - 1];
        if (last && last[1] + 1 === a) last[1] = b; else runs.push([a, b]);
      }
      a = b + 1;
    }
    runsByTest.set(test, runs);
    return runs;
  };
  const scan = (
    pattern: RegExp,
    kind: StructuredKind,
    opts?: { accept?: (value: string, before?: string, after?: string) => boolean; group?: number; lines?: RegExp },
  ) => {
    const group = opts?.group ?? 0;
    const runs: Array<[number, number]> = opts?.lines ? linesWhere(opts.lines) : [[0, scanText.length]];
    for (const [from, upTo] of runs) {
      pattern.lastIndex = 0;
      const piece = from === 0 && upTo === scanText.length ? scanText : scanText.slice(from, upTo);
      for (const match of piece.matchAll(pattern)) {
        const indices = (match as RegExpMatchArray & { indices?: Array<[number, number] | undefined> }).indices;
        const span = indices?.[group];
        const start = from + (span ? span[0] : match.index ?? 0);
        const end = span ? from + span[1] : start + match[0].length;
        const raw = match[group];
        if (typeof raw !== "string") continue;
        if (overlaps(start, end)) continue;
        if (NUMBER_KINDS.has(kind) && insideHexToken(scanText, start, end)) continue;
        // Two readings of the same span: the normalised one for the checks,
        // which are arithmetic on digits, and the original one for the value,
        // because that is the string that has to be found and replaced in the
        // message the person wrote.
        const value = text.slice(start, end).trim();
        if (opts?.accept && !opts.accept(raw.trim(), text.slice(Math.max(0, start - 40), start), text.slice(end, end + 40))) continue;
        claim([start, end]);
        found.push({ kind, value });
      }
    }
  };

  // First. A key can contain a run that looks like something else — a JWT
  // segment reads as a long word, an AWS id as an identifier — and whichever
  // pattern claims a span keeps it. Nothing above a secret in the order can
  // carve a piece out of one and leave the rest in the clear.
  scan(SECRET_PATTERN, "secret");
  scan(AZURE_CLIENT_SECRET_PATTERN, "secret");
  // A generated key has a digit somewhere; "key-" and a word does not.
  scan(SECRET_VENDOR_PATTERN, "secret", { accept: (value) => /\d/.test(value) });
  scan(SIGNED_KEY_PATTERN, "secret", { group: 1 });
  scan(SIGNED_KEY_PATTERN, "secret", { group: 2 });
  // Values under a field name — a JSON key, a table cell, a column header —
  // with the kind the name says. See redactionFields.
  for (const field of findFields(scanText)) {
    if (overlaps(field.start, field.end)) continue;
    if (NUMBER_KINDS.has(field.kind) && insideHexToken(scanText, field.start, field.end)) continue;
    claim([field.start, field.end]);
    found.push({ kind: field.kind, value: text.slice(field.start, field.end).trim() });
  }
  // Japanese, Chinese and Korean addresses and postcodes, in their own
  // scripts — see redactionAddressAsia. Before the phone patterns, which
  // would take "243-0425" as a local number.
  for (const place of findAsianAddresses(scanText)) {
    if (overlaps(place.start, place.end)) continue;
    claim([place.start, place.end]);
    found.push({ kind: place.kind, value: text.slice(place.start, place.end).trim() });
  }
  // And Saudi and Gulf numbers in Arabic text — see redactionArabic.
  for (const v of findArabicValues(scanText)) {
    if (overlaps(v.start, v.end)) continue;
    claim([v.start, v.end]);
    found.push({ kind: v.kind, value: text.slice(v.start, v.end).trim() });
  }
  // National IDs and streets in the UAE, Israel, Russia, Vietnam and
  // Indonesia — see redactionMoreScripts.
  for (const v of findMoreScriptValues(scanText)) {
    if (overlaps(v.start, v.end)) continue;
    claim([v.start, v.end]);
    found.push({ kind: v.kind, value: text.slice(v.start, v.end).trim() });
  }
  // A number after an email, or a chat's answer to someone asking for one —
  // see redactionPhoneContext.
  for (const v of findContextPhones(scanText)) {
    if (overlaps(v.start, v.end)) continue;
    claim([v.start, v.end]);
    found.push({ kind: v.kind, value: text.slice(v.start, v.end).trim() });
  }
  // A private key, one body line at a time — see PEM_PRIVATE_KEY_PATTERN.
  PEM_PRIVATE_KEY_PATTERN.lastIndex = 0;
  for (const block of scanText.matchAll(PEM_PRIVATE_KEY_PATTERN)) {
    const bodyStart = (block.index ?? 0) + block[0].indexOf(block[1]);
    let at = bodyStart;
    for (const line of block[1].split("\n")) {
      const trimmed = line.trim();
      const start = at + line.indexOf(trimmed);
      at += line.length + 1;
      if (trimmed.length < 8 || /:/.test(trimmed)) continue; // headers such as "Proc-Type: 4,ENCRYPTED"
      const end = start + trimmed.length;
      if (overlaps(start, end)) continue;
      claim([start, end]);
      found.push({ kind: "secret", value: text.slice(start, end) });
    }
  }
  // A value given as the whole of a reply, to the question on the line
  // before: see BARE_REPLY_PATTERN. The question has to have asked, with a
  // question mark, for a phone number, a postcode or an ID, and the reply
  // needs digits: "What's your phone number?" / "560 1234". Early, so the
  // question decides what the reply is before any shape does: "(11)
  // 96123-4567" is a Brazilian mobile, not a ZIP+4.
  BARE_REPLY_PATTERN.lastIndex = 0;
  for (const m of scanText.matchAll(BARE_REPLY_PATTERN)) {
    const span = (m as RegExpMatchArray & { indices?: Array<[number, number]> }).indices?.[1];
    if (!span || overlaps(span[0], span[1])) continue;
    const value = m[1];
    const digits = value.replace(/\D/g, "").length;
    if (digits < 3 || /^(?:19|20)\d\d$/.test(value)) continue;
    // The line before the reply, without copying everything above it: slicing
    // and splitting the whole prefix per reply was quadratic in the page.
    let questionEnd = m.index ?? 0;
    while (questionEnd > 0 && /\s/.test(scanText[questionEnd - 1])) questionEnd -= 1;
    const question = scanText.slice(scanText.lastIndexOf("\n", questionEnd - 1) + 1, questionEnd);
    const kind: StructuredKind | null =
      ASKED_FOR_PHONE.test(question) && digits >= 4 ? "phone"
        : ASKED_FOR_POSTCODE.test(question) && value.length <= 10 ? "postcode"
          : ASKED_FOR_ID.test(question) && value.replace(/\s/g, "").length >= 4 ? "govid"
            : null;
    if (!kind) continue;
    claim(span);
    found.push({ kind, value: text.slice(span[0], span[1]).trim() });
  }

  // Before email: "admin:S3cretPass@db.internal" is a password, not an address.
  // "user:pass@host" in documentation is the shape, not a password.
  scan(URL_CREDENTIAL_PATTERN, "secret", { group: 1, accept: (value) => plausibleSecretValue(value) && !/^(?:pass|pwd|passwd|pw|password|secret|token|x+)$/i.test(value) });
  // The value is in whichever group matched: double, single or back quotes, or bare.
  for (const group of [1, 2, 3, 4]) scan(ASSIGNED_SECRET_PATTERN, "secret", { group, accept: plausibleAssignedSecret });
  for (const group of [1, 2]) scan(SECRET_COMPARED_PATTERN, "secret", { group, accept: plausibleAssignedSecret });
  scan(PASSWORD_IS_PATTERN, "secret", { group: 1, accept: plausiblePasswordIs });
  // See PASSWORD_WORLD_NEAR_PATTERN: a password's shape, since the words
  // between are anything. Not an address, a link or a path.
  scan(PASSWORD_WORLD_NEAR_PATTERN, "secret", {
    group: 1,
    accept: (value) => /\p{L}/u.test(value) && /\d/.test(value)
      // A password's symbol, not only a separator: "1Password 8" is a
      // product, and "textBox2.Text", "port=5432", "8-character", "OAuth2?"
      // and a GC log's "57435641K->" are code and prose (real chats).
      && /[!#$%&*@^~+_]/.test(value) && !/=/.test(value)
      && !/[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}|:\/\/|\/|\.(?:py|js|ts|env|json|ya?ml|txt|cfg|conf)$/iu.test(value)
      && !/^\d+(?:[.,:-]\d+)+$/.test(value),
  });
  scan(DOOR_CODE_PATTERN, "secret", { group: 1, accept: (value) => (value.match(/\d/g) ?? []).length >= 3 });
  // Looser in what comes between, so stricter in the value: a letter, and a
  // digit or a symbol with it — "password for it is required" is prose.
  scan(PASSWORD_FOR_PATTERN, "secret", {
    group: 1,
    // And not the next parameter of a function: "password, host='localhost'"
    // and "password=self.password, host=self.host" (WildChat).
    accept: (value) => plausiblePasswordIs(value) && /[A-Za-z]/.test(value) && /[^A-Za-z]/.test(value) && !/^(?:https?:|[$%{<\[])/.test(value) && !/^[A-Za-z_][\w.]*=/.test(value),
  });
  // Under a label, in the benchmark's languages: a value that looks made,
  // not written — letters with digits or symbols — and not a placeholder.
  // A lower-case "password:" key or a "--password=" flag is a config file or
  // a command line; the secret patterns above already judge those, and the
  // ones in Kubernetes' documentation are its examples.
  scan(PASSWORD_LABELLED_PATTERN, "secret", {
    group: 1,
    accept: (value, before) => plausiblePasswordIs(value) && value.length >= 6 && /[A-Za-z]/.test(value) && !/^(?:https?:|[$%{<\[])/.test(value)
      && !/(?:^|[^\p{L}])(?:-{1,2}[\w-]*password|password)[ \t]*[:=][ \t"']*$/u.test(before ?? ""),
  });
  // A PIN, on its label alone.
  scan(PIN_CUED_PATTERN, "secret", { group: 1 });
  // A PIN or access code under other words, or after "enter … to access":
  // see PIN_WORDED_PATTERN. A year is not one ("use 2024 to …").
  const notYear = (value: string) => !/^(?:19|20)\d\d$/.test(value);
  for (const group of [1, 2, 3]) scan(PIN_WORDED_PATTERN, "secret", { group, accept: notYear });
  scan(PIN_VERB_PATTERN, "secret", { group: 1, accept: notYear });
  // "PIN for entry: 8156", and "your 3414 for verification" — see
  // PIN_LOOSE_PATTERN and NUMBER_POSSESSIVE_PATTERN.
  scan(PIN_LOOSE_PATTERN, "secret", { group: 1, accept: notYear });
  scan(NUMBER_POSSESSIVE_PATTERN, "secret", { group: 1, accept: notYear });
  // A user name, after a colon, unless it is one every manual uses.
  scan(USERNAME_LABELLED_PATTERN, "govid", { group: 1, accept: (value) => !USERNAME_NOT.test(value) });
  // The same under the other languages' word for it — see USERNAME_WORLD_PATTERN.
  scan(USERNAME_WORLD_PATTERN, "govid", { group: 1, accept: (value) => !USERNAME_NOT.test(value) && plausibleWorldUsername(value) });
  scan(NAMED_SECRET_PATTERN, "secret", { group: 1, accept: plausibleNamedSecret });
  scan(XML_SECRET_TAG_PATTERN, "secret", { group: 2, accept: plausibleSecretValue });
  scan(BARE_KEY_PATTERN, "secret", { group: 1, accept: (value) => plausibleNamedSecret(value) && /\d/.test(value) && /[A-Za-z]/.test(value) });
  // A password or token with no label, and a user name made of a name. After
  // the labelled forms, so those keep the spans they already had.
  // Not a mail queue id: "sendmail[19391]: jA9J1Wd7019391: from=root" is how
  // sendmail starts every log line (Loghub).
  // Nor a package id on an install line (PACKAGE_COMMAND_PATTERN).
  scan(RANDOM_TOKEN_PATTERN, "secret", { group: 1, accept: (value, before, after) => randomToken(value) && !(/\]:[ \t]*$/.test(before ?? "") && /^:/.test(after ?? "")) && !PACKAGE_COMMAND_PATTERN.test(before ?? "") });
  // Not a name in code: a method ("private void Delete_Click(object sender"),
  // a property ("public string Receipt_Number { get; set; }"), a call
  // ("Mathf.Atan2(") — WildChat, pasted C# and Unity.
  // The bracket glued on: "Jamison_Goyette37 (Product Quality Coordinator)"
  // is a signature.
  // Nor one quoted or bracketed in code: ref="Target_Service", namespace
  // Albion_Helper, ObjectDelete("Key_Word1"), Dim_Orders[Order Type],
  // [Inner_Monologue] (WildChat).
  const notCode = (before?: string, after?: string) => !/^(?:\(|\s*\{\s*get\b|["']\)|\[|\])/.test(after ?? "")
    && !/(?:\b(?:void|public|private|protected|static|string|int|bool|float|double|var|let|const|def|function|DateTime|class|struct|namespace)\s+|\bref=["']|\(["']|\[)$/.test(before ?? "");
  // A first half of two letters only when it is a name: "Al_Boehm", not
  // Python's "Py_Initialize".
  //
  // Among other identifiers it is one of them: "Patient_Name ('Herr
  // Mueller'), Appointment_Date ('25. Juli'), Appointment_Time" is a schema,
  // "int Lot_Digits; input bool Trailing_Stop_ON" a trading script. 220 of
  // 635 IDs taken from real prompts were these (WildChat, 2026-10-23). Where
  // two other underscored words stand in the text, a handle must open with a
  // given name to stay one: "Laisha_Koss58" in a list of users still goes.
  const identifiers = new Set(input.match(/(?<![\p{L}\p{N}_])[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]*[A-Za-z0-9]/gu) ?? []);
  const amongIdentifiers = (value: string) => identifiers.size - (identifiers.has(value) ? 1 : 0) >= 2;
  scan(NAME_HANDLE_PATTERN, "govid", {
    group: 1,
    accept: (value, before, after) => {
      const first = value.split(/[_.]/)[0].toLowerCase();
      return nameHandle(value) && notCode(before, after)
        && (/^[A-Z][a-z]{2,}[_.]/.test(value) || GIVEN_NAMES.has(first))
        && (!amongIdentifiers(value) || isGivenNameAnywhere(first));
    },
  });
  scan(HANDLE_CUED_PATTERN, "govid", { group: 1, accept: (value) => nameHandle(value) });
  // A person's name is neither an ordinary word, a term nor a product — see
  // NAME_DOT_PATTERN and NAME_NUMBER_PATTERN for what the shapes also are.
  const personal = (word: string) => /^(?:Mc|Mac|O)?[A-Z][a-z]+$/.test(word) && !COMMON_CAPITALISED.has(word)
    && !isCommonLowercaseWord(word.toLowerCase()) && !isNotAPerson(word) && !HANDLE_NOT_A_NAME.has(word.toLowerCase()) && !NOT_A_HANDLE.test(word);
  // And the first half a given name: "Instagram.After" and "Vector3" are
  // a missing space and a type (WildChat). From any country's names, not only
  // the US list: "Priya.Sharma", "Thabo.Nkosi" (2026-10-24).
  const given = (word: string) => isGivenNameAnywhere(word) && personal(word);
  scan(NAME_DOT_PATTERN, "govid", {
    group: 1,
    accept: (value, before, after) => {
      const [first, ...rest] = value.split(/[.-]/);
      // A sentence run on after a missing space: "Christian.Since",
      // "America.Early", "Antonio.Located" (oasst2, WildChat). A surname is
      // not an adverb, a participle or the word that opens a sentence.
      const sentence = rest.some((w) => /(?:ly|ed|ing|ous|ive|ful|less|ment|tion|sion|ness|ity)$/.test(w) || SENTENCE_OPENERS.has(w));
      // A surname that ends a citation's author list, its title run on:
      // "Charles Sutton.Program synthesis", "Daya Guo.Deepseekmath" (WildChat
      // papers). A name only from the world list, after a capitalised word,
      // is that surname; one from the US list stays a handle.
      const citation = !GIVEN_NAMES.has(first.toLowerCase()) && /\p{Lu}\p{Ll}+\s+$/u.test(before ?? "");
      return given(first) && !sentence && !citation && rest.every(personal) && notCode(before, after) && !/[=:]\s*$|\bimport\s+$|\busing\s+$/.test(before ?? "");
    },
  });
  scan(NAME_NUMBER_PATTERN, "govid", {
    group: 1,
    accept: (value, before, after) => given(value.replace(/\d+$/, "")) && notCode(before, after),
  });
  scan(KEY_SPOKEN_PATTERN, "secret", { group: 1, accept: (value) => plausibleNamedSecret(value) && (value.match(/\d/g) ?? []).length >= 3 && /[A-Za-z]/.test(value) });
  // The same, a few words from its label — see API_KEY_SPOKEN_PATTERN. And
  // random-looking: letters, digits and case change often in a key, seldom
  // in a name ("documentation-update-2024-final").
  scan(API_KEY_SPOKEN_PATTERN, "secret", {
    group: 1,
    accept: (value) => plausibleNamedSecret(value) && (value.match(/\d/g) ?? []).length >= 3 && /[A-Za-z]/.test(value) && classChanges(value) >= 6,
  });
  scan(CURL_USER_PATTERN, "secret", { group: 1, accept: plausibleSecretValue });
  // A MAC address with a separator or a hex letter in it, before the phone
  // patterns: "0012.3456.789A" is Cisco's way of writing one, and the phone
  // rule took "0012.3456.789" and left the A. A dotted run of digits alone is
  // left to the later scan, where a phone number can still claim it.
  scan(MAC_ADDRESS_PATTERN, "host", { accept: (value) => /[A-Fa-f]/.test(value) && !/^(?:ff){6}$|^(?:00){6}$/i.test(value.replace(/[:.-]/g, "")) });
  scan(AUTH_HEADER_BARE_PATTERN, "secret", { group: 1, accept: (value) => /\d/.test(value) && /[A-Za-z]/.test(value) });
  scan(AUTH_HEADER_PATTERN, "secret", { group: 1, accept: (value) => /\d/.test(value) && /[A-Za-z]/.test(value) });
  // Not after a slash: "lore.kernel.org/all/20200710012662.GA29679@chep…" is
  // a mailing-list message id in a URL, not somebody's address.
  // Nor an image at a pixel density: "icon@2x.png", "T4_MAIN_ARCANESTAFF@2.png"
  // (WildChat). No mail domain ends in an image's extension.
  scan(EMAIL_PATTERN, "email", {
    accept: (value, before) => !/[^/\s]\/$/.test(before ?? "") && !/\.(?:png|jpe?g|gif|svg|webp|bmp|ico)$/i.test(value),
  });
  scan(EMAIL_ENCODED_PATTERN, "email");
  scan(OBFUSCATED_EMAIL_PATTERN, "email");
  // Before the card and phone patterns, which would carve its digits up.
  scan(PASSPORT_MRZ_PATTERN, "govid");
  // IBANs before cards. The digits inside an IBAN are a run of twelve to
  // nineteen, and one in ten passes Luhn: "PL61 1090 1014 0000 0712 …" was
  // being claimed as a card, and the rest of the account left in the clear.
  // A card never opens with letters, so nothing is lost the other way.
  scan(IBAN_PAPER_TAIL_PATTERN, "iban", { accept: iban97 });
  scan(IBAN_PATTERN, "iban", { accept: (value) => iban97(value.replace(/-/g, " ")) });
  // An IBAN spaced however its writer liked: "NO 0571 3905 25162",
  // "NO07.8380.08.06006", "ES72 2013-0692-81-0201150993". Read one character
  // at a time from the country code, allowing one space, dot or dash between
  // any two, until the country's own length is reached; then it must end
  // there and pass mod-97. Two checks a reference number does not pass.
  IBAN_START_PATTERN.lastIndex = 0;
  for (const m of scanText.matchAll(IBAN_START_PATTERN)) {
    const start = m.index ?? 0;
    const want = IBAN_LENGTHS[m[1]];
    if (!want) continue;
    let compact = "";
    let end = start;
    let gap = false;
    for (let i = start; i < scanText.length && compact.length < want; i += 1) {
      const ch = scanText[i];
      if (/[A-Za-z0-9]/.test(ch)) { compact += ch; gap = false; end = i + 1; }
      else if (/[ .\-]/.test(ch) && !gap && compact.length > 0) gap = true;
      else break;
    }
    if (compact.length !== want || /[A-Za-z0-9]/.test(scanText[end] ?? "")) continue;
    if (!iban97(compact) || overlaps(start, end)) continue;
    claim([start, end]);
    found.push({ kind: "iban", value: text.slice(start, end) });
  }
  // A phone's IMEI, before cards: the card rule no longer takes a number
  // opening with 0, 1, 7, 8 or 9, and an IMEI opens with anything. Filed as
  // an ID number, which is what it is — the phone's.
  scan(IMEI_GROUPED_PATTERN, "govid", { accept: (value) => luhn(value.replace(/\D/g, "")) });
  scan(IMEI_CUED_PATTERN, "govid", { group: 1, accept: (value) => luhn(value) });
  scan(CARD_PATTERN, "card", { accept: (value, before, after) => plausibleCard(value, before, after) });
  // After the spaced form, so a card written in groups is claimed once as one
  // value rather than found twice under two patterns.
  scan(CARD_RUN_PATTERN, "card", { accept: (value, before, after) => plausibleCard(value, before, after) });
  scan(CARD_DOTTED_PATTERN, "card", { accept: (value, before, after) => plausibleCard(value, before, after) });
  // Last among cards, so every card that passes Luhn is claimed by its shape
  // first: this takes only what its label vouches for and the check refused.
  scan(CARD_LABELLED_PATTERN, "card", { group: 1, accept: (value) => { const n = value.replace(/\D/g, "").length; return n >= 13 && n <= 19; } });
  // The same under a label in the benchmark's other languages, or a few words from it.
  scan(CARD_LABELLED_INTL_PATTERN, "card", { group: 1, accept: (value) => { const n = value.replace(/\D/g, "").length; return n >= 12 && n <= 19; } });
  scan(CARD_LABELLED_WORLD_PATTERN, "card", { group: 1 });
  scan(CARD_WORD_RUN_PATTERN, "card", { group: 1 });
  // A few words after "credit card" — see CARD_NEAR_LABEL_PATTERN.
  scan(CARD_NEAR_LABEL_PATTERN, "card", { group: 1 });
  scan(CARD_TWELVE_CUED_PATTERN, "card", { group: 1, accept: (value) => luhn(value) });
  // Sixteen bare digits that failed the check — see CARD_BARE_SIXTEEN_PATTERN.
  // An order, a ticket or an invoice says what the number is, and it stays.
  scan(CARD_BARE_SIXTEEN_PATTERN, "card", {
    accept: (value, before) => !/^(\d)\1+$/.test(value) && !/^1[5-8]/.test(value) && !BARE_SIXTEEN_REFERENCE.test(before ?? ""),
  });
  // Three digits joined to a card are its security code: "5829820619143277,
  // 395", "your 2113610009277549 or 476", "597, 5987448817889806" (ai4privacy
  // practice half: 101 of 252 CVVs in prose were missed, most of them so).
  for (let i = 0, n = found.length; i < n; i += 1) {
    if (found[i].kind !== "card") continue;
    const [start, end] = claimed[i];
    const after = CVV_AFTER_CARD.exec(scanText.slice(end, end + 40));
    const before = CVV_BEFORE_CARD.exec(scanText.slice(Math.max(0, start - 30), start));
    for (const [m, at] of [[after, end], [before, Math.max(0, start - 30)]] as const) {
      if (!m) continue;
      const s = at + m.index + m[0].indexOf(m[1]), e = s + m[1].length;
      if (overlaps(s, e)) continue;
      claim([s, e]);
      found.push({ kind: "card", value: text.slice(s, e) });
    }
  }
  // Before the postcode patterns: an IBAN opens with two letters and two
  // digits, which is also the head of a UK postcode.
  scan(SSN_PATTERN, "ssn", {
    // "call 011-44-1642" is the American international prefix and a British
    // number, and it is the shape of an SSN to the character. Real email is
    // full of them. The word in front is what tells them apart.
    // Structural, rather than a list of words that might precede one: a
    // Social Security number is three groups and stops. "011-44-1642-718309"
    // is an American international prefix, a country code and a British
    // number, and the first eleven characters of it are an SSN to the
    // letter. What gives it away is the fourth group.
    accept: (value, before) => {
      if (/\b(?:call|calling|phone|tel|telephone|fax|dial|ring|mobile|cell)\b[^.]{0,12}$/i.test(before ?? "")) return false;
      return true;
    },
  });
  // After the dashed form, so "123-45-6789" is claimed by its shape rather
  // than by a cue that may or may not be sitting in front of it.
  scan(SSN_CUED_PATTERN, "ssn", { group: 1 });
  // Before phones and postcodes: a cued licence or policy number can be all
  // digits, and whichever pattern claims the span first owns it.
  scan(PAN_PATTERN, "govid", { group: 1 });
  scan(ID_LABEL_AFTER_PATTERN, "govid", { group: 1, accept: (value) => /\d/.test(value) && !/^(?:19|20)\d\d$/.test(value) });
  scan(CVV_CUED_PATTERN, "card", { group: 1 });
  // The same code under a label in another language, or a few words from it.
  scan(CVV_LABELLED_PATTERN, "card", { group: 1 });
  scan(CVV_AFTER_PATTERN, "card", { group: 1 });
  // A form copied flat — see GLUED_FORM_ID_PATTERN. Before the cued scans,
  // which read "DNI:43828314CPoblació" on into the next field's name. Not a
  // date, though a US social security number is shaped like one.
  scan(GLUED_FORM_ID_PATTERN, "govid", {
    group: 1,
    accept: (value) => {
      const d = value.replace(/\D/g, "").length;
      return d >= 5 && value.length <= 26 && (/^\d{3}-\d{2}-\d{4}$/.test(value) || !/^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$/.test(value));
    },
  });
  // Portuguese and Brazilian labels — see PT_ID_CUED_PATTERN. Six digits at
  // least, and not a date or a year.
  scan(PT_ID_CUED_PATTERN, "govid", {
    group: 1,
    accept: (value) => (value.match(/\d/g) ?? []).length >= 6 && value.length <= 20 && !/^\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}$/.test(value) && !/^(?:19|20)\d\d$/.test(value),
  });
  // A NINO-shaped value under a social-security label, whatever its prefix.
  // Before the general labelled ID: that one stops at the last group with a
  // digit, so "NI number: QQ 12 34 56 C" lost its final letter, and a span
  // once claimed is kept (2026-11-04).
  scan(NINO_CUED_PATTERN, "govid", { group: 1 });
  for (const pattern of [CUED_ID_PATTERN, CUED_ID_ACRONYM_PATTERN]) scan(pattern, "govid", {
    group: 1,
    // A cue followed by prose is a sentence, not a number. Requiring a digit
    // is what separates "my passport 561234567" from "my passport expires
    // next year", whose "expires next" would otherwise be redacted.
    //
    // The length bounds replace the ones the pattern used to carry. They moved
    // here when the value stopped being a single run of "letters, digits,
    // spaces and hyphens": the old form counted characters and could not tell
    // the number from the words after it, so "policy number 88213 was
    // cancelled" redacted "88213 was cancelled" and the model was asked a
    // question with its verb missing. The pattern now only crosses a space
    // into another chunk that has a digit in it, and what is left to check is
    // the size.
    // A bare year is not an identifier: "DL 2024 conference" is an event, and
    // "the Passport Act 1950" is a statute.
    // A value that runs on past a colon into more digits is the start of
    // something longer ("Aadhaar 3123:4567:8909"), which its own pattern takes.
    accept: (value, before, after) => !/^:\d/.test(after ?? "") && /\d/.test(value) && value.replace(/\s/g, "").length >= 4 && value.length <= 24 && !/^(?:[A-Za-z]+\s+)?(?:19|20)\d\d$/.test(value) && !/^[A-Za-z][a-z]{2,}\s+\d/.test(value) && !/^[A-Z]{3,}\s+\d/.test(value)
      // A date is a date: "passport 12/05/2024" is when it expires.
      && !/^\d{1,2}\/\d{1,2}\/\d{2,4}$/.test(value)
      // "ein" in lower case is German's "a", not the US employer number: "Ich
      // besitze ein Samsung S10", "ein Text-2-Image Modell" (oasst2). And a
      // description is not the number: "Aadhaar is a 12-digit unique
      // identity number" (Dolly 15k).
      // A real number after it is still one: "hast du ein R8521964".
      && !(/(?<![\p{L}\p{N}])ein[ \t]*$/u.test(before ?? "") && (value.match(/\d/g) ?? []).length < 5)
      && !/^(?:an?|the)\s/i.test(value) && !/^\d+-digits?$/i.test(value)
      // A year and a month: "合同编号：DL202304" (WildChat).
      && !/^(?:19|20)\d\d(?:0[1-9]|1[0-2])$/.test(value)
      // After a comma, a list goes on as often as a number follows: "carry
      // their passport, Form I-94", "tireur1=license, tireur2" (Enron,
      // WildChat). Four digits at least, and one piece, there.
      && !(/,\s*$/.test(before ?? "") && ((value.match(/\d/g) ?? []).length < 4 || /\s/.test(value))),
  });
  scan(KR_PASSPORT_CUED_PATTERN, "govid", { group: 1 });
  // Aadhaar, PAN, passport and the rest under a Hindi or Telugu label.
  scan(ID_CUED_INDIC_PATTERN, "govid", {
    group: 1,
    accept: (value) => value.replace(/\s/g, "").length >= 6 && !/^(?:19|20)\d\d$/.test(value),
  });
  // Licence and passport numbers under a label in the benchmark's languages,
  // or a few words from it.
  scan(ID_DOC_CUED_PATTERN, "govid", {
    group: 1,
    accept: (value) => value.length <= 20 && !/^(?:19|20)\d\d$/.test(value) && !/^\d{1,2}-\d{1,2}-\d{2,4}$/.test(value) && !/^\d{4}-\d{2}-\d{2}$/.test(value),
  });
  // See CJK_ID_LABELLED_PATTERN: any shape under its label, with a digit
  // or eight letters.
  scan(CJK_ID_LABELLED_PATTERN, "govid", { group: 1, accept: (value) => /\d/.test(value) || value.length >= 8 });
  // See WORLD_ID_LABELLED_PATTERN: five digits or more, not a date.
  scan(WORLD_ID_LABELLED_PATTERN, "govid", {
    group: 1,
    accept: (value) => { const d = value.replace(/\D/g, "").length; return d >= 5 && value.length <= 26 && !/^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$/.test(value); },
  });
  // The label, some words, then the number — see WORLD_ID_NEAR_PATTERN.
  // Seven digits or more, and not a date.
  scan(WORLD_ID_NEAR_PATTERN, "govid", {
    group: 1,
    accept: (value) => { const d = value.replace(/\D/g, "").length; return d >= 7 && value.length <= 26 && !/^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$/.test(value); },
  });
  // A customer, client or employee number: letters and digits together, or
  // six digits or more, and not a year or a date.
  scan(CUSTOMER_ID_CUED_PATTERN, "govid", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "").length;
      if (!digits || value.length < 4 || value.length > 24) return false;
      if (/^(?:19|20)\d\d$/.test(value) || /^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
      return /[A-Za-z]/.test(value) ? digits >= 3 : digits >= 6;
    },
  });
  // The same in the other languages — see WORLD_RECORD_ID_PATTERN. A label
  // that names the number outright lets four digits alone through
  // ("Matricola 7731"), but not a year or a date.
  scan(WORLD_RECORD_ID_PATTERN, "govid", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "").length;
      if (value.length < 4 || value.length > 24) return false;
      if (/^(?:19|20)\d\d$/.test(value) || /^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$/.test(value)) return false;
      return /[A-Z]/.test(value) ? digits >= 3 : digits >= 4;
    },
  });
  // Insurance policy and claim numbers under their label — see
  // INSURANCE_ID_PATTERN. Four digits at least, and not a year or a date.
  scan(INSURANCE_ID_PATTERN, "govid", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "").length;
      if (value.length < 5 || value.length > 26 || digits < 4) return false;
      return !/^(?:19|20)\d\d$/.test(value) && !/^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$/.test(value);
    },
  });
  // Record numbers under the labels above does not know, and by their prefix
  // (2026-10-05, Gretel and Nemotron) — see RECORD_ID_LABELLED_PATTERN. The
  // same date and year checks; four digits or more, or letters and three.
  // A plate in groups first, so "BH 2547 FK" is one value — see
  // PLATE_LABELLED_PATTERN. Two digits or more, four to ten characters.
  scan(PLATE_LABELLED_PATTERN, "govid", {
    group: 1,
    accept: (value) => {
      const chars = value.replace(/[ -]/g, "");
      return chars.length >= 4 && chars.length <= 10 && /\d.*\d/.test(chars) && !/^(?:19|20)\d\d$/.test(chars);
    },
  });
  scan(RECORD_ID_LABELLED_PATTERN, "govid", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "").length;
      if (value.length < 5 || value.length > 30) return false;
      if (/^(?:19|20)\d\d$/.test(value) || /^\d{4}-\d{2}-\d{2}$/.test(value) || /^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$/.test(value)) return false;
      // "PLCB-EQ8P-LV1V" has two digits and is plainly a code.
      return /[A-Za-z]/.test(value) ? digits >= 3 || (digits >= 2 && value.length >= 8) : digits >= 4;
    },
  });
  scan(RECORD_ID_PREFIXED_PATTERN, "govid");
  scan(RECORD_ID_SHAPED_PATTERN, "govid");
  // See RECORD_REF_PATTERN: three digits or more, and not a year range.
  scan(RECORD_REF_PATTERN, "govid", {
    group: 1,
    accept: (value) => (value.match(/\d/g)?.length ?? 0) >= 3 && !/^[A-Z]+-(?:19|20)\d\d$/.test(value),
  });
  scan(USERNAME_QUOTED_PATTERN, "govid", { group: 2, accept: (value) => !USERNAME_NOT.test(value) });
  scan(SESSION_COOKIE_PATTERN, "secret", { group: 1, accept: (value) => /[A-Za-z]/.test(value) || value.length >= 12 });
  // A cookie and a user name said in a sentence — see COOKIE_SPOKEN_PATTERN
  // and USERNAME_SPOKEN_PATTERN. A user name with a digit, a dot or an
  // underscore is one. Letters only, it must be "is" one and be built on a
  // given name ("victormaya"), so "the username is invalid" is a sentence.
  scan(COOKIE_SPOKEN_PATTERN, "secret", { group: 1 });
  scan(USERNAME_SPOKEN_PATTERN, "govid", {
    group: 3,
    accept: (value, before) => {
      if (USERNAME_NOT.test(value) || isCommonLowercaseWord(value)) return false;
      if (/[\d._]/.test(value)) return true;
      if (!/(?:is|was)\s+$/.test(before ?? "")) return false;
      // A name at the start counts only when the rest is not a word ending:
      // "generated" opens with Gene. See WORD_ENDING_PATTERN.
      const wordy = WORD_ENDING_PATTERN.test(value);
      for (let i = 4; i <= value.length - 2; i++) {
        if (GIVEN_NAMES.has(value.slice(value.length - i))) return true;
        if (!wordy && GIVEN_NAMES.has(value.slice(0, i))) return true;
      }
      return false;
    },
  });
  scan(MY_NUMBER_IS_PATTERN, "govid", { group: 1, accept: (value) => /\d/.test(value) && /[A-Za-z]/.test(value) });
  // See ID_POSSESSIVE_PATTERN and ID_UPPER_TOKEN_PATTERN.
  // Each only when the message has a run of digits long enough to need it:
  // most messages have none, and these are tried at every position.
  const hasTwoDigits = /\d\D{0,13}\d/.test(scanText);
  if (hasTwoDigits) {
    scan(CH_UID_PATTERN, "govid");
    scan(EU_VAT_PATTERN, "govid");
    scan(FR_TAX_GROUPED_PATTERN, "govid");
    scan(FR_PASSPORT_PATTERN, "govid");
    // See VAT_CUED_PATTERN, JA_ACCOUNT_PATTERN and ES_PHONE_PATTERN.
    scan(VAT_CUED_PATTERN, "govid", { group: 1, accept: (value) => { const d = value.replace(/\D/g, "").length; return d >= 8 && d <= 14; } });
    // A business's registration number under its label — see BUSINESS_ID_LABELLED_PATTERN.
    scan(BUSINESS_ID_LABELLED_PATTERN, "govid", {
      group: 1,
      accept: (value) => {
        const d = value.replace(/\D/g, "").length;
        return /^[0-9A-Z]{18}$/.test(value) ? /[A-Z]/.test(value) || d === 18 : d >= 7 && d <= 14 && !/^\d{1,2}[./-]\d{1,2}[./-]\d{2,4}$/.test(value);
      },
    });
    // An identity number as a key in a log line — see ID_LOG_KEY_PATTERN.
    scan(ID_LOG_KEY_PATTERN, "govid", {
      group: 1,
      accept: (value) => {
        const d = value.replace(/\D/g, "").length;
        return d >= 8 && d <= 16 && !/^\d{4}-\d{2}-\d{2}/.test(value);
      },
    });
    scan(JA_ACCOUNT_PATTERN, "iban", { group: 1 });
    scan(ES_PHONE_PATTERN, "phone", { group: 1 });
    // Eight digits alone are left to ACCOUNT_BARE_PATTERN, which takes them
    // as an account wherever they stand.
    scan(ID_POSSESSIVE_PATTERN, "govid", { group: 1, accept: (value) => idLike(value, true) && !/^\d{8}$/.test(value) });
    // Not a package id on an install line: "winget install 9NQ7512CXL7T".
    scan(ID_UPPER_TOKEN_PATTERN, "govid", { group: 1, accept: (value, before) => idLike(value, false) && !PACKAGE_COMMAND_PATTERN.test(before ?? "") });
    // See CN_RESIDENT_ID_PATTERN. A birth year not after this one.
    scan(CN_RESIDENT_ID_PATTERN, "govid", { group: 1, accept: (value) => Number(value.slice(6, 10)) <= new Date().getUTCFullYear() });
    // See ID_SANDWICH_PATTERN. Not a chip, a standard or a hardware part.
    scan(ID_SANDWICH_PATTERN, "govid", {
      group: 1,
      // Nor a size in a log, "57435322K"; nor counting digits, a placeholder;
      // nor what a part, a ticket or an order number says it is.
      accept: (value, before) => idLike(value, true) && !/^(?:KB|CVE|ISO|EN|IEC|SKU|PO|SN|RFC)\d/.test(value) && !PACKAGE_COMMAND_PATTERN.test(before ?? "")
        && !/^\d+[KMGTB]$/.test(value) && !"01234567890123456789".includes(value.replace(/^[A-Z]+|[A-Z]+$/g, "").slice(0, 7))
        && !/\b(?:part|ticket|order|item|model|sku|serial|product|invoice|ref(?:erence)?|tracking|booking)\s*(?:no\.?|number|#|id)?\s*[:#]?\s*$/i.test(before ?? ""),
    });
    // See PASSPORT_SHAPE_PATTERN: patents, Windows updates, CVEs and the
    // like have the shape and a prefix that gives them away.
    scan(PASSPORT_SHAPE_PATTERN, "govid", {
      group: 1,
      // And a Unicode escape, "\U00000394" (Python's documentation).
      accept: (value, before) => !/^(?:US|EP|WO|JP|CN|KR|DE|GB|FR|KB|PR|PO|SO|SN|RFC|ISO|IEC|EN|TX|RX|CU|ID)\d/.test(value) && !/^[A-Z]{1,2}(\d)\1+$/.test(value) && !/^[A-Z]{1,2}0+$/.test(value)
        && !(/^U0{3}/.test(value) || /\\$/.test(before ?? ""))
        // Counting digits are a placeholder ("V1234567 is my version tag"),
        // and a room or a gate is a place (redaction.eval).
        && !"0123456789".includes(value.replace(/^[A-Z]+/, "").slice(0, 7)) && !NOT_A_STREET_PATTERN.test((before ?? "").split(/\s+/).slice(-2).join(" ")),
    });
  }
  // After CUED_ID_PATTERN, not before it.
  //
  // "Account number 1234 5678 9012" was already found, as a cued identifier,
  // and scanning this first took the span and relabelled it — the value was
  // still redacted but the kind changed, and a policy written against govid
  // stopped seeing it. Nothing that already worked is reclassified; this
  // picks up only the forms the cued-identifier pattern never matched,
  // where the bare word "account" is the whole cue.
  // Twice, for the two groups: "make sure 70416002 and 40687381 have
  // updated" names a pair off one cue, and taking the first while leaving
  // the second is the half-a-door problem again.
  for (const group of [1, 2]) scan(ACCOUNT_CUED_PATTERN, "iban", {
    group,
    // Six digits is a reference; eight is an account. The upper bound keeps
    // it from swallowing a run of figures that happens to follow the cue.
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 6 && digits.length <= 18;
    },
  });
  // See ACCOUNT_PAYMENT_PATTERN. Not a year, a date or a time in a log.
  if (/\d{6}/.test(scanText)) scan(ACCOUNT_PAYMENT_PATTERN, "iban", {
    group: 1,
    accept: (value) => !/^(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:[0-3]\d)?$/.test(value) && !/^(\d)\1+$/.test(value),
  });
  // An account number with letters in it, or under a label in another
  // language. Eight digits at least: fewer is a reference, not an account.
  scan(ACCOUNT_CUED_INTL_PATTERN, "iban", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "").length;
      return digits >= 8 && value.replace(/[ -]/g, "").length <= 34 && !/^(?:19|20)\d{6}$/.test(value);
    },
  });
  // See ACCOUNT_CUED_WORLD_PATTERN: eight digits or more, and not a date.
  scan(ACCOUNT_CUED_WORLD_PATTERN, "iban", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "").length;
      return digits >= 8 && digits <= 34 && !/^(?:19|20)\d{6}$/.test(value) && !/^\d{1,4}[ -]\d{1,2}[ -]\d{1,4}$/.test(value);
    },
  });
  // A routing or bank code under its label in another language.
  scan(ROUTING_CUED_INTL_PATTERN, "iban", { group: 1 });
  // The cued bank account, after the identifier pattern — see the note there.
  scan(IBAN_CUED_PATTERN, "iban", { group: 1 });
  scan(IBAN_SHAPED_PATTERN, "iban");
  // The bank code that travels with it, only where "BIC" or "SWIFT" says so.
  scan(BIC_CUED_PATTERN, "iban", { group: 1 });
  // And under the longer labels business paperwork uses, where the country
  // in the code is what tells it from a capitalised word.
  scan(BIC_LABELLED_PATTERN, "iban", { group: 1, accept: (value) => ISO_COUNTRY_CODES.has(value.slice(4, 6)) });
  // And with no label at all: see BIC_BARE_PATTERN. Never a word, and never
  // in text that is shouting ("PLEASE TRANSFER THE DEPOSIT"), where capitals
  // are the whole sentence.
  if (BANKING_CONTEXT.test(scanText)) scan(BIC_BARE_PATTERN, "iban", {
    group: 1,
    accept: (value, before, after) => ISO_COUNTRY_CODES.has(value.slice(4, 6))
      && !(/^[A-Z]+$/.test(value) && (isCommonLowercaseWord(value.toLowerCase()) || COMMON_CAPITALISED.has(value[0] + value.slice(1).toLowerCase())))
      && !/\b[A-Z]{4,}\b[^a-z]{0,20}$/.test(before ?? "") && !/^[^a-z]{0,20}\b[A-Z]{4,}\b/.test(after ?? "")
      // Letters alone are also every word in capitals ("UNSUBSCRIBE",
      // "FILENAME", "PORTLAND" — Enron, the Kubernetes docs), so they need
      // an IBAN or a bank code's own name beside them; a digit in the place
      // or branch, or the XXX of a head office, is evidence enough.
      && (/\d|XXX$/.test(value.slice(6)) || NEAR_A_BANK_CODE.test(`${before ?? ""} ${after ?? ""}`)),
  });
  // National identity numbers that prove themselves — before the phone and
  // SSN patterns, which would otherwise take their digits by shape.
  scan(BR_CNPJ_PATTERN, "govid", { accept: brazilCnpj });
  scan(BR_CPF_PATTERN, "govid", { accept: brazilCpf });
  // Without its dots, eight digits, a dash and a digit is a shape many
  // references share: then it needs a K, or RUT or RUN just before it.
  scan(CL_RUT_PATTERN, "govid", {
    accept: (value, before) => chileRut(value) && (value.includes(".") || /k$/i.test(value) || /\bRU[TN]\b[^\n]{0,20}$/i.test(before ?? "")),
  });
  scan(MX_CURP_PATTERN, "govid", { accept: mexicoCurp });
  scan(SG_NRIC_PATTERN, "govid", { accept: singaporeNric });
  scan(HK_ID_PATTERN, "govid", { accept: hongKongId });
  scan(CN_RIC_PATTERN, "govid", { accept: chinaRic });
  scan(IE_PPS_PATTERN, "govid", { accept: irishPps });
  scan(FR_NIR_PATTERN, "govid", { accept: frenchNir });
  scan(BE_NN_PATTERN, "govid", { accept: belgianNn });
  // Malaysia's MyKad number, YYMMDD-PB-NNNN, on its birth date.
  scan(MY_NRIC_PATTERN, "govid", { accept: (value) => validDate(Number(value.slice(0, 2)), Number(value.slice(2, 4)), Number(value.slice(4, 6))) });
  // Pakistan's CNIC, 5-7-1, opening with a province digit.
  scan(PK_CNIC_PATTERN, "govid", { accept: (value) => /^[1-7]/.test(value) && !/^(\d)\1{4}-\1{7}-\1$/.test(value) });
  scan(CZ_RC_PATTERN, "govid", { accept: czechRc });
  scan(PT_CC_PATTERN, "govid", { accept: portugueseCc });
  scan(MU_NID_PATTERN, "govid", { accept: mauritiusNid });
  scan(ES_NIE_LOWER_PATTERN, "govid", { accept: spanishId });
  scan(UK_DL_PATTERN, "govid");
  scan(IT_CF_PATTERN, "govid");
  scan(US_MBI_PATTERN, "govid");
  scan(DE_SVNR_PATTERN, "govid", { accept: germanSvnr });
  scan(PH_CRN_PATTERN, "govid", { accept: (value) => !/^(\d)\1*-\1+-\1$/.test(value) });
  scan(IN_PAN_PATTERN, "govid");
  scan(UK_NINO_PATTERN, "govid");
  scan(FI_HETU_PATTERN, "govid", { accept: finnishId });
  // A Java GC log is a row of sizes in kilobytes, "57435641K->57435322K(…)",
  // and one in 23 of them passes the DNI's check letter (Dolly 15k).
  scan(ES_ID_PATTERN, "govid", { accept: (value, before, after) => spanishId(value) && !(/[KMG]$/i.test(value) && (/(?:->|\()$/.test(before ?? "") || /^(?:->|\()/.test(after ?? ""))) });
  scan(KR_RRN_PATTERN, "govid", { accept: koreanId });
  scan(SE_PNR_PATTERN, "govid", { accept: swedishId });
  // Thirteen digits after "=" or a decimal point are a value in a log, not a
  // Thai or South African ID: "TotalDetailSteps=1514040240000" is a time in
  // milliseconds, "16:16:01.530 28601 28601" a time, a pid and a thread
  // (Loghub). One in ten passes the check digit.
  const notALogValue = (before?: string) => !/(?:=|\d\.)[ \t]*$/.test(before ?? "");
  scan(TH_TNIN_PATTERN, "govid", { accept: (value, before) => thaiId(value) && notALogValue(before) });
  scan(ZA_ID_PATTERN, "govid", { accept: (value, before) => southAfricanId(value) && notALogValue(before) });
  scan(ELEVEN_DIGITS_PATTERN, "govid", { accept: elevenDigitId });
  scan(IN_AADHAAR_PATTERN, "govid", { accept: aadhaar });
  scan(AU_MEDICARE_PATTERN, "govid", { accept: medicare });
  // Not when the sentence has just said it is a phone number: "Mi número de
  // teléfono es 612 345 678" passes the check digit by chance, and taken as an
  // ID it went out with an ID-shaped stand-in where the model expected a phone.
  // Left for the phone labels further down.
  scan(GROUPED_ID_PATTERN, "govid", { accept: (value, before) => groupedId(value) && !PHONE_WORD_BEFORE.test(before ?? "") });
  scan(SSN_CUED_LOOSE_PATTERN, "ssn", {
    group: 1,
    // A cue followed by a date or a short reference is not a number anybody
    // is protecting. Nine digits is the American shape; the corpus's Swiss
    // and stripped forms are eleven and twelve.
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 8 && digits.length <= 14;
    },
  });
  scan(SSN_CUED_INTL_PATTERN, "ssn", { group: 1 });
  scan(CH_SSN_PATTERN, "ssn");
  scan(CH_SSN_BARE_PATTERN, "ssn");
  scan(SSN_SPACED_PATTERN, "ssn");
  scan(PHONE_PATTERN, "phone", { accept: (value, before, after) => notAReference(value, before) && plausiblePhone(value, before, after) });
  // A number the sentence calls a phone number.
  //
  // PHONE_PATTERN knows the shapes people write in Britain and America. The
  // rest of the world writes "(95)-5544-2455", "0371-52754478",
  // "07-03-39-19.17" and "3243.564-0066", and a pattern loose enough to take
  // all of those by shape alone would also take every account number and
  // order reference in the document. The word in front is the evidence, as
  // it is for accounts and for named identifiers.
  scan(PHONE_LABEL_AFTER_PATTERN, "phone", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 7 && digits.length <= 16;
    },
  });
  // The pattern does not end on a short group with a letter or "/" after it:
  // "call 020 7946 0142 24/7" leaves the opening hours out. Only a short group
  // after a space, so "Contact 35-279711-494655-6for" (a missing space) keeps
  // its last digit.
  scan(PHONE_CUED_PATTERN, "phone", {
    group: 1,
    // Seven digits is the shortest thing anybody calls; sixteen is the
    // longest international number plus its separators.
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 7 && digits.length <= 16;
    },
  });
  // Under a label or a verb in the benchmark's other languages. A date is
  // not a phone number: "Telefon: 12.03.2024" is a form left half filled.
  scan(PHONE_CUED_INTL_PATTERN, "phone", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 7 && digits.length <= 16 && !/^\d{1,4}[./-]\d{1,2}[./-]\d{2,4}$/.test(value.trim());
    },
  });
  // The same in the rest of the languages (PHONE_CUED_WORLD_PATTERN), and the
  // groupings that are a phone's alone (PHONE_NATIONAL_SHAPED_PATTERN).
  scan(PHONE_CUED_WORLD_PATTERN, "phone", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 7 && digits.length <= 16 && !/^\d{1,4}[./-]\d{1,2}[./-]\d{2,4}$/.test(value.trim());
    },
  });
  if (hasTwoDigits) scan(PHONE_NATIONAL_SHAPED_PATTERN, "phone", { group: 1 });
  // See PHONE_SMALL_CUE_PATTERN: a phone's shape, since the cue proves little.
  if (hasTwoDigits) scan(PHONE_SMALL_CUE_PATTERN, "phone", {
    group: 1,
    accept: (value, before, after) => {
      const v = value.trim();
      const digits = v.replace(/\D/g, "");
      const separators = (v.match(/[ ./-]/g) ?? []).length;
      return digits.length >= 8 && digits.length <= 15 && (/^[+(]/.test(v) || separators >= 2)
        && !/^\d{1,4}[./-]\d{1,2}[./-]\d{2,4}/.test(v) && !/^\d{4}-\d{2}-\d{2}/.test(v)
        // Judged without its plus: "+61.38.625.4974" is a phone written with
        // points, which plausiblePhone reads as a float ("+3.140000") alone.
        && !/^\d{1,3}(?:[.,]\d{3})+(?:[.,]\d+)?$/.test(v) && plausiblePhone(v.replace(/^\+/, ""), before, after)
        // "AU (740.7–816.4 million km)" is an astronomical unit and a range
        // (Dolly 15k): the cue is a lower-case word, and no phone has a
        // single digit after a point or runs into a dash.
        && !/(?<![\p{L}])(?:AU|LE|IL|AL)[ \t]*$/u.test(before ?? "") && !/\.\d(?!\d)/.test(v) && !/^[–—]/.test(after ?? "");
    },
  });
  // The same under a Hindi or Telugu label.
  scan(PHONE_CUED_INDIC_PATTERN, "phone", {
    group: 1,
    accept: (value) => {
      const digits = value.replace(/\D/g, "");
      return digits.length >= 7 && digits.length <= 16 && !/^\d{1,4}[./-]\d{1,2}[./-]\d{2,4}$/.test(value.trim());
    },
  });
  scan(PHONE_SHORT_CUED_PATTERN, "phone", {
    group: 2,
    accept: (value, before) => {
      const d = value.replace(/\D/g, "");
      if (d.length < 4 || d.length > 7) return false;
      // "call me at 1030": four digits after "at" that read as a time.
      return !(/\bat\s+$/.test(before ?? "") && d.length <= 4 && Number(d.slice(-2)) < 60 && Number(d.slice(0, -2)) <= 23);
    },
  });
  // See PHONE_TRUNK_PATTERN: nine to eleven digits with the trunk zero, a
  // phone word within a few words before it — or a number and "or" right
  // before it, the second of two — and not a date.
  scan(PHONE_TRUNK_PATTERN, "phone", {
    accept: (value, before) => {
      const d = value.replace(/\D/g, "");
      if (d.length < 9 || d.length > 11) return false;
      if (/^\d{2}[-. ]\d{2}[-. ](?:19|20)\d{2}$/.test(value) || /^\d{4}[-. ]\d{2}[-. ]\d{2}$/.test(value)) return false;
      const b = before ?? "";
      return /\b(?:call|calls|calling|phone|tel|telephone|ph|mob|mobile|cell|fax|hotline|helpline|contact|contactable|reach|reached|ring|text|whatsapp|téléphone|telefon|telefone|teléfono|telefono)\b[^.\n\d]{0,30}$/i.test(b)
        || /\d[\d)]*\s*(?:or|,|\/)\s*$/.test(b);
    },
  });
  // See PHONE_MIXED_PATTERN: a plus, or two kinds of separator, and not a
  // date written with a time after it.
  scan(PHONE_MIXED_PATTERN, "phone", {
    accept: (value) => {
      const d = value.replace(/\D/g, "");
      if (d.length < 9 || d.length > 14) return false;
      if (/^(?:19|20)\d\d[.\-\/ ]\d{1,2}[.\-\/ ]\d{1,2}\b/.test(value) || /^\d{1,2}[.\-\/ ]\d{1,2}[.\-\/ ](?:19|20)?\d\d\b/.test(value)) return false;
      // An address and a port, or an amount in thousands: "192.168.1.1 4000",
      // "1 234 567.8901".
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(value) || /^\d{1,3}(?:[ .]\d{3})+[.,]\d+$/.test(value)) return false;
      const seps = new Set(value.replace(/^\+/, "").match(/[ .\-]/g) ?? []);
      return value.startsWith("+") ? /[.\-]/.test(value) : seps.size >= 2;
    },
  });
  // The pairs only with two kinds of separator, which a list of numbers or
  // a draw does not mix, and not climbing like one: "01 02 03-04 05".
  scan(PHONE_ZERO_GROUPS_PATTERN, "phone", {
    accept: (value) => {
      const pairs = /^0[1-9](?:[ .\-]\d{2}){4}$/.test(value) ? value.split(/[ .\-]/).map(Number) : null;
      if (!pairs) return true;
      return new Set(value.match(/[ .\-]/g)).size >= 2 && !pairs.every((n, i) => i === 0 || n > pairs[i - 1]);
    },
  });
  // Before the postcode patterns, so a full address is taken as one value
  // rather than being carved into a street and a code that no longer agree.
  scan(PO_BOX_PATTERN, "address");
  scan(JP_ADDRESS_PATTERN, "address");
  scan(JP_ROMAJI_ADDRESS_PATTERN, "address");
  scan(MILITARY_ADDRESS_PATTERN, "address");
  scan(MILITARY_SHIP_PATTERN, "address");
  // A year in front of a name is an event when the name goes on, or carries
  // an acronym: "the 2018 UCI Track Cycling World Championships", "the 2019
  // Indian Wells Masters", "the 2010 Banff Mountain Film Festival" (Dolly
  // 15k). "2018 Maple Track" ending its phrase is still a street.
  // The rest are from the same real prompts (oasst2, Dolly 15k): "the 1989
  // Tiananmen Square protests", "In 2013, Dick's Drive-In", a rank and a
  // population in a table ("12 Aveyron Rodez Aveyron River 279,206"), "on
  // the Porce River 90 kilometres", "in Microgravity Dr. Michael Chang",
  // "in Google Drive".
  const addressAccept = (value: string, before?: string, after?: string): boolean => {
      const next = after ?? "";
      if (!notACourt(value)) return false;
      // A year and a verb is a street only when its word is a street's own:
      // "1934 Barud Deshgaon Road will be closed", but "in 2004 State Security
      // Courts were abolished" (TAB) is history.
      const roadWord = /\b(?:Street|Road|Avenue|Lane|Drive|Boulevard|Way|Highway|St|Rd|Ave|Ln|Dr|Blvd)\.?$/.test(value);
      if (/^(?:19|20)\d\d\s/.test(value) && (/^[ \t]+\p{Lu}/u.test(next) || /\s[A-Z]{3,}\s/.test(value)
        || /^[ \t]+\p{Ll}/u.test(next) && !(/^[ \t]+(?:in|at|on|near|and|or|from)\b/.test(next) || (roadWord && /^[ \t]+(?:is|was|are|were|will|would|has|had|can|may|should)\b/.test(next))))) return false;
      // A decade, and a Wi-Fi standard: "2020s Mel Brooks-style", "802.11a Access Point" (WildChat, Enron).
      if (/^(?:19|20)\d0s\s/.test(value) || /\d\.$/.test(before ?? "")) return false;
      if (/^(?:19|20)\d\d,/.test(value) && /(?:\b(?:in|since|by|until|from|of|jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec|january|february|march|april|june|july|august|september|october|november|december)\.?|\d)[ \t,]*$/i.test(before ?? "")) return false;
      if (/^,?[ \t]+\d{1,3}(?:,\d{3})+(?!\d)/.test(next)) return false;
      // A street the whole world knows by name, with no number on it, is a
      // landmark or a byword, not where somebody lives: "the Wall Street
      // Journal", "10 minutes from Times Square", "the Fertile Crescent".
      // A compass point makes it somebody's again: "Main Street E, 53594".
      if (!/^\d/.test(value) && FAMOUS_STREETS.test(value) && !/^[ \t]+[NSEW]{1,2}\b/.test(next) && !/\b[NSEW]\s+\S+\s+\S+$/.test(value)) return false;
      // A numbered list: "6 Electronics 7 Real Estate 8 Corporates" (WildChat).
      if (/^\d{1,2}\s/.test(value) && /^\s+\d{1,2}[ \t]+\p{Lu}/u.test(next)) return false;
      if (/\d$/.test(value) && /^[ \t]*(?:km|mi|miles?|kilomet(?:er|re)s?|met(?:er|re)s?|feet|ft|days?|weeks?|months?|years?|hours?|minutes?)\b/.test(next)) return false;
      if (!/^\d/.test(value) && /\b(?:Dr|St)$/.test(value) && /^\.[ \t]+\p{Lu}\p{Ll}+[ \t]+\p{Lu}/u.test(next)) return false;
      return !/^(?:Google|One|Hard|Disk|Flash|USB|Thumb|Network|Shared|Team|Test)\s+Drive$/.test(value);
  };
  scan(ADDRESS_PATTERN, "address", { accept: addressAccept });
  // Its two branches for other languages, only where there is one to read.
  if (HAS_NON_LATIN.test(scanText)) scan(ADDRESS_NON_LATIN_PATTERN, "address", { accept: addressAccept });
  // A house and its street in Hindi, Bengali, Telugu, Tamil, Urdu, Arabic
  // and Thai — see SOUTH_ASIAN_ADDRESS_PATTERN.
  scan(SOUTH_ASIAN_ADDRESS_PATTERN, "address", { lines: HAS_SOUTH_ASIAN_OR_ARABIC });
  if (HAS_STREET_CUE_INTL.test(scanText)) scan(ADDRESS_INTL_CUED_PATTERN, "address", { accept: addressAccept });
  // A street in its own language's words — see WORLD_STREET_PATTERN. Not a
  // bare year for its number ("Via Crucis 2025"), unless a flat follows.
  // Nor English's "via" and "place" before a month, an acronym or a word
  // that is no street's: "via IP 81.202…", "take place January 16", "via
  // Royal Decree 1066/2001" (WildChat, multilingual).
  scan(WORLD_STREET_PATTERN, "address", {
    accept: (value, before, after) => {
      if (!addressAccept(value, before, after) || /(?:^|\s)(?:1[5-9]|20)\d\d\.?$/.test(value)) return false;
      const first = value.match(/^(?:\d[\w ]*?\s)?\S+\s+(?:(?:de|del|della|dei|di|da|do|du|des|la|le|DE|DEL|DA|DO|DOS|DAS|LA|LOS|LAS)\s+)?(\S+)/u)?.[1] ?? "";
      return !/^\p{Lu}{2,4}$/u.test(first) && !NOT_A_STREET_NAME.has(first.replace(/[.,]$/, ""));
    },
  });
  // Shapes the street rules above do not reach — see redactionAddressWorld.
  // Each on the lines that have its anchor: see linesWhere.
  scan(PH_BARANGAY_PATTERN, "address", { lines: HAS_BARANGAY });
  // Lower case after the word "address" ("address 45 nehru st"), unless the
  // words before the street word are a sentence's.
  scan(IN_LOWER_ADDRESS_PATTERN, "address", {
    lines: /addr|adress|vilasam|pata/i,
    accept: (value) => value.replace(/^[\d/-]+[A-Za-z]?,?\s+/, "").split(/[\s,]+/).slice(0, -1).every((w) => !IN_NOT_A_STREET.test(w)),
  });
  scan(VN_NUMBER_FIRST_PATTERN, "address", { lines: /đường|phố|ngõ|hẻm|ngách/i });
  // Its two numbers are Czech enough on their own; a bare "-ova" number needs
  // a Czech or Slovak letter in the message. Not a season: "Sezóna 2024/25".
  const czech = HAS_CZECH_SLOVAK.test(scanText);
  scan(CS_STREET_PATTERN, "address", {
    lines: /\d\/\d|ova[ \t]+\d/,
    accept: (value) => (czech || value.includes("/")) && !/\s(?:19|20)\d\d\/\d\d$/.test(value),
  });
  scan(EL_STREET_PATTERN, "address", { lines: /[Ͱ-Ͽ]/ });
  const huLines = /[1-9]\d{3}[ \t]+\p{Lu}\p{Ll}+(?:-\p{Lu}?\p{Ll}+)?,/u;
  scan(HU_TOWN_FIRST_PATTERN, "address", { group: 2, lines: huLines });
  // Checked word by word, not only the first: "Heathrow Terminal 5" is an
  // airport, "WeWork 3" a brand (a capital inside a word, which a street
  // name has only after Mc or Mac), "Pier 39" and "Lot 14" places.
  scan(ADDRESS_CUED_PATTERN, "address", {
    accept: (value) => notACourt(value) && !NOT_A_STREET_PATTERN.test(value) && !/(?<!\bMa?c)[a-z][A-Z]/.test(value),
  });
  // See WEAK_STREET_CUED_PATTERN: the name in front must read as a person's.
  scan(WEAK_STREET_CUED_PATTERN, "address", {
    group: 1,
    // A compass word opens a town's name: "bei South Bend (Indiana)".
    accept: (value) => !NOT_A_STREET_PATTERN.test(value) && value.split(/\s+/).slice(0, -1).every((w) => personal(w) && !/^(?:North|South|East|West|New|Old|Upper|Lower|Great|Little)$/.test(w)),
  });
  // A street under a label that says it is one, in the benchmark's seven
  // languages, whatever its street word — unless the label is a machine's.
  scan(ADDRESS_LABELLED_PATTERN, "address", {
    group: 1,
    // "resident at No. 25" is a house the text has already named, and a
    // number with nothing of the street in it.
    accept: (value, before) => !/^(?:No|Nr|Nos|Number|Nº)\.?[ \t]*\d/i.test(value) && !ADDRESS_LABEL_NOT_A_STREET.test((before ?? "").replace(/[\s:=>"'*]*(?:address|addr|adresse?|adres)[\s:=>"'*]*$/i, "")),
  });
  // Both streets of a corner, each on the cue's word: see CORNER_PATTERN.
  // A side is a name, not a clause: "the northwest corner of Wyoming and
  // extending into Montana and Idaho" is geography (Dolly 15k).
  const cornerSide = (value: string) => /[\p{Lu}\d]/u.test(value) && !/^(?:the|a|an|my|our|your|his|her|their|this|that)\b/i.test(value)
    // Two lower-case words: one is a street word in some language ("Csabai
    // kapu 39", "rue de pologne"), two are a sentence.
    && !/(?:^|\s)(?:and|or)\s/.test(value) && (value.match(/(?:^|\s)\p{Ll}{4,}/gu) ?? []).length < 2;
  scan(CORNER_PATTERN, "address", { group: 1, accept: cornerSide });
  // The second side only when the first is a street too: "the corner of
  // the room and Sarah laughed" is furniture and a person.
  scan(CORNER_PATTERN, "address", {
    group: 2,
    accept: (value, before) => {
      // The first side as far as the window reaches back: a long one is cut
      // short, and still says whether it was a name or a clause.
      const first = (before ?? "").split(/[Cc]orner\s+of\s+/).pop()!.replace(/[ \t]+(?:and|&)[ \t]+$/, "");
      return cornerSide(value) && !/[Cc]orner\s+of\s+(?:the|a|an|my|our|your|his|her|their|this|that)\s[^\n]*$/.test(before ?? "") && cornerSide(first);
    },
  });
  scan(CORNER_SECOND_PATTERN, "address", { group: 1, accept: cornerSide });
  scan(JP_POSTCODE_PATTERN, "postcode", { group: 1 });
  scan(UK_POSTCODE_PATTERN, "postcode");
  scan(CA_POSTCODE_PATTERN, "postcode");
  scan(AU_POSTCODE_PATTERN, "postcode", { group: 1 });
  scan(EIRCODE_PATTERN, "postcode", { group: 1 });
  scan(NL_POSTCODE_PATTERN, "postcode", { group: 1 });
  scan(POSTCODE_GLUED_PATTERN, "postcode", { group: 1 });
  // A year is not a postcode, whatever letters follow it ("in 1945 VE Day").
  scan(NL_POSTCODE_ALONE_PATTERN, "postcode", { group: 1, accept: (value) => !/^(?:1[89]|20)\d\d\b/.test(value) });
  scan(EU_POSTCODE_PATTERN, "postcode", { group: 1 });
  scan(HU_TOWN_FIRST_PATTERN, "postcode", { group: 1, lines: huLines });
  scan(ES_ROAD_PATTERN, "address", { accept: (value) => !ES_ROAD_FAMOUS.test(value) });
  scan(IT_FR_ROAD_PATTERN, "address", { accept: (value) => !IT_FR_ROAD_FAMOUS.test(value) });
  scan(DE_NL_STREET_TOWN_PATTERN, "address");
  scan(PT_STREET_NUMERO_PATTERN, "address");
  if (HAS_BARANGAY.test(scanText)) scan(PH_POSTCODE_PATTERN, "postcode", { group: 1 });
  scan(IN_PIN_PATTERN, "postcode", { group: 1, lines: /addr|adress|pin|vilasam/i });
  if (HAS_INDIC.test(scanText)) {
    scan(IN_PIN_INDIC_PATTERN, "postcode", { group: 1 });
    scan(IN_STREET_INDIC_PATTERN, "address");
  }
  // Before the state-anchored form, so a ZIP+4 that does have a state in
  // front of it is still claimed once, as the whole nine digits.
  scan(US_ZIP_PLUS4_PATTERN, "postcode");
  // Before the state-anchored form: these have no state, which is the point.
  scan(ZIP_BESIDE_ADDRESS_PATTERN, "postcode", { group: 1 });
  scan(ZIP_BESIDE_ADDRESS_PATTERN, "postcode", { group: 2 });
  // The state follows a place: "Reno NV 89501". "[PR 57758]" is a pull request.
  scan(US_ZIP_PATTERN, "postcode", { group: 1, accept: (_value, before) => /[A-Za-z][A-Za-z]+,?\s+[A-Z]{2}\s+$/.test(before ?? "") });
  scan(US_ZIP_AFTER_STATE_COMMA_PATTERN, "postcode", { group: 1 });
  scan(ZIP_AFTER_PLACE_PATTERN, "postcode", { group: 1 });
  // Before the ZIP rule, which would take "40301" of Brazil's "40301-110".
  scan(POSTCODE_LABELLED_PATTERN, "postcode", { group: 1, accept: (value) => /\d/.test(value) });
  // The label glued to the field before it — see POSTCODE_LABEL_GLUED_PATTERN.
  scan(POSTCODE_LABEL_GLUED_PATTERN, "postcode", { group: 1 });
  scan(POSTCODE_LABEL_GLUED_PATTERN, "postcode", { group: 2 });
  // Taiwan's three or five digits run into the city ("110台北市信義區",
  // "40354台中市"), and Korea's five follow the address in brackets
  // ("…12길 34, 302호 (03995)"). realistic5, 2026-10-24.
  scan(TW_POSTCODE_BEFORE_CITY_PATTERN, "postcode", { group: 1 });
  scan(KO_POSTCODE_AFTER_ADDRESS_PATTERN, "postcode", { group: 1 });
  scan(US_ZIP_CUED_PATTERN, "postcode", { group: 1 });
  // Three digits at least: "postal code 53-320" is Polish, "zip 12" is a quantity.
  scan(POSTCODE_CUED_INTL_PATTERN, "postcode", { group: 1, accept: (value) => value.replace(/\D/g, "").length >= 3 });
  scan(COUNTRY_POSTCODE_PATTERN, "postcode", { group: 1 });
  scan(PLACE_POSTCODE_PATTERN, "postcode", {
    group: 2,
    accept: (value, before) => {
      const town = (before ?? "").split(/\bin[ \t]/).pop()?.trim() ?? "";
      if (/^(?:19|20)\d\d$/.test(value) || NOT_A_STREET_PATTERN.test(town)) return false;
      // A town does not run across a full stop: "in Portuguese. In 1516," is
      // two sentences and a year (Dolly 15k). "St. Gallen 9000" still may.
      if (/\p{Ll}{3,}\.\s/u.test(town)) return false;
      return !/^\d{4}$/.test(value) || /\s/.test(town) || /^\p{Lu}{4,}$/u.test(town);
    },
  });
  // Last. Every pattern above is more specific, and a host is the one thing
  // here that can contain another — an internal address with a port and a path
  // sits next to all sorts of things, and whatever claimed its span first
  // should keep it.
  // Before the host patterns: an IPv6 address contains colons and hex runs
  // that a hostname pattern will happily carve up.
  // 2001:db8::/32 is reserved for documentation (RFC 3849) and routes nowhere.
  // "1::2" is a valid way to write an IPv6 address and the commonest way to
  // write a Python slice: face[1::2], pe[:, 0::2]. A slice sits inside
  // brackets, after "[" or a comma; "ping 2001::1" is a machine.
  scan(IPV6_PATTERN, "host", {
    accept: (value, before) => !/^2001:0?db8:/i.test(value) && !(/^\d{1,4}::\d{1,4}$/.test(value) && /[[,:][ \t]*$/.test(before ?? "")),
  });
  // A digit is required of the base58 forms: without one, "Landesgrundverkehrsreferent"
  // is a Litecoin address. A real one lacks a digit about once in three hundred.
  // A letter too: "3.141592653589793238462643383" is pi, not a Bitcoin wallet.
  // The base58 forms mix cases too: a 26-character run with no capital
  // ("apiserver-1dfef752bcb36637d2763d1868", a Kubernetes lease) is hex, and
  // a real one lacks either about once in ten million. bc1 and 0x are
  // lower case or hex by design and keep their own rules.
  //
  // Some Ethereum addresses are the same in every developer's code and belong
  // to nobody: the main contracts and the test chains' default accounts.
  // 100 of 154 taken from real prompts were these (WildChat, 2026-10-23).
  // So are the system addresses that are nearly all zeros ("0x4300…0000",
  // the zero address). A wallet the writer owns is none of these and still goes.
  scan(CRYPTO_ADDRESS_PATTERN, "govid", {
    accept: (value) => /\d/.test(value) && /[A-Za-z]/.test(value)
      && (/^(?:bc1|0x)/.test(value) || (/[A-Z]/.test(value.slice(1)) && /[a-z]/.test(value)))
      && !(value.startsWith("0x") && (PUBLIC_ETHEREUM.has(value.toLowerCase()) || (value.match(/0/g) ?? []).length >= 33)),
  });
  scan(CRYPTO_CUED_PATTERN, "govid", { group: 1, accept: (value) => /\d/.test(value) && /[A-Z]/.test(value) && /[a-z]/.test(value) });
  scan(VIN_PATTERN, "govid", { group: 1, accept: (value) => /[A-Za-z]/.test(value) && /\d/.test(value) });
  // Nobody born before 1900 is alive to be identified by it: "Charles Inglis
  // was born on 31 July 1875" is history, and Wikipedia-style passages pasted
  // into a question are full of it (Dolly 15k).
  const historical = (value: string) => !/(?<!\d)1[0-8]\d\d(?!\d)/.test(value);
  // And the opening of an encyclopedia article: "Taylor Alison Swift (born
  // December 13, 1989) is an American singer-songwriter". The brackets right
  // after a name and "is a…" or "was a…" right after them are how Wikipedia
  // introduces a notable person, and a pasted article asked about ("how old
  // is she?") is the commonest way a birth date reaches a prompt (Dolly 15k:
  // 257 of 400 false alarms). Only that form: "born on 14 March 1988" in a
  // sentence about somebody stays hidden.
  //
  // Widened on 2026-10-23, on Dolly's real prompts (111 birth dates hidden,
  // nearly all article openings): the birthplace may sit inside the brackets
  // ("born 29 April 1986 in Banbury, England"), a known-as may follow them
  // ("), commonly known as Adão, is a"), and two words may come before the
  // nationality ("is a former professional Canadian").
  //
  // Both halves are needed, and each is checked strictly, because a wrong
  // yes shows a private person's birth date. A full name opens the brackets:
  // "my client (born …)" has none. And the word after "is a" is a nationality
  // by its ending, not any capital: "My son Jake Miller (born 2 January 2015)
  // is an Arsenal fan" stays hidden, and so does "John Smith (born 3 May
  // 1990) is a teacher", whatever an article would say.
  const encyclopedic = (before?: string, after?: string) =>
    ARTICLE_BORN_BEFORE.test(before ?? "") && ARTICLE_NAME_BEFORE.test(before ?? "") && ARTICLE_NATIONALITY_AFTER.test(after ?? "");
  scan(DOB_CUED_PATTERN, "govid", { group: 1, accept: (value, before, after) => historical(value) && !encyclopedic(before, after) });
  // The same, with a few words between the label and the date.
  scan(DOB_LABELLED_PATTERN, "govid", { group: 1, accept: historical });
  // A name written the other way round is a bundle or package id, never a
  // machine: macOS logs list "com.apple.private.alloy.maps" (Loghub).
  // Nor is a dotted name with a word in camelCase or PascalCase inside it:
  // that is a class or a method from a stack trace, "jdk.internal.reflect.
  // NativeMethodAccessorImpl.invoke0", "Microsoft.EntityFrameworkCore.Query.
  // Internal.QueryCompiler", "pdf.internal.pageSize.width". Hostnames are not
  // written with a capital inside a word after the marker. 56 of 172 hosts
  // taken from real prompts were these (WildChat, 2026-10-23). Before the
  // marker, a capital inside a word is how machines are named: "SqlServer01.
  // corp.internal", "Johns-MacBook-Pro.local". So only what comes after
  // "internal" (or "local", "corp"…) decides.
  const looksLikeClass = (value: string) => {
    const labels = value.split(".");
    const marker = labels.findIndex((label) => INTERNAL_MARKERS.includes(label.toLowerCase()));
    return marker !== -1 && labels.slice(marker + 1).some((label) => /[a-z][A-Z]/.test(label));
  };
  scan(INTERNAL_HOST_PATTERN, "host", {
    accept: (value) => !/^(?:com|org|net|io|android|java|javax|de|uk)\.[a-z]/.test(value) && !looksLikeClass(value),
  });
  // "Version 10.0.0.0" is a release, not a machine on the office network.
  // Every octet under 256: "192.168.0.256" is the error message Python's
  // ipaddress documentation shows for an address that cannot exist.
  scan(PRIVATE_IP_PATTERN, "host", { accept: (value, before) => value.split(".").every((o) => Number(o) <= 255) && !/\b(?:version|ver|v|release|build|sdk|firmware|rev)\.?\s*$/i.test(before ?? "") });
  // A public address in an authentication log: see AUTH_LOG_IP_PATTERN.
  // Documentation's reserved ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
  // are examples, not anybody's connection.
  scan(AUTH_LOG_IP_PATTERN, "host", { group: 1, accept: (value) => !/^(?:192\.0\.2|198\.51\.100|203\.0\.113)\./.test(value) });
  // A public address only when its label makes it somebody's — see IP_LABELLED_PATTERN.
  scan(IP_LABELLED_PATTERN, "host", {
    group: 1,
    accept: (value, before) => {
      if (IP_NOT_A_PERSON.test(value)) return false;
      // The words before the label, with the label itself taken off.
      const lead = (before ?? "").replace(/[\s:=*"'(]*(?:(?:customer|client|user|visitor|member|login|sign[\s-]?in|source|remote|originating|unknown|suspicious)\s+)?(?:ip[\w\s-]*|(?:indirizzo|direcci[óo]n|adresse|coordonn[ée]es)\s+ip)(?:\s+(?:is|was|of))?[\s:=*"'(|,>]*$/iu, "");
      return !IP_LABEL_MACHINE.test(lead);
    },
  });
  // A few words from its label — see IP_BRIDGED_PATTERN.
  scan(IP_BRIDGED_PATTERN, "host", { group: 1, accept: (value) => !IP_NOT_A_PERSON.test(value) });
  // And the next one in its list, "… and 101.73.200.74": only after a public
  // address taken above (or by this, for a third), never a list of servers.
  scan(IP_AFTER_IP_PATTERN, "host", {
    group: 2,
    accept: (value, before) => {
      const first = (before ?? "").match(/(\d{1,3}(?:\.\d{1,3}){3})[ \t]{0,3}(?:,|and|or|&|\/)[ \t]{0,3}$/)?.[1];
      if (!first || IP_NOT_A_PERSON.test(value) || new RegExp(PRIVATE_IP_PATTERN.source).test(first)) return false;
      return found.some((f) => f.kind === "host" && f.value === first);
    },
  });
  // Broadcast and all-zero are addresses every network shares, not a device.
  // Six rising numbers with no hex letter are a lottery draw: "红区07-10-14-
  // 20-21-25+蓝区11" (WildChat).
  scan(MAC_ADDRESS_PATTERN, "host", {
    accept: (value) => {
      const groups = value.split(/[:.-]/);
      const rising = groups.every((g, i) => /^\d+$/.test(g) && Number(g) <= 49 && (i === 0 || Number(g) > Number(groups[i - 1])));
      return !rising && !/^(?:ff){6}$|^(?:00){6}$/i.test(value.replace(/[:.-]/g, ""));
    },
  });

  // A card's security code written straight after it, in any of the
  // benchmark's languages: "4969014595602364 con 879", "(1960774002511208,
  // 054)", "4111 1111 1111 1111 and 123" (ai4privacy fr/de/it). Three or four
  // digits, ending the phrase, after a card already found.
  for (let i = 0, n = found.length; i < n; i += 1) {
    if (found[i].kind !== "card" || found[i].value.replace(/\D/g, "").length < 13) continue;
    const end = claimed[i][1];
    const m = /^(?:\s*,\s*|\s+(?:and|with|et|avec|und|mit|con|e|y)\s+)(\d{3,4})(?=\s*(?:[),.;]|$|\s+(?:and|et|und|e|y|for|pour|für|per|to)\b))/.exec(scanText.slice(end, end + 24));
    if (!m) continue;
    const start = end + m[0].length - m[1].length;
    if (overlaps(start, start + m[1].length)) continue;
    claim([start, start + m[1].length]);
    found.push({ kind: "card", value: text.slice(start, start + m[1].length) });
  }

  // The rest of each address block: its unit, town, region, country and
  // postcode, whether on the same line after commas or on the lines below.
  // "Koskikatu 25" alone leaves "Artilleros, CO, Uruguay 64677" beside it.
  // Kept only up to the last piece that proves it is a block — see
  // ADDRESS_TAIL_PATTERN — and never through anything else already found.
  // The pieces of a block after `from`: see ADDRESS_TAIL_PATTERN. `keep` is
  // how many of them run up to the last one that proves the block.
  const blockTail = (from: number, strict = false) => {
    let at = from;
    const pieces: Array<[number, number]> = [];
    let keep = 0;
    for (let n = 0; n < 5; n += 1) {
      ADDRESS_TAIL_PATTERN.lastIndex = at;
      const m = ADDRESS_TAIL_PATTERN.exec(scanText);
      const span = (m as (RegExpExecArray & { indices?: Array<[number, number]> }) | null)?.indices?.[1];
      if (!m || !span) break;
      // Strict: the first piece is a place, after a comma or a line break —
      // not a figure. "PLN 10,000" and "Articles 38, 215, 343" are money and
      // a list, and the next thing after them is another number.
      if (strict && n === 0 && (!/[,\n]/.test(m[0].slice(0, span[0] - at)) || !/^\p{Lu}(?:\p{Ll}|\p{Lu}{2})/u.test(m[1]))) break;
      const other = claimed.findIndex(([f, t]) => f < span[1] && t > span[0]);
      if (other !== -1 && found[other].kind !== "address" && found[other].kind !== "postcode") break;
      // Strict: only a postcode proves it, and a year is not one. A country
      // or a region follows "Boeing 747, Seattle, WA" and "Formula 1,
      // Monaco" just as well as it follows a street.
      // Nor is a number after a name, unless it is four digits or more and
      // no year: "Server 2003, Server 2008", "UEFA Euro 2000" and "FTSE 100
      // Index, Financial Times Global 500" are products, a tournament and an
      // index (Dolly 15k). "Sydney NSW 2000" keeps its region in front, and
      // a flat ("3922 The Poplars, Suite 176") still proves the block.
      const terminal = strict
        ? /(?:^|\s)\d{3,6}(?:[ -]\d{2,4})?$/.test(m[1]) && !/^(?:19|20)\d\d$/.test(m[1].trim())
          && (!/\p{L}/u.test(m[1]) || /^(?:Apt|Apartment|Suite|Ste|Unit|Flat|Room|Floor|Fl)\b/.test(m[1]) || (/\d{4}(?:[ -]\d{2,4})?$/.test(m[1]) && (!/(?:^|\s)(?:19|20)\d\d$/.test(m[1]) || /(?:^|\s)[A-Z]{2,3}\s+\d{4}$/.test(m[1]))))
        : ADDRESS_BLOCK_TERMINAL.test(m[1]);
      pieces.push(span);
      at = span[1];
      if (terminal) keep = pieces.length;
    }
    return pieces.slice(0, keep);
  };
  const takePieces = (pieces: Array<[number, number]>) => {
    for (const [start, end] of pieces) {
      if (end - start < 3 || overlaps(start, end)) continue;
      claim([start, end]);
      found.push({ kind: "address", value: text.slice(start, end) });
    }
  };
  const streets = found.length;
  for (let i = 0; i < streets; i += 1) {
    // Not past a full stop after a whole street word: "at 179 South Powell
    // Avenue. In August 2016, the cupola" is the next sentence, and its year
    // is not a postcode (Dolly 15k). "123 Main St. Anytown" is an abbreviation.
    if (found[i].kind === "address" && !(/\p{Ll}{2,}\.$/u.test(found[i].value) && !/\b(?:Blvd|Pkwy|Hwy|Ave|Rd|Ln|Dr|Ct|Pl|Trl|Str|Sq|Cres|Terr|St)\.$/.test(found[i].value))) takePieces(blockTail(claimed[i][1]));
  }

  // A postcode on the line above a street, with or without its town, and
  // at most one town line between: Russia, Belarus, Ukraine, Kazakhstan and
  // Kyrgyzstan write "125075 Springfield" above "12 Station Road". Only
  // directly above a street already found, and only a line that is nothing
  // but the postcode and the place.
  for (let i = 0; i < streets; i += 1) {
    if (found[i].kind !== "address") continue;
    // Whether the street starts its line, read back over the whitespace before
    // it rather than back to the line's start: on a page with no line breaks
    // that was the whole page again for every street, quadratic in its length
    // (scanner-safety, "streets that never end their line"). The same answer:
    // the line is blank before the street exactly when nothing but whitespace
    // lies between it and the previous line break.
    let back = claimed[i][0] - 1;
    while (back >= 0 && scanText[back] !== "\n" && /\s/.test(scanText[back])) back -= 1;
    if (back >= 0 && scanText[back] !== "\n") continue;
    const lineStart = back + 1;
    let end = lineStart - 1;
    for (let up = 0; up < 2 && end > 0; up += 1) {
      const start = scanText.lastIndexOf("\n", end - 1) + 1;
      const line = scanText.slice(start, end);
      const pc = POSTCODE_LINE_PATTERN.exec(line);
      if (pc) {
        const at = start + line.indexOf(pc[1]);
        const to = at + pc[1].length;
        if (!overlaps(at, to)) {
          claim([at, to]);
          found.push({ kind: "postcode", value: text.slice(at, to) });
        }
        break;
      }
      if (!PLACE_LINE_PATTERN.test(line)) break;
      end = start - 1;
    }
  }

  // A postcode a few words after a street it belongs to — see
  // POSTCODE_AFTER_STREET_PATTERN. Not a year: "Hauptstraße 5, 2023 Umzug".
  for (let i = 0, n = found.length; i < n; i += 1) {
    if (found[i].kind !== "address") continue;
    const from = claimed[i][1];
    const tail = scanText.slice(from, from + 60).split("\n")[0];
    const m = POSTCODE_AFTER_STREET_PATTERN.exec(tail) as (RegExpExecArray & { indices?: Array<[number, number]> }) | null;
    if (!m?.indices?.[1] || /^(?:19|20)\d\d$/.test(m[1])) continue;
    const at = from + m.indices[1][0];
    const to = from + m.indices[1][1];
    if (overlaps(at, to)) continue;
    claim([at, to]);
    found.push({ kind: "postcode", value: text.slice(at, to) });
  }

  // The other way round: a name and a number that no pattern knows as a
  // street — "Parmova 109", "214 Pavlou Drandaki" — is one when the rest of
  // an address block follows it, after a comma or on the next line, and ends
  // in a postcode. The block is the evidence the
  // street word would have been. Refused for anything NOT_A_STREET names:
  // "Windows 11, Microsoft, USA" is a product.
  STREET_BEFORE_BLOCK_PATTERN.lastIndex = 0;
  for (const m of scanText.matchAll(STREET_BEFORE_BLOCK_PATTERN)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    // Overlapping another piece of the same address is not a reason to drop
    // the street: "68 \n Suite 707" is claimed as a flat its street vouches
    // for, and that claim used to cost "Baarlandhof 68" the line it is on.
    if (claimed.some(([f, t], i) => start < t && end > f && found[i].kind !== "address" && found[i].kind !== "postcode")) continue;
    if (claimed.some(([f, t]) => f <= start && t >= end)) continue;
    // A name in ordinary case: "PLN 10", "QB 1334", "A.C. 942" are a currency
    // and law reports.
    if (NOT_A_STREET_PATTERN.test(m[0]) || !notACourt(m[0]) || !/\p{Lu}\p{Ll}{2}/u.test(m[0])) continue;
    // A year is not a building number, before the name or after it — the rule
    // every European branch of ADDRESS_PATTERN already keeps: "1998 FIFA World
    // Cup", "Server 2003" (Dolly 15k). Nor an older one after a word: "Geboren
    // 1707, Gestorben 1778, Gärtner" is a life in a list (WildChat).
    if (/^(?:19|20)\d\d\s|\s(?:1[5-9]|20)\d\d\.?$/.test(m[0])) continue;
    const pieces = blockTail(end, true);
    // Or a number on both sides and a town after it: "Inc., 8764 Vestre
    // Solhellinga 92, JESSHEIM". A building number and a house number around
    // a name is the whole of an address in most of Europe, and a town after a
    // comma is what a count or a product ("3 Windows 11, then") never has.
    // The town is not taken without a postcode to prove it.
    const numbered = pieces.length === 0
      && /\d\.?$/.test(m[0]) && !/^\d/.test(m[0]) && !NOT_A_LABELLED_STREET.test(m[0])
      && /(?:^|[,:;\n]|\b(?:at|to|in|on|is))[ \t]*(?!(?:19|20)\d\d\b)\d{3,5}[ \t]+$/u.test(scanText.slice(Math.max(0, start - 12), start))
      && /^[ \t]*(?:,[ \t]*|\r?\n[ \t]*)\p{Lu}[\p{Ll}\p{Lu}]/u.test(scanText.slice(end, end + 40));
    if (pieces.length === 0 && !numbered) continue;
    claim([start, end]);
    found.push({ kind: "address", value: text.slice(start, end) });
    takePieces(pieces);
  }

  // A street name in front of a building number and a flat: "Palackého 496
  // Apt. 615", "Estrada Nacional 105 Suite 273". The number and the flat were
  // found together (a number beside a flat is an address on its own) and the
  // name before them, which no street word marks, was left beside them.
  // Capitalised words only, on the same line, and never one NOT_A_STREET
  // names: "Room 12 Suite 4" stays a room.
  for (let i = 0; i < found.length; i += 1) {
    if (found[i].kind !== "address" || !/^\d{1,5}[A-Za-z]?,?\s+(?:Apt|Apartment|Suite|Ste)\b/.test(found[i].value)) continue;
    const [from, to] = claimed[i];
    const name = /(?<![\p{L}\p{N}'’.-])(?:\p{Lu}[\p{L}\p{M}'’.-]{1,30}[ \t]+){1,3}$/u.exec(scanText.slice(Math.max(0, from - 80), from));
    if (!name || NOT_A_STREET_PATTERN.test(name[0]) || !notACourt(name[0])) continue;
    const start = from - name[0].length;
    // Through the claimed-character map, not every claim: a claim per street
    // made this quadratic on a page of them. Span i itself starts at `from`,
    // so it never overlaps [start, from) and needs no exclusion.
    if (overlaps(start, from)) continue;
    claimed[i] = [start, to];
    mark(claimed[i]);
    found[i] = { kind: "address", value: text.slice(start, to) };
  }

  // The house number in front of a street found by its name and its other
  // number: "7848 Heirstraat 58", "796 Fredbo allé 14", "469 21 Sydney
  // Road", and a flat written first: "Apt. 518 447 Siikarannantie 59". Only
  // on the same line, only where nothing else has the digits, and never a
  // year: "since 2019 Baker Street" is a date and a street.
  for (let i = 0; i < found.length; i += 1) {
    if (found[i].kind !== "address" || !/^[\p{Lu}\d]/u.test(found[i].value)) continue;
    let [from] = claimed[i];
    const to = claimed[i][1];
    for (let step = 0; step < 2; step += 1) {
      const lead = /(?<![\p{L}\p{N}.,\/-])((?:(?:Apt|Apartment|Suite|Ste)\.?[ \t]*#?[ \t]*)?\d{1,5}[A-Za-z]?)[ \t]+$/u.exec(scanText.slice(Math.max(0, from - 20), from));
      if (!lead || /^(?:19|20)\d\d$/.test(lead[1])) break;
      const start = from - lead[0].length;
      // As above: the map, and span i (which starts at or after `from`) cannot overlap.
      if (overlaps(start, from)) break;
      from = start;
    }
    if (from === claimed[i][0]) continue;
    claimed[i] = [from, to];
    mark(claimed[i]);
    found[i] = { kind: "address", value: text.slice(from, to) };
  }

  // The next of a list a cue introduced: "Passports: AB1234567 and
  // XY9876543". Only a value of exactly the same shape — letters where the
  // first has letters, digits where it has digits — right after a comma,
  // "and" or "or".
  const shape = (v: string) => v.replace(/[A-Za-z]/g, "A").replace(/\d/g, "9");
  for (let i = 0; i < found.length; i += 1) {
    if (found[i].kind !== "govid" || !/\d/.test(found[i].value) || !/[A-Za-z]/.test(found[i].value)) continue;
    let to = claimed[i][1];
    for (let n = 0; n < 4; n += 1) {
      const next = /^(?:[ \t]*,[ \t]*|[ \t]+)(?:(?:and|or|&)[ \t]+)?([A-Za-z0-9-]{5,20})(?![\w-])/.exec(scanText.slice(to, to + 40));
      if (!next || shape(next[1]) !== shape(found[i].value)) break;
      const start = to + next[0].length - next[1].length;
      const end = to + next[0].length;
      if (overlaps(start, end)) break;
      claim([start, end]);
      found.push({ kind: "govid", value: text.slice(start, end) });
      to = end;
    }
  }

  // A flat number on its own, last: every street and block above has had its
  // chance to take it with its street. See APT_ALONE_PATTERN.
  scan(APT_ALONE_PATTERN, "address", { group: 1 });
  // "END.: RUA DAS PALMEIRAS, 1450" and Argentina's C1416 — see
  // END_LABEL_PATTERN and AR_CPA_PATTERN. A code ending in letters that
  // spell a unit or a standard is not one.
  scan(END_LABEL_PATTERN, "address", { group: 1, accept: (value) => /\d/.test(value) || /\p{Lu}{3,}/u.test(value) });
  scan(AR_CPA_PATTERN, "postcode", { group: 1, accept: (value) => !/(?:USD|EUR|ARS|KWH|MHZ|GHZ|RPM)$/.test(value) });
  scan(AR_CPA_PATTERN, "postcode", { group: 2 });
  // A building's number under its word, or with "on" and its street — see
  // BUILDING_CUED_PATTERN. Not a year ("the house 1920s style").
  scan(BUILDING_CUED_PATTERN, "address", { group: 1, accept: (value) => !/^(?:1[89]|20)\d\d$/.test(value) });
  scan(NUMBER_ON_STREET_PATTERN, "address", { group: 1 });
  scan(NUMBER_ON_STREET_PATTERN, "address", { group: 2, accept: (value) => !FAMOUS_STREETS.test(value) });

  // Labels learned from benchmark misses and approved by review — see
  // redactionLearned.ts. Last of all, so a learned label only fills a gap
  // and never takes a value a written pattern reads better: "(97) 9856-7733"
  // keeps its bracket, and a Swiss AHV number stays an SSN.
  for (const { kind, pattern } of trialCues?.length ? [...LEARNED, ...learnedCuePatterns(trialCues)] : LEARNED) {
    scan(pattern, kind, { group: 1, accept: (value) => acceptLearned(kind, value) });
  }
  // A postcode beside its town in any country's address — see
  // findPostcodesBesideTowns. Last, on what no other rule has taken: a
  // number in a hash, an address or a VIN is theirs.
  const besideTowns = findPostcodesBesideTowns(scanText);
  for (const p of besideTowns) {
    if (overlaps(p.start, p.end)) continue;
    claim([p.start, p.end]);
    found.push({ kind: "postcode", value: text.slice(p.start, p.end).trim() });
  }
  // And the street before such a postcode, or after the word for an address
  // (findStreetsBesidePostcodes).
  for (const s of findStreetsBesidePostcodes(scanText, besideTowns)) {
    if (overlaps(s.start, s.end)) continue;
    claim([s.start, s.end]);
    found.push({ kind: "address", value: text.slice(s.start, s.end).trim() });
  }

  // A street with no number, by its name alone — see STREET_NUMBERLESS_PATTERN.
  scan(STREET_NUMBERLESS_PATTERN, "address", { accept: (value) => !FAMOUS_STREETS.test(value) });

  // Five digits where a place goes, last among postcodes so a street or a
  // town claims its own first — see ZIP_PLACE_WORD_PATTERN.
  scan(ZIP_PLACE_WORD_PATTERN, "postcode", { group: 1 });

  // The rest of a person's record, a row with no header: the account and
  // the PIN beside an email (redactionRows). `claimed[i]` is found[i]'s.
  const byStart = claimed.map(([s, e], i) => [s, e, i] as const).filter(([s, e]) => e > s).sort((x, y) => x[0] - y[0]);
  const kindAt = (start: number, end: number) => {
    if (!overlaps(start, end)) return null;
    let lo = 0, hi = byStart.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (byStart[mid][0] < end) lo = mid + 1; else hi = mid; }
    for (let j = lo - 1; j >= 0 && j >= lo - 50; j -= 1) if (byStart[j][1] > start) return found[byStart[j][2]]?.kind ?? null;
    return "govid" as const;
  };
  for (const cell of findRowCells(scanText, kindAt)) {
    if (overlaps(cell.start, cell.end)) continue;
    claim([cell.start, cell.end]);
    found.push({ kind: cell.kind, value: text.slice(cell.start, cell.end) });
  }

  // The rest of a list. A table pasted as one line names its column once —
  // "ime;oib;iznos Dražen Kovačević;32358571182;1.450,00 Mirjana
  // Horvat;47185421039;620,00" — and only the first number sits near the
  // label. Once an ID is found, another value of exactly its shape in the same
  // text is the same kind of number: "47185421039", "PAPI820215HPLRSS01",
  // "65 230888 A 027" (ID practice set, 2026-10-26). Only shapes that cannot
  // be a word, a price or a date: nine digits or more, or six with letters.
  // And only a cell: a comma, semicolon, tab or bar on each side (or the end
  // of the line after it). Without that, one ID in a training log took every
  // loss value's decimals with it ("1949.982177734375"), and one in an XML
  // dump every hex address (WildChat, 2026-10-26).
  const shapes = new Set<string>();
  for (const f of found) {
    if (f.kind !== "govid") continue;
    const digits = (f.value.match(/\d/g) ?? []).length;
    const letters = /\p{L}/u.test(f.value);
    if (!(digits >= 9 || (digits >= 6 && letters)) || f.value.length > 26 || /[^\p{Lu}\d .\/-]/u.test(f.value)) continue;
    shapes.add(f.value.replace(/\d/g, "0").replace(/\p{Lu}/gu, "A"));
  }
  for (const shape of shapes) {
    const body = [...shape].map((c) => (c === "0" ? "\\d" : c === "A" ? "\\p{Lu}" : escapeRegex(c))).join("");
    for (const m of scanText.matchAll(new RegExp(`(?<=[,;|\\t][ ]?)${body}(?=[ ]?[,;|\\t]|[ ]*$)`, "gmu"))) {
      const start = m.index ?? 0, end = start + m[0].length;
      if (overlaps(start, end)) continue;
      claim([start, end]);
      found.push({ kind: "govid", value: text.slice(start, end) });
    }
  }

  // A customer's own order code, only in the customer's own message: see
  // ORDER_CODE_PATTERN. Measured on realistic5-7 (2026-10-31): 12 of the 12
  // lettered order codes in a customer's message were private, and none of
  // the plain order numbers or invoice numbers.
  if (ORDER_CODE_PERSONAL.test(scanText)) scan(ORDER_CODE_PATTERN, "govid", { group: 1 });

  // Last, after every pattern with a label has had its turn: see
  // ACCOUNT_BARE_PATTERN. Not a date, not a number its own word calls a
  // reference (see BARE_EIGHT_NOT_AN_ACCOUNT), and not a count of something.
  scan(ACCOUNT_BARE_PATTERN, "iban", {
    group: 1,
    accept: (value, before = "", after = "") =>
      !/^(?:19|20)\d\d(?:0[1-9]|1[0-2])[0-3]\d$/.test(value)
      && !/^[0-3]\d(?:0[1-9]|1[0-2])(?:19|20)\d\d$/.test(value)
      && !/^(\d)\1+$/.test(value) && !/^(\d\d)\1{3}$/.test(value)
      && !BARE_EIGHT_NOT_AN_ACCOUNT.test(before)
      && !BARE_EIGHT_COUNTS.test(after)
      // Beside a hex word it is a register or an address in a dump: "iar
      // 00106228 dear 0244c1ec".
      && !/(?<![\p{L}\p{N}])(?=[\da-f]{6,16}(?![\p{L}\p{N}]))[\d]*[a-f][\da-f]*(?![\p{L}\p{N}])/iu.test(`${before.slice(-24)} ${after.slice(0, 24)}`),
  });

  // A line break cannot be substituted (isSubstitutable), so a value that
  // runs over two lines — "285\n Suite 578" — would be found and then
  // dropped, and go out as written. Each line goes as its own value instead.
  return found.filter((f) => f.kind !== "secret" || !codeNotASecret(f.value)).flatMap((f) => {
    if (!/[\r\n]/.test(f.value)) return [f];
    return f.value
      .split(/\r?\n/)
      .map((line) => line.trim().replace(/^[,;]\s*|[,;]$/g, "").trim())
      .filter((line) => line.length >= 3)
      .map((value) => ({ kind: f.kind, value }));
  });
}

/**
 * Adds an alias for every structured identifier in `scanText` that the map
 * does not already cover. Runs after the profile pass, so the user's own email
 * and phone keep the aliases stage 1 gave them rather than being re-minted
 * here under a different name.
 */
export async function addStructuredRedactions(
  map: RedactionMap,
  scanText: string,
  haystack: string,
  /** Values the person has said may be sent as written. See AllowList. */
  allow: AllowList = new Set(),
): Promise<RedactionMap> {
  return addFoundRedactions(map, findStructured(scanText), haystack, allow);
}

/**
 * The same, for values found some other way — the number stage's verdicts —
 * so they get stand-ins of the same shape by the same rules.
 */
export async function addFoundRedactions(
  map: RedactionMap,
  found: Array<{ kind: StructuredKind; value: string }>,
  haystack: string,
  allow: AllowList = new Set(),
): Promise<RedactionMap> {
  const taken = new Set(Object.keys(map));
  const covered = new Set(Object.values(map).map((value) => value.toLowerCase()));
  const out: RedactionMap = { ...map };
  // Counted only near the ceiling: each value adds at most three entries (its
  // stand-in and an email's two name halves), and counting all of them for
  // every one of four thousand values was a second of nothing.
  const start = Object.keys(out).length;
  let minted = 0;

  for (const { kind, value } of found) {
    if (start + 3 * minted >= MAX_REDACTION_ENTRIES && Object.keys(out).length >= MAX_REDACTION_ENTRIES) break;
    minted += 1;
    if (!isSubstitutable(value)) continue;
    if (covered.has(value.toLowerCase())) continue;
    // Checked before minting rather than filtered out afterwards: an alias
    // that is created and then dropped still consumed a slot and a stand-in.
    if (isAllowed(value, allow)) continue;

    const fake = await pickFake(value, taken, haystack, (i, hex) => {
      switch (kind) {
        case "email": {
          const first = FAKE_FIRST[(parseInt(hex.slice(0, 6), 16) + i) % FAKE_FIRST.length];
          const last = FAKE_LAST[(parseInt(hex.slice(6, 12), 16) + i) % FAKE_LAST.length];
          const domain = FAKE_EMAIL_DOMAINS[(parseInt(hex.slice(12, 16), 16) + i) % FAKE_EMAIL_DOMAINS.length];
          return `${first}.${last}`.toLowerCase() + `@${domain}`;
        }
        /**
         * A stand-in key, wearing the same badge.
         *
         * The prefix is kept and only the secret half is replaced, so the
         * model still reads "this is an OpenAI key" or "this is an AWS access
         * key id" and can reason about the payload — which is the whole
         * difference between this product and a black bar. What it cannot do
         * is spend anybody's money.
         *
         * Same length as the original, so a payload whose shape is checked
         * downstream still passes, and drawn from the same hex the rest of
         * this switch uses, so the same secret gets the same stand-in every
         * time it appears.
         */
        case "secret": {
          const prefix = value.match(/^(AIza|AKIA|gh[pousr]_|xox[baprs]-|github_pat_|glpat-|npm_|hf_|SG\.|shp(?:at|ss|ca|pa)_|pypi-|dop_v1_|https:\/\/hooks\.slack\.com\/services\/|sk-ant-|sk-proj-|sk-|sai_(?:live|test)_|(?:sk|pk|rk)_(?:live|test)_|eyJ)/)?.[0] ?? "";
          const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
          const want = Math.max(16, value.length - prefix.length);
          let tail = "";
          for (let n = 0; n < want; n += 1) {
            const at = (parseInt(hex.slice((n * 2) % 30, ((n * 2) % 30) + 2) || "0", 16) + i + n) % alphabet.length;
            tail += alphabet[at];
          }
          return prefix + tail;
        }
        case "card":
          return fakeCard(hex, i);
        case "iban":
          return fakeIban(value, hex, i);
        case "ssn": {
          const area = 400 + (parseInt(hex.slice(0, 4), 16) + i) % 200;
          const group = 10 + (parseInt(hex.slice(4, 8), 16) + i) % 80;
          const serial = 1000 + (parseInt(hex.slice(8, 12), 16) + i) % 9000;
          return `${area}-${group}-${serial}`;
        }
        case "phone": {
          const areaCode = FAKE_AREA_CODES[(parseInt(hex.slice(16, 20), 16) + i) % FAKE_AREA_CODES.length];
          const mid = 100 + (parseInt(hex.slice(20, 26), 16) + i) % 900;
          const end = 1000 + parseInt(hex.slice(26, 32), 16) % 9000;
          return `(${areaCode}) ${mid}-${end}`;
        }
        case "address": {
          const number = 100 + (parseInt(hex.slice(0, 6), 16) + i) % 8900;
          const street = FAKE_STREETS[(parseInt(hex.slice(6, 12), 16) + i) % FAKE_STREETS.length];
          const word = FAKE_STREET_WORDS[(parseInt(hex.slice(12, 16), 16) + i) % FAKE_STREET_WORDS.length];
          return `${number} ${street} ${word}`;
        }
        case "postcode": {
          // Kept in the shape it arrived in. A UK postcode replaced by a US ZIP
          // tells the model the user moved country, which is a bigger leak of
          // the wrong kind than the code itself.
          if (/^\d{5}(-\d{4})?$/.test(value)) {
            const zip = 10000 + (parseInt(hex.slice(0, 6), 16) + i) % 89999;
            return value.includes("-")
              ? `${zip}-${1000 + (parseInt(hex.slice(6, 10), 16) + i) % 8999}`
              : String(zip);
          }
          const letters = "ABCDEFGHJKLMNPRSTUWXYZ";
          const l = (n: number) => letters[(parseInt(hex.slice(n, n + 2), 16) + i) % letters.length];
          const d = (n: number) => (parseInt(hex.slice(n, n + 2), 16) + i) % 10;
          return `${l(0)}${l(2)}${d(4)} ${d(6)}${l(8)}${l(10)}`;
        }
        case "host": {
          /*
           * An IPv6 address, which has no dots in it at all.
           *
           * Without this it fell through to the hostname branch below, which
           * splits on "." — one label, one fake word — and
           * "ca9f:5ca7:00c3:bc12:a1c1:f65d:a643:9d1b" was sent to the model
           * as "umber". Nothing leaked, and the model was handed a word
           * where an address belongs, which is its own kind of wrong answer.
           *
           * Same number of groups, same compression if it had any, hex drawn
           * from the same digest as everything else here so the value gets
           * the same stand-in every time it appears.
           */
          if (value.includes(":")) {
            let n = 0;
            return value
              .split(":")
              .map((group) => {
                if (group === "") return "";   // the "::" run, kept where it was
                const from = (n * 4) % 28;
                n += 1;
                const chunk = ((parseInt(hex.slice(from, from + 4), 16) || 0) + i + n) & 0xffff;
                return chunk.toString(16).padStart(group.length >= 4 ? 4 : group.length, "0");
              })
              .join(":");
          }
          // An IP stays on the range it came from: a 10.x replaced by a 192.168.x
          // would tell the model the network was laid out differently, which is
          // a made-up fact rather than a hidden one.
          const ipParts = value.split(".");
          if (ipParts.length === 4 && ipParts.every((part) => /^\d{1,3}$/.test(part))) {
            const octet = (n: number) => (parseInt(hex.slice(n, n + 2), 16) + i) % 254 + 1;
            if (value.startsWith("10.")) return `10.${octet(0)}.${octet(2)}.${octet(4)}`;
            if (value.startsWith("192.168.")) return `192.168.${octet(0)}.${octet(2)}`;
            if (value.startsWith("169.254.")) return `169.254.${octet(0)}.${octet(2)}`;
            return `172.${16 + (parseInt(hex.slice(0, 2), 16) + i) % 16}.${octet(2)}.${octet(4)}`;
          }
          // A hostname keeps the shape that made it recognisable — same number
          // of labels, same marker, same suffix — and loses the words that say
          // whose it is.
          return value
            .split(".")
            .map((label, n) => {
              if (HOST_KEEP.has(label.toLowerCase())) return label;
              return FAKE_HOST_WORDS[(parseInt(hex.slice((n * 4) % 28, (n * 4) % 28 + 4), 16) + i + n) % FAKE_HOST_WORDS.length];
            })
            .join(".");
        }
        case "govid": {
          // A date of birth is caught by this kind too, and it is the one
          // value here the character swap cannot handle: it reads "March" as
          // letters and hands back "Hrswr", and 1988 as digits and hands back
          // 1574. What reaches the model is then not a date at all, which is
          // exactly the failure the rule below is written to avoid — and a
          // birth year of 1574 is a thing a model remarks on rather than uses.
          const asDate = fakeDate(value, hex, i);
          if (asDate) return asDate;
          // Same shape, different characters: letters stay letters, digits stay
          // digits, separators stay put. A licence number that no longer looks
          // like a licence number is one the model will query rather than use.
          let out = "";
          let n = 0;
          for (const ch of value) {
            if (/[A-Za-z]/.test(ch)) {
              const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ";
              const pick = letters[(parseInt(hex.slice(n % 28, (n % 28) + 2), 16) + i + n) % letters.length];
              out += ch === ch.toLowerCase() ? pick.toLowerCase() : pick;
              n += 2;
            } else if (/\d/.test(ch)) {
              out += String((parseInt(hex.slice(n % 28, (n % 28) + 2), 16) + i + n) % 10);
              n += 2;
            } else {
              out += ch;
            }
          }
          return out;
        }
      }
    });

    if (fake) {
      out[fake] = value;
      taken.add(fake);
      covered.add(value.toLowerCase());
      if (kind === "email") aliasEmailName(out, fake, value, taken, haystack);
    }
  }

  return out;
}

/** Addresses that belong to a desk rather than to somebody. */
const ROLE_LOCALS = new Set([
  "info", "sales", "support", "help", "helpdesk", "admin", "hello", "hi",
  "contact", "enquiries", "inquiries", "team", "office", "mail", "email",
  "billing", "accounts", "accounting", "invoices", "orders", "service",
  "jobs", "careers", "recruiting", "hr", "press", "media", "marketing",
  "legal", "privacy", "security", "abuse", "noreply", "donotreply", "no",
  "webmaster", "postmaster", "hey", "bookings", "reservations",
  // A web address's ending, from a local part that is itself a domain
  // ("shockwave.com@…"). Taken as a surname it was hidden wherever the
  // message wrote ".com" (bench/roundTrip, Enron).
  "com", "net", "org", "edu", "gov", "co", "io", "uk", "biz", "www",
]);

/**
 * The name a stand-in address implies, mapped back to the real one's.
 *
 * A fake email is minted as `first.last@domain`, which reads as a person —
 * and a model asked to write to colette.nakashima@proton.me addresses the
 * reply to "Colette". Restoration is exact-string, so that name matched
 * nothing and the stand-in came back to the user in their own answer: the
 * reply thanked somebody who does not exist, and the one thing the product
 * promises is that what comes back is in the user's own terms.
 *
 * Found on a real device, sending "a thank you note from Mel Harper at
 * Northwind Labs to dana@acme.com" — the person and the address were both
 * replaced and restored correctly, and the answer still said "Colette".
 *
 * So the fake's first name, last name and full name are mapped to the real
 * address's own local part, title-cased: "Colette" becomes "Dana". Only when
 * the real local part reads as a name — an address at info@, sales@, or
 * anything with digits in it has no name to restore to, and inventing one
 * would be a different wrong answer. Those keep the stand-in, which is
 * harmless: nothing addresses a reply to "info".
 *
 * Entries are added only if the key is free, so this can never overwrite a
 * mapping a real name already owns.
 */
function aliasEmailName(map: RedactionMap, fake: string, real: string, taken: Set<string>, haystack: string): void {
  const fakeLocal = fake.split("@")[0] ?? "";
  const [fakeFirst, fakeLast] = fakeLocal.split(".");
  if (!fakeFirst || !fakeLast) return;

  const realLocal = (real.split("@")[0] ?? "").trim();
  // Name-like: letters, optionally two parts, no digits, and long enough that
  // "hi@" or "j@" does not become a person.
  if (!/^[A-Za-z]{3,}([._-][A-Za-z]{2,})?$/.test(realLocal)) return;
  // A desk is not a person. "info@" passes the shape test above and would
  // restore the stand-in's first name to "Info", which is a stranger of a
  // different kind.
  if (realLocal.split(/[._-]/).some((part) => ROLE_LOCALS.has(part.toLowerCase()))) return;

  const title = (word: string) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
  const realParts = realLocal.split(/[._-]/).filter(Boolean).map(title);
  const realFirst = realParts[0];
  const realWhole = realParts.join(" ");

  // Not a name the message already holds, in any case or inside a longer
  // word: these keys are only ever restored, and a restore that found
  // "Rosalind" inside the person's own "Rosalinda" turned it into "Berrya"
  // (bench/roundTrip, Enron). pickFake checks its stand-ins the same way;
  // these are cut out of one and were not checked at all.
  const lower = lowered(haystack);
  const add = (key: string, value: string) => {
    if (!key || taken.has(key) || key in map) return;
    if (lower.includes(key.toLowerCase())) return;
    if (Object.keys(map).length >= MAX_REDACTION_ENTRIES) return;
    map[key] = value;
    taken.add(key);
  };

  const First = title(fakeFirst);
  const Last = title(fakeLast);
  // Longest first, the way the apply loop consumes them.
  add(`${First} ${Last}`, realWhole);
  add(First, realFirst);
  // The surname alone only has something true to restore to when the real
  // address carried two parts of its own.
  if (realParts.length >= 2) add(Last, realParts[realParts.length - 1]);
}
