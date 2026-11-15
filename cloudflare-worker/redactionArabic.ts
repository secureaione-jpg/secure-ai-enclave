/**
 * Saudi and Gulf numbers in Arabic text, which no other rule here reads.
 *
 * Measured on Sitr (mabahboh/sitr-arabic-pii, 2026-10-05), where the engine
 * caught 38.7% of identity numbers, 67% of phones and 1.3% of postcodes:
 *
 *   Identity   a Saudi national ID or iqama is ten digits opening with 1
 *              (citizen) or 2 (resident) and closing on a Luhn check digit.
 *              All 1,122 ten-digit IDs in Sitr's validation and test splits
 *              have that shape; a random ten-digit number has it one time in
 *              fifty.
 *   Phone      a Saudi mobile written without its trunk zero ("544498507")
 *              or with the country code and no plus ("966568432658").
 *   Postcode   five digits after "الرمز البريدي" (and the "الرمد البريدي"
 *              people type for it), or after ص.ب.
 *   Address    the Saudi short national address, four capitals and four
 *              digits ("UFEC8100", "HWVC٠٢٢٨"), which a message gives after
 *              "العنوان المختصر" or on its own, a prefix like و glued to it
 *              (moreLanguages practice half, 2026-10-31: 13 of 344 streets
 *              missed were these).
 *
 * Only in text with Arabic letters in it: in an English log, a ten-digit
 * number opening with 1 is a Unix time, and Luhn passes one in ten.
 */

export type ArabicValue = { start: number; end: number; kind: "govid" | "phone" | "postcode" | "address" };

const HAS_ARABIC = /\p{Script=Arabic}/u;
const DIGITS = "٠١٢٣٤٥٦٧٨٩";
/** Arabic-Indic digits read as ASCII, so one check covers both. */
const ascii = (s: string) => s.replace(/[٠-٩]/g, (d) => String(DIGITS.indexOf(d)));

function luhn(digits: string): boolean {
  let total = 0;
  for (let i = 0; i < digits.length; i += 1) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2) n = n * 2 > 9 ? n * 2 - 9 : n * 2;
    total += n;
  }
  return total % 10 === 0;
}

const ID = /(?<![\d٠-٩])([12١٢][\d٠-٩]{9})(?![\d٠-٩])/gu;
/**
 * The other Gulf identity numbers: Qatar's eleven digits and Kuwait's
 * civil ID of twelve, each opening with 2 or 3 for the century of birth
 * ("القطري 28185444279 والمدني 360120502447"); and any of nine to twelve
 * digits under the words for a personal, civil or identity number, which is
 * how Bahrain's nine-digit CPR comes ("الرقم الشخصي البحريني 746579968")
 * (moreLanguages practice half, 2026-11-02). A phone opens with 0, 5, 9 or
 * a plus, so none of these is one.
 */
const GULF_ID = /(?<![\d٠-٩+])([23٢٣][\d٠-٩]{10,11})(?![\d٠-٩])/gu;
const GULF_ID_CUED = /(?:الرقم\s+(?:الشخصي|المدني|القطري|الوطني)|البطاقة\s+(?:الذكية|المدنية)|(?:رقم\s+)?(?:ال)?هوية|رقم\s+الإقامة|وثيقة|المدني|القطري)(?:\s+\p{Script=Arabic}+)?[^\d٠-٩\n]{0,6}?(?<![\d٠-٩+])([\d٠-٩]{9,12})(?![\d٠-٩])/gu;
const PHONE = /(?<![\d٠-٩+])((?:(?:\+|00)?966|0)?5\d{8})(?!\d)/gu;
/** Not a word in capitals next to it, nor a code in a URL or a path. */
const SHORT_ADDRESS = /(?<![A-Za-z\d٠-٩\/._:#=-])([A-Z]{4}[\d٠-٩]{4})(?![A-Za-z\d٠-٩\/_@-])/gu;
/**
 * The place under a form's address or city label, which a Saudi form often
 * gives as the town alone, and with the next label on the same line:
 * "العنوان: القنفذه رقم الهوية: …", "المدينة: مكة المكرمة", "ميدنة السكن:
 * عفيف", "ومدينتي الدمام" (moreLanguages practice half, 2026-11-02: most of
 * the Arabic streets missed). Up to four words, and none of them the next
 * label.
 */
const ADDRESS_LABEL = /(?<![\p{L}])(?:و?(?:العنوان(?:\s+الوطني(?:\s+للفرع)?)?|عنوان\s+السكن|مكان\s+السكن|(?:مدينة|ميدنة)\s+السكن|المدينة|المدينه)\s*[:：]|و?مدينتي)\s*((?:\p{Script=Arabic}+\s*){1,4}(?:\p{Nd}{1,5}(?:\s*[,،]\s*\p{Script=Arabic}+(?:\s+\p{Nd}{5})?)?)?)/gu;
const NEXT_LABEL = /^(?:رقم|البند|الرمز|الرمد|الطرف|ملاحظات|ملاحظه|ملاحظة|الموضوع|تاريخ|الجوال|الهاتف|البريد|نطاق|مدة|الراتب|الجنسية|الاسم|اسم|الوظيفة|المسمى|الفرع|الحالة|الحي|ص)$/u;
/** A check's result under the label, not a place: "العنوان الوطني: مطابق". */
const NOT_A_PLACE = /^(?:مطابق|مطابقة|غير|تم|لا|نعم|موجود|متوفر|محدث|مسجل|صحيح|صحيحة|مؤكد|محجوز|فارغ|بدون)$/u;
/** The label may say whose code it is before the code, in up to four words:
 *  "الرمز البريدي المسجل في النظام: 65847", "الرمز البريدي للوحدة: 03975";
 *  and people type it "الرمززززز" and "الرزم", or say "العنوان البريدي" and
 *  "النطاق البريدي رقم" (moreLanguages practice half, 2026-11-02). */
const POSTCODE = /(?:(?:ال)?(?:رمز+|رمد|رزم)\s*(?:ال)?بريدي|(?:ال)?(?:عنوان|نطاق)\s+(?:ال)?بريدي|ص\.?\s*ب\.?)(?:\s+\p{Script=Arabic}+){0,4}?\s*[:：]?\s*([\d٠-٩]{5})(?![\d٠-٩])/gu;

export function findArabicValues(text: string): ArabicValue[] {
  if (!HAS_ARABIC.test(text)) return [];
  const out: ArabicValue[] = [];
  const take = (re: RegExp, kind: ArabicValue["kind"], ok: (v: string) => boolean = () => true) => {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const value = m[1];
      if (!ok(ascii(value))) continue;
      const start = (m.index ?? 0) + m[0].lastIndexOf(value);
      out.push({ start, end: start + value.length, kind });
    }
  };
  take(POSTCODE, "postcode");
  take(ID, "govid", luhn);
  take(GULF_ID, "govid");
  take(GULF_ID_CUED, "govid", (v) => !/^(?:0|5|9665)/.test(v));
  take(PHONE, "phone");
  // Not four letters that are one of the codes Arabic text quotes in Latin:
  // a currency, a flight, a standard.
  take(SHORT_ADDRESS, "address", (v) => !/^(?:ISO[A-Z]|IATA|ICAO|HTTP|UTF[A-Z]|SAR[A-Z]|USD[A-Z]|AED[A-Z]|COVI)/.test(v));
  for (const m of text.matchAll(ADDRESS_LABEL)) {
    if (NOT_A_PLACE.test(m[1].trim().split(/\s+/)[0])) continue;
    const start = (m.index ?? 0) + m[0].length - m[1].length;
    let end = start;
    for (const w of m[1].matchAll(/\p{Script=Arabic}+/gu)) {
      const after = m[1].slice((w.index ?? 0) + w[0].length);
      if (NEXT_LABEL.test(w[0]) || (/^\s*[:：]/.test(after) && end > start)) break;
      end = start + (w.index ?? 0) + w[0].length;
    }
    if (end > start) out.push({ start, end, kind: "address" });
  }
  return out;
}
