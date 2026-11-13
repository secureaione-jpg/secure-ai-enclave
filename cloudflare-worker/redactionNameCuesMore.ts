/**
 * Names the words around them give away, in the languages where realistic5's
 * name misses were (2026-10-26): what people put in front of a name or after
 * it instead of a capital letter, and the name fields of a form.
 *
 *   - a title or a word for a relative in front: "Pak Slamet", "BU LESTARI",
 *     "anh Kiên", "cậu Tư", "si Bea", "nonna Assunta";
 *   - glued in front, in Thai, which writes no spaces: "คุณนิตยา",
 *     "พี่เอก", "ป้าบัวผัน";
 *   - after, in Japanese and Korean: "野口医師", "피은서 님", "구본석 팀장";
 *   - a nickname with 老 or 小 and a surname in Chinese: "老黄";
 *   - under a name label on a form: "AD SOYAD:HATİCE KARAKAYA",
 *     "Họ và tên: ĐẶNG THỊ THANH HƯƠNG", "氏名：ヤマグチ　ケンジ".
 *
 * Every one is a cue, and what follows it is checked as any cued name is:
 * not a common word, not a place, not another language's ordinary word.
 * Never a single character: a value is swapped wherever it occurs, and one
 * Korean syllable or one kanji occurs inside other words.
 */
import { COMMON_CAPITALISED, isAcronym, isNotAPerson, isSentenceFragment, isTechnicalTerm } from "./redactionNameWords.js";
import { isForeignCommonWords } from "./redactionNameWordsIntl.js";
import { isSubstitutable } from "./redactionMap.js";
import { THAI_GIVEN_NAMES } from "./redactionThaiGivenNames.js";

const ok = (name: string) =>
  [...name].length >= 2 && !COMMON_CAPITALISED.has(name) && !isForeignCommonWords(name) && !isNotAPerson(name) &&
  !isAcronym(name) && !isSentenceFragment(name) && !isTechnicalTerm(name) && isSubstitutable(name);

const push = (out: string[], name: string) => { if (ok(name) && !out.includes(name)) out.push(name); };

/* A title or relative, then a capitalised name of one to three words. Not
   Portuguese "em" ("em Lisboa") nor Italian "tanti" ("tanti Auguri"). */
const BEFORE = [
  "Pak", "Bu", "Bapak", "Ibu", "Bang", "Om", "Mas", "Mbak", "Kak", "Tante", "Encik", "Cik", "Puan", "Datuk", "Tuan", // Indonesian, Malay
  "anh", "chị", "cô", "chú", "cậu", "bác", "ông", "bà",                                                            // Vietnamese
  "si", "kay", "ate", "kuya", "tita", "tito", "lola", "lolo",                                                     // Tagalog
  "nonna", "nonno", "zia", "zio", "nașa", "nașul", "nenea",                                                       // Italian, Romanian
  "svigerfar", "svigermor", "farmor", "mormor", "farfar", "morfar",                                               // Danish, Norwegian
];
const CUED = new RegExp(`(?<![\\p{L}])(?:${BEFORE.join("|")})[ \\t]+(\\p{Lu}[\\p{Ll}\\p{M}]+(?:[ \\t]\\p{Lu}[\\p{Ll}\\p{M}]+){0,2})(?![\\p{L}])`, "gu");
// A message typed in capitals types the name that way too: "KE BU LESTARI".
// One word only: the next is as likely the sentence ("LESTARI HARI INI").
const CUED_CAPS = new RegExp(`(?<![\\p{L}])(?:${BEFORE.map((w) => w.toUpperCase()).join("|")})[ \\t]+(\\p{Lu}{2,})(?![\\p{L}])`, "gu");

/* Thai: the title glued to the name. The word splitter cuts an unknown name
   into pieces ("นิต|ยา"), so the pieces up to the next ordinary word are
   joined back. คุณ is also "you", and the words that follow "you" are in the
   stop list, which is why it is long. */
const TH_BEFORE = new Set(["คุณ", "พี่", "น้อง", "ครู", "หมอ", "ลุง", "ป้า", "น้า", "อา", "นาย", "นาง", "นางสาว"]);
const TH_STOP = new Set(`ให้ ที่ จะ ไว้ บอก ว่า จ่าย เป็น คะ ค่ะ ครับ นะ ก็ ได้ ไม่ มี ช่วย ของ ไป มา ทำ กับ และ หรือ ยัง แล้ว วัน นี้ เลย ด้วย
ชาย สาว ใจดี สามารถ ต้องการ ควร อยาก ชอบ คิด รู้ ใช้ เคย กำลัง เอง ภาพ ค่า แม่ พ่อ ลูก คน ทุก ท่าน เขา เธอ เรา ผม ฉัน
ต้อง จริง มาก น้อย ดี อยู่ ถึง เมื่อ ถ้า แต่ เพราะ ใน บน จาก ตอน หน่อย ซื้อ ขาย ส่ง รับ ถาม ตอบ โทร ไหม มั้ย อะไร ใคร ที่ไหน
ครูใหญ่ หมอฟัน ประจำ ชั้น ใหม่ เก่า เพื่อน ช่าง แทน คือ ดูแล รวม ผู้ การ จัด แพทย์ ผู้จัดการ ลูกค้า งาน`.split(/\s+/));
const thaiWords = typeof Intl !== "undefined" && "Segmenter" in Intl ? new Intl.Segmenter("th", { granularity: "word" }) : null;

function thaiNames(text: string, out: string[]): void {
  if (!thaiWords || !/\p{Script=Thai}/u.test(text)) return;
  const segs = [...thaiWords.segment(text)].map((s) => s.segment);
  for (let i = 0; i < segs.length - 1; i++) {
    if (!TH_BEFORE.has(segs[i])) continue;
    let name = "";
    for (let j = i + 1; j < segs.length && j <= i + 3; j++) {
      const s = segs[j];
      if (!/^\p{Script=Thai}+$/u.test(s) || TH_STOP.has(s) || TH_BEFORE.has(s)) break;
      name += s;
    }
    if (!TH_STOP.has(name)) push(out, name);
  }
}

/* Thai: a listed given name where a name stands, with no title in front.
   The list holds ordinary words too ("สามารถ", "ใหม่", "ธนาคาร"), so a
   listed name is taken only:
     - after ชื่อ "named" or a title: "ชื่ออนุชา", "ด.ช.ธีรภัทร",
       "นางสาวณัฐธิดา" (the splitter cuts นางสาว apart, so the cue above
       misses it);
     - with a surname after one space: "สมศักดิ์ แก้วมณี,081-…";
     - as a chat's speaker: "ภูมิ: กินแล้วครับ";
     - giving itself after a colon: "ลูกค้า:ปิยะนุชค่ะ";
     - beside another listed name: "แพรวากับกฤษดา".
   The word splitter knows a common name as one word ("ธนากร") and an
   ordinary word the same way, so a short one-word name is not taken on a
   surname or a partner alone. */
const TH_WORDS = new Set(`สามารถ ใหม่ กรุงเทพ กรุณา น้ำตาล น้อย ชาติ อาทิตย์ ธรรม สุภาพ ภาค ประมวล ฟ้า ทานตะวัน สมัย สัมพันธ์
เจริญ หอม มานะ มิตร ตรี ปัญญา สหรัฐ สมควร มงคล ศักดิ์สิทธิ์ ชาญ นวล กรุง สุนทร บัญชา ลักษณ์ พงษ์ ธนาคาร คลัง นคร ชนะ
ทวี ถาวร ชัย ดี สุข รัก ทอง เพชร น้ำ ดาว เดือน แสง ใจ บุญ ศรี ทิพย์ ขวัญ`.split(/\s+/));
const TH_CUE = /(?:ชื่อ|นางสาว|นาง|นาย|ด\.ช\.|ด\.ญ\.|เด็กชาย|เด็กหญิง)[ \t]?$/u;
const TH_SURNAME = /^ (\p{Script=Thai}{3,14})(?=$|[\s,;:.)\]>|/]|\d)/u;
const isThai = (c: string | undefined) => !!c && /\p{Script=Thai}/u.test(c);

function thaiListedNames(text: string, out: string[]): void {
  if (!thaiWords || !/\p{Script=Thai}/u.test(text)) return;
  const segmenter = thaiWords;
  const cuts = new Set<number>([text.length]);
  for (const s of segmenter.segment(text)) cuts.add(s.index);
  // The splitter glues punctuation to the word after it: "ลูกค้า:ปิยะ", "ด.ช.ธีร".
  for (let i = 0; i < text.length; i++) if (isThai(text[i]) && !isThai(text[i - 1])) cuts.add(i);
  const long = (name: string) => [...segmenter.segment(name)].length > 1 || [...name].length >= 5;

  // The longest listed name from each word start, ending where a word ends:
  // not "สมหมาย" out of "สมหมายเลข".
  const hits: Array<{ start: number; end: number; name: string }> = [];
  for (const start of [...cuts].sort((a, b) => a - b)) {
    if (!isThai(text[start]) || (hits.length && start < hits[hits.length - 1].end)) continue;
    for (let end = Math.min(text.length, start + 16); end > start + 1; end--) {
      const name = text.slice(start, end);
      if (!cuts.has(end) || !THAI_GIVEN_NAMES.has(name)) continue;
      if (!TH_WORDS.has(name)) hits.push({ start, end, name });
      break;
    }
  }

  for (const [i, h] of hits.entries()) {
    const before = text.slice(Math.max(0, h.start - 10), h.start);
    const after = text.slice(h.end, h.end + 20);
    const cued = TH_CUE.test(before);
    const s = cued || (!isThai(text[h.start - 1]) && long(h.name)) ? TH_SURNAME.exec(after) : null;
    // Not the sentence going on: "ดวงจันทร์ ที่ดังที่สุด", "the most famous".
    const surname = s && !TH_STOP.has([...segmenter.segment(s[1])][0].segment) && !TH_WORDS.has(s[1]) ? s[1] : "";
    if (surname) { push(out, `${h.name} ${surname}`); continue; }
    if (cued) { push(out, h.name); continue; }
    if (/(?:^|\n|\])[ \t]*$/.test(before) && /^[ \t]*:/.test(after)) { push(out, h.name); continue; }
    if (/[:：][ \t]*$/.test(before) && /^(?:ค่ะ|คะ|ครับ)/.test(after)) { push(out, h.name); continue; }
    const next = hits[i + 1];
    if (next && /^(?:กับ|และ)$/.test(text.slice(h.end, next.start)) && long(h.name) && long(next.name)) {
      push(out, h.name);
      push(out, next.name);
    }
  }
}

/* Japanese: a name, then the word for what the person is to the writer.
   Not the words that are not names in front of those: 皆様, 患者様,
   お客様, 王様 (a king as often as Mr Wang). */
const JA_AFTER = /(?<=^|[\sのはがをにへともや、。「」『』：:（）()])([\p{Script=Han}]{2,4}|[\p{Script=Katakana}ー]{2,8}|[\p{Script=Hiragana}]{2,5})(?=先生|医師|様|さん|くん|君|ちゃん|おじいちゃん|おばあちゃん|部長|課長|社長|弁護士)/gmu;
const JA_NOT = new Set(["皆さ", "みな", "お客", "患者", "担当", "主治", "女王", "王子", "お父", "お母", "お兄", "お姉", "おじい", "おばあ", "子供", "赤ち", "お嬢", "お疲れ", "ご苦労", "皆々", "各位", "校長", "先輩", "神様", "奥さ", "旦那"]);

/* Korean: a name before 님 or 씨, and a three-syllable name before a job title. */
const KO_HONORIFIC = /(?<![가-힣])([가-힣]{2,4})[ \t]?(?:님|씨)(?![가-힣])/gu;
const KO_ROLE = /(?<![가-힣])([가-힣]{3})[ \t](?:팀장|과장|부장|차장|대리|사원|주임|실장|원장|이사|선생님|교수님|변호사)(?:님|에게|께|이|가|은|는|을|를|의|과|와|한테)?(?![가-힣])/gu;
/* A whole name of two to four words before 님 or 씨, the way a letter
   writes a name with its parts apart, or half in Latin letters: "근민 철우
   산 님", "태수 좌 님", "재문 순이 Bech님" (moreLanguages practice half,
   2026-10-31). Taken as one value, so a one-syllable surname inside it is
   swapped only there. A word of four syllables or more is the sentence, not
   a name, and ends the run; a greeting, a title or a role in front of it is
   dropped (KO_RUN_LEAD). */
/** A word of a Korean name: up to three syllables and not a particle on its
 *  own, or a capitalised Latin word. */
const KO_NAME_WORD = String.raw`(?:(?!(?:은|는|이|가|을|를|의|와|과|도|님|씨)(?![가-힣]))[가-힣]{1,3}|\p{Lu}[\p{Ll}\p{M}'’-]+)`;
const KO_RUN = new RegExp(String.raw`(?<![가-힣\p{Script=Latin}])(${KO_NAME_WORD}(?:[ \t]${KO_NAME_WORD}){1,3})[ \t]?(?:님|씨)(?:의|께서?|은|는|이|가|을|를|에게|과|와)?(?![가-힣])`, "gu");
const KO_RUN_LEAD = new Set(["양", "군", "씨", "님", "고객", "회원", "선생", "교수", "학생", "환자", "보호자", "담당자", "신청인", "수신인", "성명", "이름", "Dear", "Hi", "Hello", "Mr", "Ms", "Mrs", "Miss", "Dr", "안녕", "저는", "제", "우리", "그", "이", "저", "및", "또는", "그리고", "같이", "함께", "모든", "각", "해당", "본", "귀하", "대한", "위한", "오늘", "다시", "바로"]);

/* And three more ways a Korean letter or form sets a name apart: 양 or 군
   (Miss, Master) before two words or more, closed by a particle, a comma or
   a bracket — "양 진우 현태 탕 은(는)"; "Dear" before Hangul, "Dear 홍기,";
   and the form's 성명 (full name) before the name or after it in brackets,
   "성명 성민 권률 용,", "근율 좌 (성명)". One word after 양 is "양 조절",
   an amount, and is not read. */
const KO_TITLE_RUN = new RegExp(String.raw`(?<![가-힣\p{Script=Latin}])(?:양|군)[ \t]+(${KO_NAME_WORD}(?:[ \t]${KO_NAME_WORD}){1,3})(?=[ \t]*(?:님|은\(는\)|,|\(|께))`, "gu");
const KO_DEAR = /(?<![\p{L}])Dear[ \t]+([가-힣]{2,4}(?:[ \t][가-힣]{1,3}){0,2})(?=[ \t]*[,，])/gu;
const KO_FORM = new RegExp(String.raw`(?<![가-힣])성명[ \t]*[:：]?[ \t]+(${KO_NAME_WORD}(?:[ \t]${KO_NAME_WORD}){1,3})(?=[ \t]*[,，(\n])|(?<![가-힣\p{Script=Latin}])(${KO_NAME_WORD}(?:[ \t]${KO_NAME_WORD}){1,3})[ \t]*\(성명\)`, "gu");

function koreanRuns(text: string, out: string[]): void {
  if (!/[가-힣]/.test(text)) return;
  for (const re of [KO_TITLE_RUN, KO_DEAR, KO_FORM]) {
    for (const m of text.matchAll(re)) {
      const name = m[1] ?? m[2];
      if (name && !name.split(/[ \t]+/).some((w) => KO_NOT.has(w) || KO_RUN_LEAD.has(w))) push(out, name);
    }
  }
  for (const m of text.matchAll(KO_RUN)) {
    const words = m[1].split(/[ \t]+/);
    while (words.length && (KO_RUN_LEAD.has(words[0]) || KO_NOT.has(words[0]) || /(?:님|께|에게|께서|은|는|이|가|을|를|의)$/.test(words[0]) && [...words[0]].length >= 3)) words.shift();
    if (words.length < 2) continue;
    if (words.reduce((n, w) => n + [...w].length, 0) < 3) continue;
    push(out, words.join(" "));
  }
}

const KO_NOT = new Set(["고객", "회원", "사장", "선생", "교수", "기사", "여러분", "부모", "어머", "아버", "할머", "할아버", "아저", "아가", "형", "누나", "언니", "오빠", "선배", "후배", "작가", "환자", "손님", "신부", "신랑", "사모", "따님", "아드", "주인", "관리자", "담당자", "대표", "사용자", "구매자", "판매자"]);

/* Chinese: 老 or 小 and a surname, a nickname nobody writes about a stranger. */
const ZH_SURNAMES = "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤張劉陳楊黃趙吳孫馬鄭謝韓馮鄧蕭葉蘇呂盧鍾譚陸錢嚴龔";
const ZH_NICK = new RegExp(`(?<![\\p{Script=Han}])((?:老|小)[${ZH_SURNAMES}])([\\p{Script=Han}]?)`, "gu");
/** Words that start like a nickname and are not one. */
/* Chinese: a salutation or a title, then a name written in parts, the given
   name first and the surname apart, or half in Latin letters: "尊敬的Mr. 籽萱
   薛，", "亲爱的 立恒 时，", "联系组织者玓蓉 黄。", "Ms.福寿 硕芸 武的"
   (moreLanguages practice half, 2026-10-31). Up to the punctuation or the
   的 that ends it, and two characters at least between the words, so one
   surname alone after "尊敬的Ms." is not taken. */
// A given name or a surname is one character or two; three is the sentence
// going on ("祁 请留意").
const ZH_NAME_WORD = String.raw`(?:[\p{Script=Han}]{1,2}|\p{Lu}[\p{Ll}\p{M}'’-]+)`;
const ZH_SALUTED = new RegExp(
  String.raw`(?:尊敬的|亲爱的|致|女士|先生|小姐|组织者|收件人|申请人(?:姓名)?[:：]?|(?<![\p{Script=Latin}])(?:Mr|Ms|Mrs|Miss|Dr|GM|Teacher)\.?)[ \t]*` +
  String.raw`(?:(?:(?:Mr|Ms|Mrs|Miss|Dr)\.?|先生|女士|小姐)[ \t]*)?(?!先生|女士|小姐)(${ZH_NAME_WORD}(?:[ \t]${ZH_NAME_WORD}){1,4})(?=[ \t]*(?:[，,、。！!：:（(；;]|的|$))`,
  "gmu",
);

const ZH_NOT = new Set(["小王子", "老黄历", "老黄牛", "小李飞", "小马过", "老王卖", "小金库", "小白兔", "小白鼠", "老白干", "小朱雀", "老江湖", "小方块", "老方法", "小高潮", "小程序", "老程序"]);

/* A form's name field. The value runs to the end of the line, a run of two
   spaces, punctuation, a digit, or the next field's label; four or five
   words at most, and the next label's words come off its end. */
const NAME_LABELS = [
  "ad soyad", "adı soyadı", "ad-soyad", "soyadı",
  "họ và tên", "họ tên",
  "שם משפחה", "שם פרטי", "שם מלא",
  "氏名", "患者氏名", "お名前", "姓名", "名前", "이름", "성명",
  "фио", "имя", "фамилия", "отчество", "прізвище", "ім'я",
  "nama lengkap", "pangalan", "buong pangalan",
  "nombre completo", "nombre y apellidos", "apellidos", "nome completo", "cognome",
  "imię i nazwisko", "nazwisko", "imię", "jméno a příjmení", "příjmení", "jméno",
  "fullt navn", "fullständigt namn", "koko nimi", "teljes név", "ονοματεπώνυμο", "επώνυμο", "όνομα",
  "पूरा नाम", "नाम", "নাম", "பெயர்", "పేరు", "ชื่อ-สกุล", "الاسم الكامل", "الاسم",
];
const FORM_NAME = new RegExp(
  `(?<![\\p{L}])(?:${NAME_LABELS.join("|")})[ \\t]*[:：][ \\t]*` +
    `([\\p{L}\\p{M}'’-]+(?:[ \\t\\u3000][\\p{L}\\p{M}'’-]+){0,4})` +
    `(?=[ \\t]{2}|[ \\t]*(?:\\n|$|[,;|/]|\\d)|[ \\t]+[\\p{L}.]{1,12}(?:[ \\t][\\p{L}.]{1,12}){0,2}[ \\t]*[:：])`,
  "giu",
);
/** The next field's words caught on the end of a name: "HATİCE KARAKAYA TC
 *  KİMLİK NO:", "ĐẶNG THỊ THANH HƯƠNG Số CCCD:". */
const FORM_WORDS = new Set(["tc", "kimlik", "no", "nr", "số", "cccd", "cmnd", "tel", "sdt", "sđt", "id", "dob", "nik", "ktp", "pesel", "dni", "nie", "cpf", "rg", "snils"]);

export function moreCuedNames(text: string, out: string[]): void {
  for (const m of text.matchAll(CUED)) push(out, m[1]);
  for (const m of text.matchAll(CUED_CAPS)) push(out, m[1]);
  thaiNames(text, out);
  thaiListedNames(text, out);
  for (const m of text.matchAll(JA_AFTER)) if (!JA_NOT.has(m[1])) push(out, m[1]);
  for (const m of text.matchAll(KO_HONORIFIC)) if (!KO_NOT.has(m[1])) push(out, m[1]);
  for (const m of text.matchAll(KO_ROLE)) if (!KO_NOT.has(m[1])) push(out, m[1]);
  koreanRuns(text, out);
  for (const m of text.matchAll(ZH_NICK)) if (!ZH_NOT.has(m[1] + m[2])) push(out, m[1]);
  if (/\p{Script=Han}/u.test(text)) {
    for (const m of text.matchAll(ZH_SALUTED)) {
      if ((m[1].match(/\p{Script=Han}/gu) ?? []).length >= 2) push(out, m[1]);
    }
  }
  for (const m of text.matchAll(FORM_NAME)) {
    const sep = m[1].includes("　") ? "　" : " ";
    const words = m[1].trim().split(/[ \t　]+/);
    // Turkish lower case, so "KİMLİK" is "kimlik" and not "ki̇mli̇k".
    while (words.length > 1 && FORM_WORDS.has(words[words.length - 1].toLocaleLowerCase("tr"))) words.pop();
    if (words.every((w) => !COMMON_CAPITALISED.has(w))) push(out, words.join(sep));
  }
}
