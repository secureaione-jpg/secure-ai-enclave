/**
 * Addresses and postcodes written the way Japan, China and Korea write them.
 *
 * Every address rule elsewhere in this engine starts from a Latin street word
 * or a European prefix, and on ai4privacy's Japanese, Chinese and Korean rows
 * (pii-masking-micro-100k, 2026-10-05) streets and postcodes were found
 * between 0% and 5% of the time. The shapes are regular:
 *
 *   Japan   a district and its block, lot and building — "上飯田東町 2-20-33",
 *           "1-18-26 加茂内町" — and a seven-digit postcode, "243-0425",
 *           "〒222-0032".
 *   China   a road (路 街 道 巷 大道 弄 胡同 里) and its number with or
 *           without 号 — "通站路 523号", "1027 号 世歌路" — and a six-digit
 *           postcode after 邮编 or 邮政编码.
 *   Korea   a road name (로 길 대로, "청수로3길", "배곶로40번길") and its
 *           building number, "마장로 407", "보문산로길 591번지", and a
 *           five-digit postcode after 우편번호 or after the city it belongs to.
 *
 * Each needs its script around it, so none of these can fire on a Latin
 * message: "2-20-33" is a score in English and a lot in Japanese.
 */

export type AsianAddress = { start: number; end: number; kind: "address" | "postcode" };

const HAN = String.raw`\p{Script=Han}`;
const KANA = String.raw`\p{Script=Hiragana}\p{Script=Katakana}ー`;
const HANGUL = String.raw`\p{Script=Hangul}`;

/** Japanese: a place name in kanji or kana, then chōme-ban-gō, either way round. */
// Three numbers, or two with 番 or 号 after them: "07-10.89" is a phone.
const JA_NUMBER = String.raw`(?:[1-9]\d?-[1-9]\d?-[1-9]\d{0,3}(?:番地|番|号)?|[1-9]\d?-[1-9]\d?(?:番地|番|号))`;
// The place in kanji and katakana only: hiragana is the grammar between words
// ("切牛の上飯田東町" is "上飯田東町 of 切牛"), so a run stops at it.
const JA_PLACE = String.raw`[${HAN}\p{Script=Katakana}ー]{2,10}`;
// With の, "of", between them, either way round: "唐浜の3-3-24", "中豊岡町 の
// 8-11-35", "8-23-46番地の宮川町西忍" (moreLanguages practice half,
// 2026-11-02). After the number, only a place with a town's or a city's word
// in it: "3-1-2の試合" is a score.
const JA_TOWN_PLACE = String.raw`[${HAN}\p{Script=Katakana}ー]{0,6}[町村区市郡][${HAN}\p{Script=Katakana}ー]{0,6}`;
const JA_BLOCK = new RegExp(
  String.raw`${JA_PLACE}[ \t　]?(?:の[ \t　]?)?${JA_NUMBER}(?![\d.-])` +
  String.raw`|(?<![\d.-])${JA_NUMBER}の${JA_TOWN_PLACE}` +
  String.raw`|(?<![\d.-])${JA_NUMBER}[ \t　]?${JA_PLACE}`,
  "gu",
);
/** Japanese postcode: 〒 or the word for it, or a 3-4 shape inside Japanese. */
const JA_POSTCODE = /(?:〒|郵便番号[:：\s]*(?:は)?)\s*(\d{3}-?\d{4})(?!\d)|(?<![\d-])(\d{3}-\d{4})(?![\d-])/gu;

/** Chinese: a road word with its number on either side. */
// 街道 is a sub-district, not a road: "新街口街道 200082" is its postcode.
// The road's name stops at the small words of the sentence around it:
// "建议更新其在通站路 523号" is "suggest updating its [address] at 通站路 523号".
const ZH_NAME = String.raw`(?:(?![在于到的至从往其和与及向对把被给为是请将我你他她们])[${HAN}]){1,6}`;
// And the word must be a road's: 走路 is walking, 思路 an idea, 知道 to know,
// 报道 a report, 骂街 a shouting match, 两万里 a distance (WildChat) — so the
// road word is not one of those, and the number is a building's: 号 after
// it, or two digits or more that are not a year, a date, a chapter or a count.
const ZH_ROAD_WORD = String.raw`(?:(?<![走思马铁公小网线道一])路|(?<![骂上逛])街(?!道)|(?<![街知报频味渠轨管难人赤大])道|巷|大道|弄|胡同)`;
// A comma may stand between the road and a number with 号, as a form lists
// them: "632 号，仪凤巷", "清溪路，1381号" (moreLanguages practice half,
// 2026-11-02). Without 号 the number after a comma is the sentence's.
const ZH_ROAD = new RegExp(
  String.raw`${ZH_NAME}${ZH_ROAD_WORD}(?:[ \t]*路)?(?:[ \t]*(?:\d{1,5}[ \t]*号|\d{2,5}(?![\d年月日章节点个%％.-]))|[ \t]*[，,][ \t]*\d{1,5}[ \t]*号)` +
  String.raw`|(?<!\d)\d{1,5}[ \t]*号[ \t]*(?:[，,][ \t]*)?${ZH_NAME}${ZH_ROAD_WORD}`,
  "gu",
);
/** Chinese: a flat in a residential compound, building, entrance and room:
 *  "朝阳区望京西园三区312号楼1单元502", "绿城花园3栋2单元1102室". No road word,
 *  so ZH_ROAD missed them (realistic2). The room number is asked for, so "3号楼"
 *  alone, a building in a sentence, is not taken. */
const ZH_FLAT = new RegExp(
  String.raw`(?:${ZH_NAME}(?:区|县|镇|村|小区|社区|花园|新村|公寓|大厦|苑|园)){0,3}(?:${ZH_NAME})?\d{1,4}[ \t]*(?:号楼|栋|幢|座)[ \t]*(?:\d{1,3}[ \t]*单元[ \t]*)?\d{2,5}(?:室|号|户)?(?![\d年月日])`,
  "gu",
);
/**
 * Chinese: a whole address, province or city down to the room, as forms and
 * parcels write it: "江苏省南京市玄武区中山路218号3栋502室", "新北市板橋區
 * 文化路一段188巷7號3樓", "高雄市苓雅區四維三路6號8樓之2", "四川省成都市武侯区
 * 天府大道北段1700号环球中心E2区1607". ZH_ROAD took the road and number from
 * the middle and left the city, district and flat to be sent (realistic5,
 * 2026-10-25). A city or district must lead, and the number must have 号 or 號.
 */
const ZH_ADMIN = String.raw`(?:${ZH_NAME}(?:省|自治区|自治區|特别行政区))?(?:${ZH_NAME}(?:市|县|縣|州|盟))?(?:${ZH_NAME}(?:区|區|县|縣|镇|鎮|乡|鄉|旗))?(?:${ZH_NAME}(?:街道|镇|鎮))?`;
const ZH_FULL_ROAD = String.raw`${ZH_NAME}(?:路|街|大道|道)(?:[东西南北中一二三四五六七八九十\d]{1,3}段)?(?:\d{1,4}[巷弄])*`;
const ZH_FULL_TAIL = String.raw`(?:(?:${ZH_NAME}(?:大厦|大廈|中心|广场|廣場|大楼|大樓|花园|花園|小区|小區|公寓))?(?:[A-Z]?\d{1,3}(?:栋|棟|幢|座|号楼|號樓|区|區)[ \t]?\d{1,4}(?:室|号|號)?|[ \t]?\d{1,4}(?:楼|樓|层|層|室|单元|單元)(?:之\d{1,2})?)){0,3}`;
const ZH_FULL_ADDRESS = new RegExp(
  // Not the label in front: "地址四川省…" starts at 四川.
  String.raw`(?:(?<=地址|住址|地點|地点|收货地址|收貨地址)|(?<!地|住))(?!地址|住址)(?=${ZH_NAME}(?:省|市|县|縣|区|區))${ZH_ADMIN}${ZH_FULL_ROAD}[ \t]?\d{1,5}(?:-\d{1,4})?[号號]${ZH_FULL_TAIL}`,
  "gu",
);

/** Chinese postcode under its label, with 为 or 是 after it or not; or six
 *  digits beside a district, a city or a sub-district with only a comma
 *  between, as an address lists them: "830000，未央区", "联盟街道，518000"
 *  (moreLanguages practice half, 2026-11-02). A postcode opens with 1 to 8. */
const ZH_POSTCODE = new RegExp(
  String.raw`(?:邮编|邮政编码)(?:为|是)?[:：\s（(]*(\d{6})(?!\d)` +
  String.raw`|(?<![\d.])([1-8]\d{5})(?=[ \t]*[，,][ \t]*[${HAN}]{1,6}(?:区|县|市|街道|镇))` +
  String.raw`|(?<=[${HAN}](?:区|县|市|街道|镇)[ \t]*[，,][ \t]*)([1-8]\d{5})(?![\d.])`,
  "gu",
);

/** Korean: a road name and its building number. */
// -로 is also the ending "with, to" ("자료로 15반", "예시로 1945-12-29"), so
// the number must end there: nothing but 번지 or 번, then no letter, digit,
// dash or @ — a building number is the end of its phrase.
const KO_ROAD = new RegExp(
  // …or a case ending, which Korean writes onto the number itself: "마장로
  // 407에 거주합니다", "49번이며".
  // -으로 is never a road ("처음으로 10", "주기적으로 1"), and a road's
  // number ends an address: 번지 or 번, a case ending, punctuation, the end,
  // or the city after it. "상대로 3골" is a score.
  // The side street may stand apart from its road: "월드컵북로 38길 12".
  String.raw`[${HANGUL}]{1,10}(?<!으)(?:대로|로|길)(?:[ \t]?\d{1,3}(?:번)?길)?(?:[ \t]*거리)?[ \t]*\d{1,4}(?:-\d{1,4})?(?:번지|번)?(?=(?:에서|에|이며|이고|의|까지)(?![\p{L}\d])|호?(?:[ \t]*[,.)\n(]|$|[ \t]+[${HANGUL}]+(?:시|구|군|동|도|읍|면)(?![\p{L}])))`,
  "gu",
);
/** Korean postcode: under its label, or right after the city it belongs to.
 *  The label takes its particle as often as a colon — "우편번호는 61057이며"
 *  — and the code comes before a city or the word for a district as often
 *  as after: "61960 인천광역시", "44686 지역에" (moreLanguages practice half,
 *  2026-10-31). */
const KO_POSTCODE = new RegExp(
  String.raw`우편번호(?:는|은|가|이|를)?[:：\s]*(\d{5})(?!\d)|(?<=[${HANGUL}](?:시|구|군|동|도)[ \t,]*)(\d{5})(?!\d)` +
  String.raw`|(?<![\d.,\p{Script=Latin}-])(\d{5})(?=[ \t]*(?:지역|[${HANGUL}]{1,6}(?:특별시|광역시|특별자치시|특별자치도)))`,
  "gu",
);
/** Korean: a side street by its name alone, a road and a number and 길,
 *  "동원로11길", "월산로116번길", "한강대로40길", with no building number
 *  after it (moreLanguages practice half, 2026-11-02). Nothing else is
 *  written so. */
const KO_SIDE_STREET = new RegExp(String.raw`(?<![${HANGUL}\d])[${HANGUL}]{1,10}(?<!으)(?:대로|로|길)\d{1,4}(?:번)?길`, "gu");

const HAS_JA = /[\p{Script=Hiragana}\p{Script=Katakana}]/u;
const HAS_HAN = /\p{Script=Han}/u;
const HAS_HANGUL = /\p{Script=Hangul}/u;

export function findAsianAddresses(text: string): AsianAddress[] {
  const out: AsianAddress[] = [];
  const take = (re: RegExp, kind: AsianAddress["kind"]) => {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const value = m.slice(1).find((g) => g !== undefined) ?? m[0];
      const start = (m.index ?? 0) + m[0].indexOf(value);
      out.push({ start, end: start + value.length, kind });
    }
  };
  // Japanese has kana; Chinese has Han and no kana; Korean has Hangul.
  if (HAS_JA.test(text)) {
    take(JA_BLOCK, "address");
    take(JA_POSTCODE, "postcode");
  } else if (HAS_HAN.test(text)) {
    // The whole address first, so the road inside it is not taken alone.
    take(ZH_FULL_ADDRESS, "address");
    take(ZH_ROAD, "address");
    take(ZH_FLAT, "address");
    take(ZH_POSTCODE, "postcode");
  }
  if (HAS_HANGUL.test(text)) {
    take(KO_ROAD, "address");
    take(KO_SIDE_STREET, "address");
    take(KO_POSTCODE, "postcode");
  }
  return out;
}
