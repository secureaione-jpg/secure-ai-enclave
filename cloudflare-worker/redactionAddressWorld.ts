/**
 * Addresses and postcodes in shapes the European and Asian street rules do
 * not reach. realistic5 still missed each of these (2026-10-26):
 *
 *   Philippines  a barangay — "23 P. Burgos St., Brgy. Poblacion", "Blk 7
 *                Lot 12, Phase 2, Brgy. San Isidro", "Purok 4, Brgy. Mabini"
 *                — and the four-digit postcode after the city, "Quezon City
 *                1100".
 *   India        an address typed in lower case after the word itself, as
 *                chats do: "address 45 nehru st, gandhipuram", "12-5-34, mvp
 *                colony sector 4", and the six-digit PIN that follows.
 *   Vietnam      the number before the street: "142/7 đường Trần Hưng Đạo,
 *                phường An Phú".
 *   Czech and    the street name and its two numbers, "Vinohradská 1874/112",
 *   Slovak       or a Slovak "-ova" street, "Štúrova 9".
 *   Greece       a street in the genitive after "στην" or "οδός": "στην
 *                Πατησίων 210".
 *   Hungary      postcode and town first, then the street with its number
 *                and full stop: "9400 Sopron, Várkerület 41."
 *
 * Each is tied to a word or a letter of its own language, so none of them
 * reads an English sentence.
 */

const NAME = String.raw`\p{Lu}[\p{L}\p{M}.'’-]*`;

/** "Brgy", "BRGY", "Barangay", "Bgy" with or without the full stop. */
const BRGY = String.raw`(?:[Bb](?:rgy|RGY|gy|GY|arangay|ARANGAY)\.?)`;
const PH_STREET_WORD = String.raw`(?:St|ST|Street|STREET|Ave|AVE|Avenue|AVENUE|Rd|RD|Road|ROAD|Blvd|BLVD|Drive|DRIVE|Dr|Ext|EXT|Highway|Hwy)\.?`;
const PH_PIECE = String.raw`(?:(?:Blk|BLK|Block|BLOCK)\.?[ \t]*\d{1,4}[A-Z]?[ \t]+(?:Lot|LOT)[ \t]*\d{1,4}[A-Z]?` +
  String.raw`|(?:Purok|PUROK|Phase|PHASE|Sitio|SITIO|Zone|ZONE)[ \t]+(?:\d{1,3}[A-Z]?|${NAME}(?:[ \t]+${NAME})?)` +
  String.raw`|(?:\d{1,5}[A-Z]?(?:-[A-Z])?[ \t]+)?(?:${NAME}[ \t]+){1,3}${PH_STREET_WORD})`;
/** Up to two pieces before the barangay, each with its comma, and the barangay's name. */
export const PH_BARANGAY_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])(?:${PH_PIECE},?[ \t]+){0,2}${BRGY}[ \t]+[\p{Lu}\d][\p{L}\p{M}\d.'’-]*(?:[ \t]+[\p{Lu}\d][\p{L}\p{M}\d'’-]*){0,2}`,
  "gu",
);
/** Run the Philippine rules at all. */
export const HAS_BARANGAY = new RegExp(String.raw`(?<![\p{L}])(?:${BRGY}|Purok|PUROK)[ \t]`, "u");
/** The four digits after the city: "Quezon City 1100", "ANTIPOLO CITY 1870". */
export const PH_POSTCODE_PATTERN = /(?<=\b(?:City|CITY|Municipality|Manila|MANILA)[ \t]+)(\d{4})(?![\d-])/gu;

/** The words an Indian address ends its street with, in English letters. */
const IN_STREET_WORD = String.raw`(?:st|street|road|rd|colony|nagar|layout|lane|marg|salai|veedhi|veedi|puram|pet|palem|enclave|extension|extn)\.?`;
const IN_CUE = String.raw`(?:address|addr|adress|vilasam|vilasamu|pata)`;
/** "address 45 nehru st, gandhipuram", "address 12-5-34, mvp colony sector 4". */
export const IN_LOWER_ADDRESS_PATTERN = new RegExp(
  String.raw`(?<=\b${IN_CUE}(?:[ \t]+is)?[ \t]*[:-]?[ \t]*)(\d{1,4}(?:[-/]\d{1,4}){0,3}[A-Za-z]?,?[ \t]+((?:[\p{L}]+[ \t]+){0,3}?)${IN_STREET_WORD}(?:[ \t]+(?:sector|phase|block|stage)[ \t]+\d{1,2})?(?:,[ \t]*[\p{L}]+(?:[ \t]+(?:sector|phase|block|stage)[ \t]+\d{1,2})?)?)(?![\p{L}\p{N}])`,
  "giu",
);
/** Words that make the run in front of the street word a sentence, not a name. */
export const IN_NOT_A_STREET = /^(?:the|a|an|on|in|of|to|and|or|for|with|from|at|by|this|that|these|those|my|your|our|their|his|her|issues?|points?|questions?|problems?|items?|things?|ways?|steps?|times?)$/i;
/** A six-digit PIN within a line of the word address or pin. */
export const IN_PIN_PATTERN = /(?<=\b(?:address|addr|adress|pin|pincode|pin\s+code|vilasam)\b[^\n]{0,80}?[\s,])([1-8]\d{5})(?![\d-])/giu;

/**
 * Six digits standing alone in Hindi or Telugu text: "कृपया अपना 502313 और
 * Bengaluru हमें बताएं", "209111 ప్రాంతంలో నివసిస్తున్నారు". There a lone six-digit
 * number is a PIN or a one-time code, and both are private. Phones have ten
 * digits; an amount is written with ₹ or Rs, rupees after it, or in lakh
 * groups ("5,02,313"), and none of those are taken. Telugu writes "in" and
 * "with" onto the number itself (440034లో, 508286తో), so a Telugu letter may
 * follow; రూపాయలు still marks an amount. The multilingual bench's
 * Hindi and Telugu PINs were caught 13% of the time.
 */
export const HAS_INDIC = /[\p{Script=Devanagari}\p{Script=Telugu}]/u;
export const IN_PIN_INDIC_PATTERN =
  /(?<![\p{L}\p{N}₹$€£+.,:/#-]|(?:Rs|INR|रु)\.?\s?)([1-8]\d{5})(?![\p{N}.,/%-]|\s?(?:रुपये|रुपए|रुपया|रु|రూపాయ|lakh|crore|kg|km|mg|ml)|(?!\p{Script=Telugu})\p{L})/gu;

/**
 * An Indian street in English letters inside Hindi or Telugu: "Khairagarh में
 * Agra Road पर", "Gangoh Roadపై", "Sant Gagangiri Maharaj Marg 348 पर",
 * "Sector 35 Road వద్ద". The script change marks where the name starts and
 * stops, so no number is needed. Initials count as words (M B Road).
 */
export const IN_STREET_INDIC_PATTERN =
  /(?<![\p{L}\p{N}])\p{Lu}\p{Ll}*(?:[ \t]+(?:\p{Lu}\p{Ll}*|\d{1,3})){0,4}[ \t]+(?:Road|Marg|Expressway|Highway|Bypass|Setu|Row|Lane|Street)(?:[ \t]+\d{1,4}(?:\/\d{1,3})?)?(?![\p{Script=Latin}\p{N}])/gu;

/** "142/7 đường Trần Hưng Đạo, phường An Phú". The word for a district or
 *  city ends the name: "phường An Phú TP Cần Thơ". */
const VN_WORD = String.raw`(?!(?:TP|Tp|Quận|Q|Huyện|Thành|Tỉnh|Thị)(?![\p{L}\p{M}]))\p{Lu}[\p{L}\p{M}]*`;
export const VN_NUMBER_FIRST_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])\d{1,4}[A-Z]?(?:\/\d{1,4}[A-Z]?){0,3}[ \t]+(?:đường|Đường|phố|Phố|ngõ|Ngõ|hẻm|Hẻm|ngách|Ngách)[ \t]+${VN_WORD}(?:[ \t]+${VN_WORD}){0,4}` +
  String.raw`(?:,[ \t]*(?:phường|Phường|xã|Xã|P\.)[ \t]*(?:\d{1,2}|${VN_WORD}(?:[ \t]+${VN_WORD}){0,3}))?`,
  "gu",
);

/** "Vinohradská 1874/112", "Národní třída 12", "Štúrova 9": the endings Czech
 *  and Slovak street names take, and their number
 *  — a bare number only after "-ova": "Národní 3 hráči" is three players. */
export const CS_STREET_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])(?:\p{Lu}[\p{Ll}]+[ \t]+)?(?:\p{Lu}[\p{Ll}]*(?:ská|cká|ní|ova|ová|ého|ovo)(?:[ \t]+(?:třída|nábřeží|náměstí|námestie|cesta))?[ \t]+\d{1,5}\/\d{1,4}[a-zA-Z]?|\p{Lu}[\p{Ll}]*ova[ \t]+\d{1,4}[a-zA-Z]?)(?![\p{L}\p{N}\/])`,
  "gu",
);
/** Run CS_STREET_PATTERN at all: a letter only Czech or Slovak writes. */
export const HAS_CZECH_SLOVAK = /[ěščřžůťďňľĺôĚŠČŘŽŮŤĎŇĽĹÔ]/;

/** "στην Πατησίων 210", "οδός Ερμού 12": a street name in the genitive. */
export const EL_STREET_PATTERN = new RegExp(
  String.raw`(?<=(?<![\p{L}])(?:στην|στη|στον|στο|οδός|οδό|οδού|επί\s+της|επί\s+του|διεύθυνση:?|Διεύθυνση:?|Οδός|Οδό)[ \t]+)(?:\p{Lu}[\p{Ll}\p{M}]+[ \t]+)?\p{Lu}[\p{Ll}\p{M}]*(?:ων|ου|ούς|ης|ας|ώς)[ \t]+\d{1,4}[α-ωΑ-Ω]?(?![\p{L}\p{N}])`,
  "gu",
);

/** Hungarian: "9400 Sopron, Várkerület 41." — the postcode (group 1) and
 *  the street (group 2), whose number keeps its full stop. */
export const HU_TOWN_FIRST_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])((?!19|20)[1-9]\d{3})[ \t]+\p{Lu}[\p{Ll}]+(?:-\p{Lu}?[\p{Ll}]+)?,[ \t]+(` +
  // A street word, or the full stop Hungarian puts after the number.
  String.raw`(?:\p{Lu}[\p{L}\p{M}-]*[ \t]+){1,2}(?:utca|út|tér|körút|krt\.|u\.|köz|sor|sétány|rakpart|fasor|liget)[ \t]+\d{1,4}(?:\/[A-Za-z])?\.?` +
  String.raw`|(?:\p{Lu}[\p{L}\p{M}-]*[ \t]+){0,2}\p{Lu}[\p{L}\p{M}-]*[ \t]+\d{1,4}(?:\/[A-Za-z])?\.(?=[ \t,]|$)` +
  String.raw`)(?![\p{L}\p{N}])`,
  "gdu",
);

/**
 * A Spanish road by its road word, with or without a number: "Carretera a San
 * Lorenzo Malacota", "Camino de los Valles", "Cañada Real de Ronda a Mojón
 * Verde 240", "Carretera Kinchil-Umán". Only the words for a road outside a
 * city centre, which name somebody's house far more often than a sight:
 * "Calle Ocho" and "Paseo de la Castellana" stay with the numbered rule.
 * ES_ROAD_FAMOUS are the pilgrim's and the king's roads.
 */
const ES_ROAD_WORD = String.raw`\p{Lu}[\p{L}\p{M}'’.]*(?:-\p{Lu}[\p{L}\p{M}'’]*)*`;
export const ES_ROAD_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])(?:Carretera|Camino|Cañada|Privada|Circuito|Calzada|Camí)(?:[ \t]+(?:(?:a|al|de|del|la|las|los|el|d['’])[ \t]*){0,2}${ES_ROAD_WORD}){1,6}(?:,?[ \t]+\d{1,5}[A-Za-z]?(?![\p{L}\p{N}]))?`,
  "gu",
);
export const ES_ROAD_FAMOUS = /^Camino (?:de Santiago|Real|Francés|Primitivo|del Norte|Portugués|Inglés)$/;

/**
 * The same for Italian and French: a farmstead, a hamlet or a country road
 * by its own word, with or without a number: "Cascina Martinenghe 156/B",
 * "Località Torrio Casetta", "Frazione Pieve d'Agnano", "Strada Provinciale
 * del Bidente", "Route de Vignols 645bis", "Chemin des Écureuils", "Impasse
 * Bel-Air". "Route" and "Chemin" only with "de" after them, so "Route
 * Planning" is a heading. IT_FR_ROAD_FAMOUS are races, battles and books.
 */
const IT_FR_PARTICLE = String.raw`(?:di|del|della|dei|delle|degli|de|du|des|la|le|les|l['’]|d['’])`;
export const IT_FR_ROAD_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])(?:(?:Cascina|Contrada|Località|Frazione|Borgata|Podere|Masseria|Strada[ \t]+(?:Provinciale|Comunale|Vicinale|Statale)|Impasse|Lieu-dit|Lieudit|Hameau)(?:[ \t]+(?:${IT_FR_PARTICLE}[ \t]*){0,2}${ES_ROAD_WORD}){1,5}` +
  String.raw`|(?:Route|Chemin|Sentier)(?:[ \t]+(?:${IT_FR_PARTICLE}[ \t]*){1,2}${ES_ROAD_WORD})(?:[ \t]+(?:${IT_FR_PARTICLE}[ \t]*){0,2}${ES_ROAD_WORD}){0,3})` +
  String.raw`(?:,?[ \t]+\d{1,5}(?:\/[A-Za-z]|[A-Za-z]|bis|ter)?(?![\p{L}\p{N}]))?`,
  "gu",
);
export const IT_FR_ROAD_FAMOUS = /^(?:Route (?:du Rhum|des Grandes Alpes|du Vin|des Vins)|Chemin des Dames)$/;

/**
 * A German or Dutch street with its number and then its town, with no street
 * word in the name: "bei Breitenloo 41 in Mels", "auf der Rehhalden 1064 in
 * Ossingen", "in der Steyermühle 31, Königsmoos", "Ort: Am Zoo 9, Wilsum",
 * "op Verloren Hoek 15 in Bronckhorst". A word for "at" or "address" before
 * it and "in" or a comma and a town after it are what make the number a
 * house's. The first word may not be one that counts things ("im Jahr",
 * "bei Kapitel", "op pagina"), and a year is not a house number.
 */
const DE_NL_AT = String.raw`(?:bei|beim|am|im|zur|zum|vom|nach|(?:auf|in|an|aus|von)[ \t]+(?:der|dem|den)|op|aan|bij|naar|van|te|(?:aan|op|bij)[ \t]+de|(?:Adresse|Anschrift|Postanschrift|Wohnadresse|Wohnort|adres|Ort|Standort)(?:[ \t]+(?:ist|is|lautet|in))?[ \t]*[:\-–]?|Haus[ \t]+in|wohne[ \t]+in)`;
const DE_NL_NOT_A_STREET = String.raw`(?:Jahr|Jahre|Jahren|Kapitel|Seite|Seiten|Teil|Folge|Gleis|Halle|Raum|Zimmer|Saal|Etage|Stock|Stufe|Level|Runde|Woche|Wochen|Tag|Tage|Tagen|Minute|Minuten|Stunde|Stunden|Uhr|Gruppe|Klasse|Version|Nummer|Nr|Linie|Bus|Tram|Platz|Punkt|Schritt|Phase|Windows|Python|Hoofdstuk|Pagina|Jaar|Jaren|Kamer|Stap|Week|Weken|Dag|Dagen|Uur|Groep|Bladzijde|Lijn|Spoor|Hal|Zaal|Fase|Versie|Nummer|Top|Januar|Februar|März|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember|Januari|Februari|Maart|Augustus|Montag|Dienstag|Mittwoch|Donnerstag|Freitag|Samstag|Sonnabend|Sonntag|Maandag|Dinsdag|Woensdag|Donderdag|Vrijdag|Zaterdag|Zondag)(?![\p{L}])`;
const DE_NL_WORD = String.raw`\p{Lu}[\p{L}\p{M}'’.-]*`;
export const DE_NL_STREET_TOWN_PATTERN = new RegExp(
  String.raw`(?<=(?<![\p{L}])${DE_NL_AT}[ \t]+)(?!${DE_NL_NOT_A_STREET})${DE_NL_WORD}(?:[ \t]+(?:(?:du|de|la|van|der|den|von|vom)[ \t]+)?${DE_NL_WORD}){0,2},?[ \t]+(?!(?:19|20)\d\d(?!\d))\d{1,4}[a-zA-Z]?(?=[ \t]+in[ \t]+\p{Lu}|,[ \t]*\p{Lu}\p{Ll})`,
  "gu",
);

/**
 * A Portuguese street with "número" or "n.º" before its number: "Rua da
 * Igreja de Paranhos, n.º 938", "Calçada de Santana, número 51Z", "Trilho dos
 * conventos, nº 202", "Rua Rua de Alves Redol, Nº 374" (moreLanguages
 * practice half, 2026-11-02). The word for number is what the rule needs, so
 * the name between may be any words.
 */
export const PT_STREET_NUMERO_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])(?:Rua|Avenida|Av\.|Travessa|Calçada|Estrada|Azinhaga|Praceta|Largo|Alameda|Passeio|Trilho|Beco|Praça|Rotunda|Caminho|Quinta|Vereda|Ladeira)(?:[ \t]+[\p{L}][\p{L}\p{M}'’.-]*){1,8}?,?[ \t]+(?:[nN]\.?[ \t]*[º°]|número|Número)[ \t]*\d{1,5}[A-Za-z]?(?:\/\d{1,4})?(?![\p{L}\p{N}])`,
  "gu",
);
