/**
 * Which capitalised words are not somebody's name.
 *
 * Everything the name stage can decide without a model: the word lists, the
 * predicates built on them, the cheap scan that says whether asking a model
 * is worth the latency at all, and the cue-based fallback for when it is not
 * available. redactionNames does the asking.
 *
 * This is where the stage's precision actually lives. A missed name is a leak
 * and a wrong one is worse in a different way — "Monday", "Excel" or "Sorry"
 * replaced by a first name is the product rewriting a sentence the user wrote
 * — so each list below is an answer to a specific sentence that came out
 * wrong, and the comments say which.
 */

import { FAMOUS_PEOPLE } from "./redactionFamous.js";
import { TOWNS } from "./redactionTowns.js";
import { FAMOUS_ALIASES } from "./redactionFamousAliases.js";
import { FAMOUS_ALONE } from "./redactionFamousAlone.js";
import { GIVEN_NAMES } from "./redactionGivenNames.js";
import { SURNAMES, TYPED_LOWER } from "./redactionSurnames.js";
import { WORLD_GIVEN_NAMES } from "./redactionWorldGivenNames.js";
import { SCRIPT_GIVEN_NAMES } from "./redactionScriptGivenNames.js";
import { isSubstitutable, ZH_TITLE } from "./redactionMap.js";
import { isForeignCommonWords } from "./redactionNameWordsIntl.js";
import { moreCuedNames } from "./redactionNameCuesMore.js";

/**
 * Words that begin a sentence, or are simply capitalised in ordinary writing,
 * and would otherwise make the gate fire on almost every message. This list
 * exists to keep the model call rare, not to decide anything — a name that
 * slips through it is caught by the model, and a non-name that gets past it
 * costs one inference.
 */
/**
 * An acronym, not a person.
 *
 * Found in production, and it broke every technical conversation there is:
 * asked to explain HTTPS and then DNS, the map came back
 * {"Priya":"HTTPS","Nolan":"TLS","Marisol":"DNS"} — so the model was asked
 * about a woman called Priya, and answered that it had no idea who that was.
 * The stage is a 3B model shown a message and asked which words are people;
 * a short capitalised token it does not recognise looks exactly like a name
 * it does not recognise.
 *
 * The rule is shape, not vocabulary. Two to six characters, no lower-case
 * letters, and it is an acronym — SQL, GDPR, AWS, HTTP, TLS, CI, PDF — and a
 * list of every acronym anyone might type is a list that is wrong the week
 * after it is written. Digits are allowed because S3, EC2 and P95 are the
 * same kind of thing.
 *
 * What this costs: a person whose name is written in capitals is not
 * redacted. That is a real hole and a narrow one — nobody writes a colleague
 * as "MARTA" in a sentence — and it is the better side of the trade against
 * every acronym in the language being replaced by a first name.
 */
export function isAcronym(name: string): boolean {
  // Anything with a digit in it. No human name carries one, and it catches the
  // mixed-case technical tokens the all-caps rule cannot see: OAuth2, S3, EC2,
  // P95, SHA256.
  if (/\d/.test(name)) return true;
  return /^[A-Z][A-Z]{1,5}$/.test(name);
}

export const COMMON_CAPITALISED = new Set([
  "I", "I'm", "I've", "I'd", "I'll", "The", "A", "An", "This", "That", "These",
  "Those", "It", "Its", "My", "Your", "Our", "Their", "His", "Her", "We", "You",
  "They", "He", "She", "What", "When", "Where", "Why", "How", "Who", "Which",
  "Can", "Could", "Would", "Should", "Will", "Do", "Does", "Did", "Is", "Are",
  "Was", "Were", "Have", "Has", "Had", "If", "But", "And", "Or", "So", "Then",
  "Please", "Thanks", "Thank", "Hi", "Hello", "Hey", "Yes", "No", "Ok", "Okay",
  "Write", "Make", "Give", "Show", "Tell", "Help", "Explain", "Let", "Here",
  "There", "Now", "Today", "Tomorrow", "Yesterday", "Monday", "Tuesday",
  "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "January",
  "February", "March", "April", "May", "June", "July", "August", "September",
  "October", "November", "December", "AI", "US", "UK", "EU", "TV", "PDF", "API",
  // The days and months as people write them in a hurry: "Dentist Tue 3pm",
  // "Soccer Wed and Fri", "Due Sept 3". A model asked for names handed "Tue"
  // back and it went out as "Anika", so the appointment had no day. None of
  // these is a first name on its own; "May" and "June" are above already.
  // Not "Mar", which is a Spanish first name — "Mar 3" is still a date,
  // through isDateWords.
  "Mon", "Tue", "Tues", "Wed", "Weds", "Thu", "Thur", "Thurs", "Fri", "Sat",
  "Sun", "Jan", "Feb", "Apr", "Jun", "Jul", "Aug", "Sep", "Sept",
  "Oct", "Nov", "Dec",
  // Imperatives, mostly. A message very often opens with one — "Pay it into
  // GB82…", "Draft a note to…" — and a small model asked for names will hand
  // one back as a name. That happened in production: "Pay" came back and was
  // replaced with "Colette", so the first word of the user's own sentence was
  // rewritten into a stranger.
  "Pay", "Send", "Book", "Call", "Draft", "Check", "Find", "Order", "Print",
  "Save", "Open", "Close", "Read", "Play", "Buy", "Sell", "Move", "Turn",
  "Set", "Add", "Put", "Get", "Take", "Keep", "Try", "Use", "Run", "Fix",
  "Plan", "Review", "Summarise", "Summarize", "Translate", "Compare", "List",
  "Create", "Design", "Build", "Remind", "Schedule", "Email", "Text",
  "Message", "Note", "Draw", "Edit", "Copy", "Paste", "Cancel", "Confirm",
  "Explain", "Describe", "Suggest", "Recommend", "Rewrite", "Reply", "Forward",
  // Spanish, for the same two reasons: the words a sentence or a letter opens
  // with, and the forms of address that are not anybody in particular
  // ("Estimado Cliente", "Estimados Señores"). Nothing here is also somebody's
  // name: not the months and days, which Spanish does not capitalise anyway
  // and which include Julio, Abril and Domingo; not "Luz", "Paz", "Rosa" or
  // "Mar"; and not the short words that are names elsewhere — Ella, Una, Su,
  // Tu, Con, Esa, Hay, Ayer.
  "El", "La", "Los", "Las", "Un", "Este", "Esta", "Esto", "Ese", "Eso",
  "Estos", "Estas", "Mi", "Mis", "Sus", "Nuestro", "Nuestra", "Yo", "Usted",
  "Ustedes", "Nosotros", "Ellos", "Qué", "Cómo", "Cuándo", "Dónde", "Quién",
  "Cuál", "Por", "Para", "Sin", "Si", "Sí", "Pero", "También", "Hola",
  "Gracias", "Aquí", "Hoy", "Mañana", "Estimado", "Estimada", "Estimados",
  "Estimadas", "Querido", "Querida", "Atentamente", "Saludos", "Cordialmente",
  "Señor", "Señora", "Señores", "Señorita", "Cliente", "Clientes", "Equipo",
  "Todos", "Factura", "Pedido", "Cuenta", "Adjunto", "Adjunta", "Favor",
  // Learned from the name stage's false alarms on the practice rows
  // (bench/.learned-name-words.md, 2026-10-06): each taken as a person three
  // times or more and never a word of any of 22,444 labelled names.
  "Aliens", "Medical", "Condition", "Application", "Inheritance", "Delegate", "Affairs", "Whether",
  // And from namesMultilingual's English practice rows (2026-10-22), checked
  // against 30,248 labelled names: none is a word of one. Not "Mom", which is.
  "Questions", "Exploration", "Exciting", "Enjoyable", "Verify", "Mister", "Mstr",
  // A contract's defined terms, capitalised throughout it: "The Parties agree
  // that this Agreement…". Checked against 64,326 labelled names (2026-10-24):
  // none is a word of one.
  "Parties", "Party", "Agreement", "Contract", "Provider", "Client", "Customer", "Supplier", "Licensor",
  "Licensee", "Lessor", "Lessee", "Purchaser", "Contractor", "Consultant", "Services", "Schedule", "Annex",
  "Appendix", "Exhibit", "Recitals", "Clause", "Territory",
]);

/**
 * Everyday words that make a phrase, not a person.
 *
 * Reported from testing: "hot dog" came back from the name stage and was
 * replaced with a stranger's name, so the user's own sentence stopped making
 * sense. The single-word list above cannot catch it — the model returns the
 * pair, and the pair is what gets substituted.
 *
 * Pairs and longer only. A single common noun is very often a surname —
 * Baker, Cook, Rose, Hunter, Green — and blocking those would send real
 * names to the provider, which is the expensive direction to be wrong in.
 * Two everyday words in a row is not somebody's name in practice.
 */
const EVERYDAY_WORDS = new Set([
  // The adjectives that sit in front of one.
  "hot", "cold", "warm", "iced", "fresh", "fried", "grilled", "baked",
  "roast", "roasted", "boiled", "raw", "sweet", "sour", "salty", "spicy",
  "big", "small", "large", "little", "old", "new", "good", "bad", "best",
  "red", "blue", "green", "black", "white", "brown", "yellow", "orange",
  "purple", "pink", "grey", "gray", "golden", "silver",
  // Food, which is where this went wrong.
  "dog", "dogs", "hotdog", "hotdogs", "burger", "burgers", "cheeseburger",
  "pizza", "pasta", "noodle", "noodles", "rice", "bread", "toast", "sandwich",
  "sandwiches", "wrap", "roll", "rolls", "bun", "buns", "chip", "chips",
  "fries", "salad", "soup", "stew", "curry", "steak", "chicken", "beef",
  "pork", "bacon", "ham", "fish", "egg", "eggs", "cheese", "butter", "milk",
  "cream", "sugar", "salt", "pepper", "sauce", "gravy", "cake", "cakes",
  "pie", "pies", "cookie", "cookies", "biscuit", "biscuits", "donut",
  "doughnut", "pancake", "pancakes", "waffle", "waffles", "muffin", "bagel",
  "croissant", "chocolate", "candy", "sweets", "ice", "coffee", "tea",
  "juice", "water", "beer", "wine", "soda", "apple", "apples", "banana",
  "orange", "lemon", "lime", "grape", "grapes", "berry", "berries",
  "strawberry", "potato", "potatoes", "tomato", "tomatoes", "onion",
  "carrot", "corn", "bean", "beans", "pea", "peas", "mushroom", "meal",
  "meals", "dish", "recipe", "snack", "breakfast", "lunch", "dinner",
  "supper", "dessert", "drink", "drinks",
  // Ordinary objects and animals that pair up the same way.
  "cat", "cats", "bird", "birds", "horse", "car", "cars", "bus", "train",
  "plane", "bike", "boat", "house", "room", "door", "window", "table",
  "chair", "desk", "bed", "box", "bag", "cup", "plate", "bowl", "phone",
  "laptop", "computer", "screen", "book", "books", "paper", "pen", "pencil",
  "shop", "store", "stand", "truck", "spot", "day", "days", "night", "week",
  "month", "year", "time", "thing", "things", "stuff", "list", "idea",
  "ideas", "plan", "plans", "note", "notes",
]);

/** Two or more everyday words in a row — see EVERYDAY_WORDS. */
export function isEverydayPhrase(name: string): boolean {
  const words = name.split(/[\s-]+/).filter(Boolean);
  if (words.length < 2) return false;
  return words.every((w) => EVERYDAY_WORDS.has(w.toLowerCase().replace(/[^a-z]/g, "")));
}

/**
 * Ordinary lowercase words the name model has returned as people.
 *
 * Seen live on 2026-09-15: a conversation that had said "a cat wearing a tiny
 * wizard hat" came back with "hat" as a name, and "hat" was swapped for
 * "Petrov" in every turn after. The single-word rule elsewhere stays loose on
 * purpose — Baker, Rose and Hunter are surnames — but those are capitalised.
 * A name typed in lowercase ("tell sarah I'm late") still counts; a common
 * word typed in lowercase, exactly as it would be in any sentence, does not.
 *
 * ── Nothing here may be a given name ──
 *
 * This list is the one place in the file that makes redaction do *less*, so
 * the cost of a wrong entry is the only kind of mistake that matters here:
 * a real name reaching a provider. The first draft carried bill, hope, joy,
 * love, angel, star, sky, river, forest, summer, autumn, winter and spring —
 * every one of them somebody's first name, and "tell hope i'll be late" would
 * have sent hope through in the clear.
 *
 * They are gone, and the rule they broke is the test for anything added
 * later: if it is plausible as the name of a person, it does not belong here,
 * however common the ordinary word is. The failure the other way — the model
 * wrongly calls "bill" a person and the bill gets a stand-in — is a strange
 * sentence in one reply. This one is the thing the product exists to stop.
 */
const COMMON_LOWERCASE = new Set([
  ...EVERYDAY_WORDS,
  "hat", "hats", "cap", "coat", "shirt", "dress", "shoe", "shoes", "boot", "boots", "sock", "socks",
  "scarf", "glove", "gloves", "jacket", "tie", "belt", "ring", "watch", "glasses", "bag", "wallet",
  "man", "woman", "boy", "girl", "baby", "kid", "kids", "friend", "friends", "mum", "mom", "dad",
  "brother", "sister", "wife", "husband", "boss", "doctor", "teacher", "neighbour", "neighbor",
  "wizard", "king", "queen", "prince", "princess", "knight", "dragon", "robot", "ghost",
  "tree", "trees", "flower", "flowers", "sun", "moon", "stars", "sea", "ocean",
  "lake", "mountain", "hill", "beach", "park", "garden", "city", "town",
  "street", "road", "school", "work", "office", "home", "church", "hospital", "bank", "hotel",
  "money", "price", "tax", "job", "team", "game", "music", "song", "movie", "film",
  "photo", "picture", "image", "drawing", "painting", "poster", "logo", "card", "gift", "party",
  "birthday", "wedding", "holiday", "trip", "fall",
  // Taken as names on namesMultilingual's English practice rows (2026-10-22).
  "questions", "enjoyable", "verify",
  "morning", "evening", "weekend", "today", "tomorrow", "yesterday",
  "luck", "help", "question", "answer", "problem", "email", "message", "letter", "report",
  "dog", "puppy", "kitten", "rabbit", "mouse", "fox", "wolf", "bear", "lion", "tiger", "cow",
  "pig", "sheep", "duck", "chicken", "owl", "snake", "frog", "monkey", "elephant", "whale",
]);

/**
 * The species half of an organism written with its genus initial: "E. coli",
 * "S. aureus", "H. pylori", "C. difficile". A lower-case word that only ever
 * follows a capital and a full stop is a bacterium, and a record that names
 * one is about the infection. Seen in a French blood culture (2026-10-08):
 * "Hémocultures positives à E. coli" sent "coli" as a person.
 */
export function isSpeciesName(name: string, text: string): boolean {
  if (!/^\p{Ll}[\p{Ll}-]{2,}$/u.test(name)) return false;
  // A name's particle after an initial: "J. van Dijk", "M. von Trapp". Of
  // 78,173 labelled names, the only one this rule touched (2026-10-08).
  if (/^(?:van|von|der|den|del|della|dos|das|ten|ter|zum|zur)$/.test(name)) return false;
  let seen = 0;
  for (let i = text.indexOf(name); i !== -1; i = text.indexOf(name, i + 1)) {
    if (/\p{L}/u.test(text[i + name.length] ?? "")) continue;
    if (!/(?:^|[^\p{L}])\p{Lu}\.[ \t]?$/u.test(text.slice(Math.max(0, i - 4), i))) return false;
    seen++;
  }
  return seen > 0;
}

/**
 * A name the sentence gives to an animal: "my dog is called Biscuit", "our
 * cat Mochi". The model is told pets are not people and shown an example;
 * this is the check that does not depend on it remembering.
 */
export function isPetName(name: string, text: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const animals = "dog|cat|puppy|kitten|pet|horse|pony|hamster|rabbit|bunny|parrot|bird|fish|goldfish|turtle|tortoise|snake|lizard|guinea pig|ferret";
  return new RegExp(`\\b(?:${animals})(?:'s name)?\\s+(?:is\\s+|was\\s+)?(?:called|named|is)?\\s*${escaped}\\b`, "i").test(text);
}

/**
 * A very famous person, asked about: "How many Grand Slam titles has Steffi
 * Graf won?", "周杰伦和林俊杰谁的演唱会门票更难抢？". The question is about
 * them, and a stand-in makes it one nobody can answer. The list is in
 * redactionFamous.ts: whole names only, never one word.
 *
 * Somebody private can share a famous name, so the name stays hidden wherever
 * the text treats its bearer as somebody the writer knows: a possessive, a
 * relation, a role or a title before it ("my client Michael Jordan", "Herr
 * Becker", "mi vecino"), or an honorific after it (さん, 様, 先生, 씨, 님, 老师).
 * One such mention anywhere keeps every mention hidden.
 *
 * The model's form is read as well as the list's: a Korean particle on the
 * end (손흥민이) and a French elision in front (d'Édith Piaf).
 *
 * One word is enough where it means one person: "Толстой или Достоевский",
 * "Einstein oder Poincaré", "李白和杜甫" (redactionFamousAlone.ts, measured
 * on Wikidata), and its case forms ("styl Dvořáka", "w stylu Mickiewicza").
 */
export function isFamousPersonHere(name: string, text: string): boolean {
  const bare = name.normalize("NFC")
    .replace(/^[dDlL]['’]/, "")
    .replace(/(?<=\p{Script=Hangul})(?:이|가|은|는|을|를|의|에게|한테|도|와|과|랑|이랑)$/u, "");
  const oneWord = !/\s/.test(bare);
  const listed = (form: string) => FAMOUS_PEOPLE.has(form) || FAMOUS_ALIASES.has(form) || (oneWord ? isFamousAlone(form) : isFamousInflected(form));
  const forms = [bare, ...withoutAffixes(bare)];
  if (!forms.some(listed)) {
    // One word of a famous name, where the whole of it is in the text and
    // famous there: the tagger returned "Steffi" out of "Steffi Graf".
    return oneWord && forms.some((form) => (famousByWord().get(form) ?? []).some((full) => text.includes(full) && isFamousPersonHere(full, text)));
  }
  const escaped = bare.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const m of text.matchAll(new RegExp(escaped, "g"))) {
    const start = m.index ?? 0;
    const before = text.slice(Math.max(0, start - 30), start);
    const after = text.slice(start + bare.length, start + bare.length + 8);
    if (KNOWN_PERSON_BEFORE.test(before) || KNOWN_PERSON_AFTER.test(after) || FORM_FIELD_BEFORE.test(before)) return false;
    // A correspondent, not a topic: "skrev Henrik Dalsgaard <henrik@…>". And
    // a street named after somebody is an address: "Av. Afonso Pena, 1500".
    if (/^\s*[<(\[]?[\w.+-]+@/.test(text.slice(start + bare.length, start + bare.length + 40))) return false;
    if (FAMOUS_STREET_BEFORE.test(before)) return false;
  }
  return true;
}

/** The word for a street just before a famous name: the name is the street's. */
const FAMOUS_STREET_BEFORE = /(?<![\p{L}])(?:av(?=\.)|avda|avenida|avenue|rua|calle|carrer|street|road|via|viale|piazza|corso|rue|bd|boulevard|blvd|praça|pça|travessa|alameda|largo|ulica|ul|ulitsa|ул|улица|просп|проспект|str|straße|strasse|plaza|plac|aleja|trg|bulevar|bulevardul|strada|calea|utca|út|tér|katu|gatan|vej|gade|laan|weg|plein|jalan|jl|đường|phố)\.?\s+$/iu;

/**
 * A name that is only ever half of a reported case: "Miranda v. Arizona",
 * "Street v Mountford". The case is public, cited by its parties' names, and
 * the question is about the ruling. Every mention must be in a citation; one
 * anywhere else ("Miranda called me") keeps it a person.
 */
export function isCaseName(name: string, text: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const mentions = [...text.matchAll(new RegExp(`(?<![\\p{L}])${escaped}(?![\\p{L}])`, "gu"))];
  if (!mentions.length) return false;
  return mentions.every((m) => {
    const start = m.index ?? 0;
    const before = text.slice(Math.max(0, start - 40), start);
    const after = text.slice(start + name.length, start + name.length + 40);
    return /^\s+v\.?\s+\p{Lu}/u.test(after) || /\p{Lu}[\p{L}'’.-]*\s+v\.?\s+$/u.test(before);
  });
}

/**
 * A famous name in a case form, as the languages with cases write it:
 * "citát od Václava Havla", "esej o Marku Maruliću", "fogalmazást ír Petőfi
 * Sándorról", "poleciła mi Olgę Tokarczuk", "rád mal Petra Sagana"
 * (realistic5, 2026-10-24). Each word is the list's word, or its stem (less a
 * final vowel, or the e that drops out: Havel, Havla) with a case ending
 * after it; either order, for Hungarian's. Only an ending, so a private "Jan
 * Husák" is not Jan Hus.
 *
 * Finnish puts an i between a name that ends in a consonant and its ending
 * (Tove Janssonista, Alexander Stubbia), turns a final s into kse (Jean
 * Sibeliuksesta) and softens the consonants before the ending (Alvar
 * Aallosta, from Aalto) (realistic5, 2026-11-02).
 */
const CASE_ENDINGS = new Set(`
a e i o u y á é í ó ú ý ą ę ie iu ovi owi ou em om ém ým ym ého ému ego emu iem iej iego ów ach ami ov ova ovej ej
t ot et öt at nak nek ra re ról ről val vel ban ben ból ből hoz hez höz tól től ért nál nél
n ä ta tä sta stä ssa ssä lla llä lta ltä lle ksi na nä in iin s ului ei ii lui
ia ista issa illa ilta ille iksi ina ihin
а я у ю ом ем ым им е ой ей ого его ому ему ую ою ы и
`.split(/\s+/).filter(Boolean));

/** Finnish consonant gradation before an ending: Aalto, Aallo-; Lindholm
 *  keeps its own. */
const softened = (f: string) => f.replace(/(?:lt|nt|rt|mp|nk|tt|kk|pp)(?=[aeiouyäö]$)/u, (c) => ({ lt: "ll", nt: "nn", rt: "rr", mp: "mm", nk: "ng", tt: "t", kk: "k", pp: "p" })[c] ?? c);

function isCaseFormOf(word: string, famous: string): boolean {
  const w = word.toLowerCase().replace(/['’]\p{L}+$/u, "");
  const f = famous.toLowerCase();
  if (w === f) return true;
  // Russian and Polish adjectival names lose two letters: Толстой, Толстого;
  // Достоевский, Достоевского.
  for (const stem of new Set([f, f.replace(/[aeiouyаяеоыию]$/u, ""), f.replace(/e(\p{L})$/u, "$1"), f.replace(/(?:ий|ый|ой)$/u, ""), softened(f), f.replace(/s$/, "kse")])) {
    if (stem.length >= 3 && w.length > stem.length && w.startsWith(stem) && CASE_ENDINGS.has(w.slice(stem.length))) return true;
  }
  return false;
}

let byStems: Map<string, string[]> | null = null;
const stemsKey = (words: string[]) => words.map((w) => w.slice(0, 3).toLowerCase()).sort().join(" ");

function isFamousInflected(name: string): boolean {
  const words = name.split(/\s+/);
  if (words.length < 2 || words.length > 3) return false;
  if (!byStems) {
    byStems = new Map();
    for (const full of FAMOUS_PEOPLE) {
      const parts = full.split(/\s+/);
      if (parts.length < 2 || parts.length > 3 || !/^[\p{Script=Latin}\p{Script=Cyrillic}\s.'’-]+$/u.test(full)) continue;
      const key = stemsKey(parts);
      const names = byStems.get(key);
      if (names) names.push(full);
      else byStems.set(key, [full]);
    }
  }
  const same = (a: string[], b: string[]) => a.every((w, i) => isCaseFormOf(w, b[i]));
  return (byStems.get(stemsKey(words)) ?? []).some((full) => {
    const parts = full.split(/\s+/);
    return parts.length === words.length && (same(words, parts) || same(words, [...parts].reverse()));
  });
}

/**
 * The name without what the grammar joined to it, for the scripts that join
 * it: Arabic's and, to, with (وأنور السادات, لجمال عبد الناصر), Hebrew's
 * and, to, the, from, that (ליצחק רבין), and Bengali's of (সত্যজিৎ রায়ের)
 * (realistic5, 2026-10-27). Only ever looked up in the famous lists, so a
 * wrong cut finds nothing.
 */
function withoutAffixes(name: string): string[] {
  const out: string[] = [];
  if (/^[وفبلك]\p{Script=Arabic}{2}/u.test(name)) out.push(name.slice(1));
  if (/^[ובלמשהכ]\p{Script=Hebrew}{2}/u.test(name)) {
    out.push(name.slice(1));
    if (/^[ובלמשהכ]{2}\p{Script=Hebrew}{2}/u.test(name)) out.push(name.slice(2));
  }
  if (/\p{Script=Bengali}(?:এর|ের|র)$/u.test(name)) out.push(name.replace(/(?:এর|ের|র)$/u, ""));
  return out;
}

/** FAMOUS_ALONE less given names ("Madonna", "Kristina"), which thousands
 *  of people have, by their first three letters for the case forms. Built
 *  once, on first use. */
let alone: { exact: Set<string>; byStart: Map<string, string[]> } | null = null;
function isFamousAlone(word: string): boolean {
  if (!alone) {
    alone = { exact: new Set(), byStart: new Map() };
    // And a word that starts more famous names than it ends, two at least: a
    // given name the lists do not hold. Hafiz (Hafez, the poet; Hafiz Saeed;
    // Hafiz al-Assad), not Толстой, which ends "Лев Толстой" more often than
    // it starts "Толстой Лев".
    const first = new Map<string, number>();
    for (const full of FAMOUS_PEOPLE) {
      const words = full.split(/\s+/);
      if (words.length < 2) continue;
      first.set(words[0], (first.get(words[0]) ?? 0) + 1);
      first.set(words.at(-1)!, (first.get(words.at(-1)!) ?? 0) - 1);
    }
    for (const w of FAMOUS_ALONE) {
      const lower = w.toLowerCase();
      if (GIVEN_NAMES.has(lower) || WORLD_GIVEN_NAMES.has(lower) || (first.get(w) ?? 0) >= 2) continue;
      alone.exact.add(w);
      if (!/^\p{Lu}/u.test(w)) continue;
      const key = lower.slice(0, 3);
      const words = alone.byStart.get(key);
      if (words) words.push(w);
      else alone.byStart.set(key, [w]);
    }
  }
  if (alone.exact.has(word)) return true;
  // A case form that is itself a name of its own ("Novaka", "Bacha") is that
  // name, not the famous one.
  const lower = word.toLowerCase();
  if (!/^\p{Lu}/u.test(word) || SURNAMES.has(lower) || GIVEN_NAMES.has(lower) || WORLD_GIVEN_NAMES.has(lower)) return false;
  return (alone.byStart.get(word.toLowerCase().slice(0, 3)) ?? []).some((famous) => isCaseFormOf(word, famous));
}

/** Each word of a famous name, to the names it is part of. Built once, on
 *  first use. The other names too: the model returned "وأنور" out of "وأنور
 *  السادات", which is an alias, not the label (realistic5, 2026-11-08). */
let byWord: Map<string, string[]> | null = null;
function famousByWord(): Map<string, string[]> {
  if (byWord) return byWord;
  byWord = new Map();
  for (const full of [...FAMOUS_PEOPLE, ...FAMOUS_ALIASES]) {
    if (!/\s/.test(full)) continue;
    for (const word of full.split(/\s+/)) {
      // Capitalised, or in a script without capitals: "خلدون" out of "ابن
      // خلدون", "जवाहरलाल" out of "जवाहरलाल नेहरू".
      if (word.length < 3 || !/^(?:\p{Lu}|[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Thai}])/u.test(word)) continue;
      const names = byWord.get(word);
      if (names) names.push(full);
      else byWord.set(word, [full]);
    }
  }
  return byWord;
}

/** What the writer puts before somebody they know, in each language read. */
const KNOWN_PERSON_BEFORE = new RegExp(String.raw`(?:^|[^\p{L}])(?:` + [
  // English. A verb of getting in touch too: "Email Ana de Armas and …" is
  // somebody the writer can reach.
  "my|our|his|her|their|your|client|customer|patient|colleague|co-?worker|friend|neighbou?r|boss|manager|son|daughter|wife|husband|partner|tenant|landlord|employee|candidate|applicant|student|pupil|cousin|uncle|aunt|brother|sister|mother|father|mum|mom|dad|grand(?:ma|pa|mother|father)|named|called|dear|hi|hello|mr|mrs|ms|miss|dr|prof",
  "e-?mail|mail|call|ring|text|message|phone|invite|meet|tell|ask|remind|thank|cc|bcc|contact|reply to|write to|send it to|regards",
  "[ée]cri(?:s|vez) [àa]|appelle[rz]?|envoie [àa]|invite[rz]?|anrufen|ruf|schreib(?:e|en)?|lade|llam[ae] a|escrib[ea] a|invita|chiama|scrivi a|ligue para|escreva para|bel|mail",
  // French
  "mon|ma|mes|notre|nos|cliente?|patiente?|coll[eè]gue|amie?|voisine?|fils|fille|appel[ée]e?|nomm[ée]e?|cher|ch[eè]re|bonjour|monsieur|madame|mme|mlle|m",
  // German
  "mein(?:e[mnrs]?)?|unser(?:e[mnrs]?)?|kund(?:e|in)|patientin|kolleg(?:e|in)|freund(?:in)?|nachbar(?:in)?|sohn|tochter|namens|liebe[rs]?|hallo|herrn?|frau",
  // Spanish
  "mis?|nuestr[oa]s?|compa[ñn]er[oa]|amig[oa]|vecin[oa]|hij[oa]|llamad[oa]|querid[oa]|hola|se[ñn]or(?:a|ita)?|sra?|srta|don|do[ñn]a",
  // Italian, Portuguese, Dutch
  "mio|mia|miei|nostr[oaei]|collega|amic[oa]|vicin[oa]|figli[oa]|signor[ae]?|sig(?:ra)?|caro|cara|ciao",
  "meu|minha|nosso|nossa|colega|vizinh[oa]|filh[oa]|senhora?|ol[aá]",
  "mijn|onze|klant|buurman|buurvrouw|zoon|dochter|meneer|mevrouw|beste",
  // Russian, Ukrainian, Polish, Turkish and Vietnamese, for the names the list
  // holds in those languages (2026-10-24).
  "мо[йяеи]|наш[аеи]?|клиент(?:ка)?|коллег[аи]|друг|подруг[аи]|сосед(?:ка)?|сын|дочь|муж|жена|пациент(?:ка)?|господин|госпожа|г-н|г-жа|уважаем(?:ый|ая)|дорог(?:ой|ая)|здравствуйте|привет",
  "мій|моя|моє|наш|колег[аи]|друже?|сусід(?:ка)?|син|донька|чоловік|дружина|пан|пані|шановн(?:ий|а)|вітаю",
  "mój|moja|moje|nasz[ae]?|klient(?:ka)?|kolega|koleżanka|przyjaciel(?:ka)?|sąsiad(?:ka)?|córka|mąż|żona|pan|pani|szanown[ya]|drog[ia]",
  "benim|müşterim|meslektaşım|arkadaşım|komşum|oğlum|kızım|eşim|sayın|bay|bayan|sevgili",
  // Malay and Indonesian put "my" after the noun: "kawan saya Hafiz"
  // (realistic5, 2026-10-27).
  "saya|aku|gw|kami|kita|encik|cik|puan|tuan|pak|bu|ibu|bapak|mas|mbak|kak|abang|adik",
  "ông|bà|anh|chị|em|bạn|khách hàng|đồng nghiệp|vợ|chồng|kính gửi",
  // Hindi, Bengali and Urdu, after the scripts' own words below: a doctor
  // and "my". "डॉ. विनोद खन्ना की ओर से" is the writer's doctor, not the
  // actor (realistic5, 2026-11-08).
].join("|") + String.raw`)\.?\s+$|(?:私の|うちの|弊社の|我的|我们的|我們的|我家|우리|제|저희|عزيزي|عزيزتي|السيد|السيدة|الأستاذ|الأستاذة|الدكتور|صديقي|زميلي|عميلي|موكلي|מר|גב['׳]|גברת|ד["״]ר|הלקוח|הלקוחה|השכן|השכנה|אשתי|בעלי|החבר שלי|החברה שלי|שלום|डॉ\.?|डॉक्टर|मेरे|मेरी|मेरा|ডাঃ|ডা\.|ডাক্তার|আমার|ڈاکٹر|میرے|میری|میرا)\s*$`, "iu");
/** A form's name field, in any of the forty languages: whoever is written
 *  into it is the form's person, not somebody asked about ("والد کا نام:
 *  محمد یونس", the father's name, realistic5). */
const FORM_FIELD_BEFORE = new RegExp(String.raw`(?:name|full name|nombre|apellidos?|nom|pr[ée]nom|nome|cognome|naam|vorname|nachname|navn|namn|nimi|n[ée]v|imi[ęe]|nazwisko|jm[ée]no|p[řr][íi]jmen[íi]|meno|ime|prezime|nume|prenume|όνομα|επώνυμο|имя|фамилия|фио|ім['’]я|прізвище|ad(?:ı)?\s*soyad(?:ı)?|isim|pangalan|nama|t[êe]n|h[ọo]\s*t[êe]n|नाम|নাম|نام|الاسم|اسم|שם(?:\s+(?:מלא|פרטי|משפחה))?|பெயர்|పేరు|ชื่อ|이름|성명|氏名|姓名|名前)\s*[:：]\s*$`, "iu");
/** The honorifics that follow somebody the writer knows: Japanese, Chinese, Korean, and Turkish Bey and Hanım. */
const KNOWN_PERSON_AFTER = /^\s?(?:さん|様|さま|君|くん|ちゃん|先生|氏|殿|女士|小姐|老师|老師|同学|同學|씨|님|군|양|선생)|^\s(?:Bey|Hanım|bey|hanım)(?![\p{L}])/u;

/**
 * A fragment of a sentence, not a name.
 *
 * Seen live on 2026-09-20: a message reading "No an aws Secure Enclave" came
 * back with "an aws" as a person, and every turn afterwards talked about
 * someone called Tessa Amberly. The acronym rule could not see it — it is
 * shape-based on capitals, and the user had typed "aws" in lower case — and
 * the everyday-phrase rule could not either, because neither "an" nor "aws"
 * is a food.
 *
 * The rule is grammar, not vocabulary: a candidate of two or more words that
 * carries an article, a conjunction, a pronoun or an auxiliary verb is a piece
 * of the sentence the model sliced badly, not somebody's name. When a small
 * model is unsure where a name ends it takes the neighbouring words with it,
 * and those neighbours are overwhelmingly these.
 *
 * Name particles are deliberately absent — van, de, von, da, di, del, bin,
 * ibn, al, la, le, mac. "Ludwig van Beethoven" and "Ana de Armas" are names
 * with a lower-case word in the middle, and this must not reject them.
 */
const SENTENCE_WORDS = new Set([
  "a", "an", "the", "and", "or", "but", "if", "so", "than", "then", "because",
  "is", "are", "was", "were", "be", "been", "am", "do", "does", "did",
  "have", "has", "had", "can", "could", "will", "would", "shall", "should",
  "may", "might", "must",
  "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us", "them",
  "my", "your", "his", "its", "our", "their", "this", "that", "these", "those",
  "to", "for", "with", "from", "on", "at", "by", "as", "in", "into", "about",
  "not", "no", "yes", "use", "uses", "using", "used", "say", "says", "said",
  "what", "when", "where", "why", "how", "who", "which",
]);

export function isSentenceFragment(name: string): boolean {
  const words = name.split(/[\s-]+/).filter(Boolean);
  if (words.length < 2) return false;
  // An initial is not the article or the pronoun: "A. Bradley" and "I. Foighel"
  // are judges of the European Court, and were thrown away as "a" and "i".
  return words.some((w) => !/^\p{Lu}\.$/u.test(w) && SENTENCE_WORDS.has(w.toLowerCase().replace(/[^a-z']/g, "")));
}

/*
 * The words of a judgment, a statute or a ministry's letter, alone. The name
 * models read a capitalised "Article", "Court" or "Registrar" as a person
 * often enough that, on the Text Anonymization Benchmark (2026-10-05), more
 * than half of everything the name stage took in 127 judgments was one of
 * these. As a whole candidate only: "Steve Case" and "Margaret Court" are
 * two words and are not touched.
 */
const DOCUMENT_WORDS = new Set([
  "article", "articles", "art", "rule", "rules", "section", "sections", "paragraph", "para", "paras",
  "chapter", "clause", "schedule", "annex", "appendix", "protocol", "convention", "treaty", "code",
  "act", "law", "regulation", "directive", "decree", "order", "case", "cases", "judgment", "decision",
  "procedure", "proceedings", "court", "courts", "chamber", "tribunal", "commission", "committee",
  "council", "assembly", "parliament", "senate", "government", "ministry", "minister", "state",
  "states", "republic", "kingdom", "crown", "registrar", "registry", "president", "vice-president",
  "secretary", "deputy", "judge", "judges", "justice", "prosecutor", "agent", "applicant", "applicants",
  "respondent", "defendant", "plaintiff", "claimant", "appellant", "counsel", "rights", "human",
  "fundamental", "freedoms", "majesty", "grand", "plenary", "facts", "circumstances", "relevant",
  "law", "admissibility", "merits", "conclusion", "dissenting", "concurring", "opinion",
]);

/**
 * A word the model read as a name and nobody would: one lower-case word that
 * is no given name, in a message that writes its names with capitals ("Write
 * a sympathy card for Mrs. Abernathy" gave "sympathy"); a clinic or a
 * hospital department in Korean, which reads like a name to the taggers
 * (소아과, 내과); and the short Hebrew words that are pronouns and
 * prepositions (לי, "me"). From the hold-outs' false alarms, 2026-10-24.
 */
export function isPlainlyNotAName(name: string, text: string): boolean {
  if (/^[a-z]{3,}$/.test(name) && !isGivenNameAnywhere(name) && (text.match(/(?<![\p{L}])\p{Lu}\p{Ll}+/gu) ?? []).length >= 2) return true;
  // A pronoun elided onto a verb in Catalan, French and Italian: "M'HAN
  // CLONAT LA TARGETA" (they have cloned my card), "t'ha", "s'est"
  // (realistic5, 2026-11-08). Nobody's name starts m', t' or s'.
  if (/^[MmTtSs]['’]\p{L}+$/u.test(name)) return true;
  return isWordOfAnUncasedScript(name, text);
}

/** The half of that a cue is held to: a lower-case word stays hidden there,
 *  since "ucup:" heading a chat line is somebody. */
export function isWordOfAnUncasedScript(name: string, text: string): boolean {
  if (KO_PLACES.has(name)) return true;
  return HE_NOT_A_NAME.has(name) || HE_FUNCTION_WORDS.has(name) || isHebrewWordPiece(name, text);
}

/**
 * The tail of a longer Hebrew word: "ום" out of היום, "ברידית" out of
 * היברידית (realistic5, 2026-11-07). Hebrew writes its prepositions onto the
 * word, so the letters in front may be those ("לדנה", "ולדנה") and a name is
 * still whole. So is one typed straight after a word ("שמידנה"): only one or
 * two letters that are no word, every time it appears, make it a piece.
 */
const HE_SHORT_WORDS = new Set(["עם", "את", "אל", "על", "מי", "זה", "כן", "לא"]);
const HE_LETTERS = /^[א-ת\s]+$/;
function isHebrewWordPiece(name: string, text: string): boolean {
  if (!HE_LETTERS.test(name)) return false;
  let at = text.indexOf(name), seen = 0;
  while (at !== -1) {
    seen++;
    const before = /[א-ת]*$/.exec(text.slice(Math.max(0, at - 8), at))?.[0] ?? "";
    if (!before || before.length > 2 || /^[משהוכלב]{1,3}$/.test(before) || HE_SHORT_WORDS.has(before)) return false;
    at = text.indexOf(name, at + 1);
  }
  return seen > 0;
}
const KO_PLACES = new Set([
  "소아과", "내과", "외과", "치과", "안과", "피부과", "이비인후과", "정형외과", "산부인과", "신경과", "정신과", "비뇨기과",
  "가정의학과", "응급실", "병원", "약국", "한의원", "보건소", "학교", "학원", "유치원", "어린이집", "회사", "은행", "주민센터",
]);
const HE_FUNCTION_WORDS = new Set([
  "לי", "לו", "לה", "לנו", "להם", "שלי", "שלך", "שלו", "שלה", "שלנו", "אני", "אתה", "את", "הוא", "היא", "אנחנו", "הם", "זה",
  "זאת", "כל", "על", "עם", "אל", "של", "מי", "איך", "למה", "כן", "לא", "יש", "אין", "רק", "עוד", "כבר", "אבל", "או", "אם", "כי",
  "עכשיו", "היום", "מחר", "אתמול", "תודה", "בבקשה", "תכין", "תכתוב", "תעזור", "תסביר",
]);

/**
 * One word that is an ordinary word here, whatever its capitals.
 *
 * Three ways to know: a word of the sentence ("the", "In", "that" — the
 * fragment rule above only reads candidates of two words or more); a word of
 * the kind of document a person pastes whole (DOCUMENT_WORDS); or a word the
 * same text also writes in lower case, which no surname ever is — "PROCEDURE"
 * heading a judgment that says "the procedure" twenty times. A given name is
 * exempt from the last, because "Rose" and "rose", "Mark" and "mark" are both
 * ordinary in one message.
 */
export function isOrdinaryWordHere(name: string, text: string): boolean {
  if (/\s/.test(name)) return false;
  const bare = name.replace(/[.’']s?$/u, "").replace(/\.$/, "");
  const lower = bare.toLowerCase();
  if (SENTENCE_WORDS.has(lower) || DOCUMENT_WORDS.has(lower)) return true;
  if (bare.length < 3 || bare === lower || isGivenNameAnywhere(lower)) return false;
  // Escaped without "-": a needless escape is a syntax error under the u flag,
  // and "Birresborn-Kochen-Veranstaltung" threw the whole stage away.
  // A word of prose, not a piece of an address or a handle: "Yulia" is in
  // "yulia.ivanova@mail.ru" and "Ivanov" in "@ivanov_88", and both are people.
  return new RegExp(`(?<![\\p{L}\\p{N}._@/\\\\-])${lower.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}_@/\\\\-]|\\.[\\p{L}\\p{N}])`, "u").test(text);
}

/**
 * A term of art, not a person.
 *
 * The same message asked about a "Secure Enclave" and was answered about a man
 * called Damon Ferreira — and the reply then explained, confidently, that
 * Secure Enclave was "a placeholder name used for anonymization". A capitalised
 * two-word technical term is the exact shape of a first name and a surname, so
 * neither the acronym rule nor anything the model was shown catches it, and
 * the failure is worst in the conversation the product most needs to get right:
 * a user asking how their own data is protected.
 *
 * The guard is the last word, not the phrase. A candidate whose final word is
 * one of these is a piece of technology however it is capitalised — nobody is
 * surnamed Enclave, Encryption or Runtime — while the first word stays free,
 * so "Marta Rivera" and "Secure Enclave" are told apart without a list of
 * every product name in the industry.
 *
 * The test for anything added here is the one COMMON_LOWERCASE carries: if it
 * is plausible as somebody's surname it does not belong, however technical the
 * term also is. That is why Gateway, Bridge, Shield, Park and Field are absent.
 */
const TECHNICAL_NOUNS = new Set([
  "enclave", "enclaves", "encryption", "decryption", "cryptography",
  "computing", "learning", "intelligence", "inference", "algorithm",
  "protocol", "runtime", "kernel", "compiler", "container", "containers",
  "sandbox", "firewall", "keychain", "keystore", "database", "datastore",
  "framework", "middleware", "namespace", "endpoint", "endpoints",
  "authentication", "authorisation", "authorization", "attestation",
  "redaction", "anonymisation", "anonymization", "tokenisation", "tokenization",
  "api", "apis", "sdk", "cpu", "gpu", "vpn", "dns", "tls", "ssl",
]);

/**
 * What a form calls a field, rather than what somebody wrote in it.
 *
 * Found by running the stage against a public corpus: the model returned
 * "date of birth", "home address", "social security number", "mac address"
 * and "investment account" as people. Every one of those is the label on the
 * line above the value — redacting it deletes the word that tells the model
 * what the value is, so the answer comes back about an unlabelled string.
 */
const FIELD_LABELS = new Set([
  "date of birth", "home address", "email address", "mac address",
  "ip address", "social security number", "national insurance number",
  "phone number", "mobile number", "account number", "sort code",
  "investment account", "checking account", "savings account",
  "bank account", "credit card", "card number", "postal code", "zip code",
  "first name", "last name", "full name", "middle name", "job title",
  "nearby gp", "next of kin", "policy number", "reference number",
]);

/**
 * Words for what somebody is, rather than who.
 *
 * Roles, departments and the furniture of an org chart: analyst, facilitator,
 * orchestrator, psychology department, account team, nurses, students. The
 * model returns these steadily and none of them names a person — and several
 * are worse than useless to redact, because a sentence about a department
 * that has had the department swapped for a name reads as being about
 * somebody who does not exist.
 */
const ROLE_WORDS = new Set([
  "analyst", "assistant", "director", "producer", "facilitator", "faculty",
  "orchestrator", "coordinator", "administrator", "supervisor", "manager",
  "engineer", "architect", "consultant", "specialist", "technician",
  "practitioner", "officer", "agent", "advisor", "adviser", "liaison",
  "nurse", "nurses", "doctor", "doctors", "student", "students", "parent",
  "parents", "guardian", "teacher", "teachers", "staff", "team", "department",
  "division", "faculty", "unit", "ward", "wing", "shift", "extension",
  "venue", "course", "quality", "research", "operations", "endocrinology",
  "paediatrics", "pediatrics", "cardiology", "oncology", "radiology",
  "psychology", "psychiatry", "physiotherapy", "occupational therapy",
  "account team", "customer service", "human resources",
]);

/**
 * How somebody describes themselves, which is not their name.
 *
 * Gender, sexuality and blood group are personal data — more sensitive than
 * a name, in most of the world's law — but they are not names, and a stand-in
 * person swapped in for "female" produces a sentence nobody wrote. The name
 * stage should not be the thing that touches these; a rule for them belongs
 * with the other special categories, if anywhere.
 */
const DESCRIBES_A_PERSON = new Set([
  "male", "female", "man", "woman", "boy", "girl", "non-binary", "nonbinary",
  "trans", "transgender", "cisgender", "cisgenders", "bigender", "pangender",
  "agender", "androgynous", "intersex", "two-spirit", "demi-girl", "demi-boy",
  "genderfluid", "genderqueer", "hermaphrodite", "polygender", "neutrois",
  "rhesus negative", "rhesus positive", "blood group",
]);

/** Money, which is named after places and people and is neither. */
const CURRENCIES = new Set([
  "dinar", "dram", "dollar", "pound", "euro", "yen", "yuan", "rupee", "peso",
  "franc", "krone", "krona", "koruna", "forint", "zloty", "shekel", "rand",
  "real", "ringgit", "baht", "dong", "lira", "leone", "kwacha", "birr",
  "naira", "cedi", "shilling", "riyal", "dirham", "taka", "rupiah",
  "litecoin", "ethereum", "bitcoin", "dogecoin",
]);

/**
 * The word an organisation's name ends with.
 *
 * "Psychology Department", "Education Solutions", "Social Emotional Learning
 * Professionals", "Berge Group", "Ruecker LLC" — a phrase ending in one of
 * these is a body, not a body's member, and the model returns them steadily
 * because most of them are built on somebody's surname.
 */
const ORGANISATION_TAILS = new Set([
  "department", "team", "group", "centre", "center", "solutions", "services",
  "professionals", "journal", "institute", "association", "foundation",
  "society", "council", "committee", "board", "bureau", "agency", "office",
  "clinic", "hospital", "practice", "surgery", "school", "college",
  "university", "academy", "library", "laboratory", "labs", "studio",
  "partners", "holdings", "ventures", "systems", "technologies", "industries",
  "llc", "ltd", "limited", "inc", "plc", "gmbh", "corp", "corporation", "co",
]);

/**
 * A place, by the shape of its name.
 *
 * Counties, forts, compass quarters and the -stead, -burgh and -ville a
 * generated town wears. A list of every place on earth is not writable; the
 * words people build place names *out of* are, and they carry most of it:
 * "Crawford County", "Fort Myers", "East of England", "Lower Saxony",
 * "Port Diegostead", "New Jalynburgh".
 *
 * The prompt already says a place is not a person. A 3B model needs it
 * checked as well as said.
 */
const PLACE_WORDS = new Set([
  "county", "shire", "province", "region", "district", "borough", "parish",
  "township", "municipality", "prefecture", "canton", "state", "territory",
  "island", "isles", "coast", "valley", "highlands", "lowlands", "borders",
  "town", "city", "village", "hamlet", "suburb", "metro",
  "midlands", "north", "south", "east", "west", "northwest", "northeast",
  "southwest", "southeast", "upper", "lower", "central", "greater", "fort",
  "port", "saint", "st", "new", "old",
]);

/** A generated town wears one of these. Real ones do too — Hampstead,
 *  Edinburgh, Nashville — which is the point: they are place endings. */
const PLACE_ENDINGS = ["stead", "burgh", "borough", "ville", "shire", "ford", "mouth", "cester", "chester", "hampton", "town", "city"];

function isPlaceName(name: string): boolean {
  const lower = name.toLowerCase().replace(/[.,]+$/, "").trim();
  const words = lower.split(/\s+/);
  if (words.length === 1) {
    return PLACE_ENDINGS.some((e) => lower.length > e.length + 2 && lower.endsWith(e));
  }
  // A place word anywhere in a short phrase: "County Down", "East of
  // England", "Lower Saxony", "Fort Myers".
  if (words.length <= 4 && words.some((w) => PLACE_WORDS.has(w))) return true;
  return words.some((w) => PLACE_ENDINGS.some((e) => w.length > e.length + 2 && w.endsWith(e)));
}

/**
 * A Nordic, Baltic or Slavic town (redactionTowns.ts), as written or in a
 * case form: "Kuopioon", "Savonlinnaan", "Uppsalassa", "в Королёве",
 * "z Krakowa". The endings are the place cases (in, into, from, to, at) and
 * the Slavic genitive, locative and instrumental; the stem is tried as it
 * is and with the vowel the ending replaced. Never a word that is also a
 * given name or a surname: the list holds none, and the stem is checked too.
 */
const TOWN_ENDINGS = [
  "ssa", "ssä", "sta", "stä", "lla", "llä", "lta", "ltä", "lle", "seen", "hin", "hun", "han", "hen", "aan", "ään", "oon", "öön", "iin", "uun", "yyn", "na", "nä", "n",
  "ie", "u", "e", "y", "a", "i", "ą", "ę", "om", "em", "iem", "ем", "ом", "ой", "е", "у", "а", "ы", "и", "і", "ові",
];
function isListedTown(lower: string): boolean {
  if (TOWNS.has(lower)) return true;
  // Case forms in the Latin alphabet only: the name lists hold Cyrillic given
  // names in Latin letters, so "Дмитрові" (to Dmytro) would read as Дмитров.
  if (/\s/.test(lower) || lower.length < 6 || !/^[\p{Script=Latin}-]+$/u.test(lower)) return false;
  for (const ending of TOWN_ENDINGS) {
    if (!lower.endsWith(ending)) continue;
    const stem = lower.slice(0, -ending.length);
    if (stem.length < 5 || SURNAMES.has(stem) || GIVEN_NAMES.has(stem) || WORLD_GIVEN_NAMES.has(stem)) continue;
    // Finnish doubles the last vowel into the illative: Kuopio-on, Savonlinna-an.
    for (const town of [stem, `${stem}a`, `${stem}ä`, `${stem}o`, `${stem}e`, `${stem}а`, `${stem}о`]) if (TOWNS.has(town)) return true;
  }
  return false;
}

/**
 * A town's name used for a person: "mi tía Clemencia", "profe Guadarrama",
 * "Frau Lindau" (realistic6 and realistic7, 2026-11-11). Many towns are also
 * given names and surnames the lists do not hold, and the word before says
 * which it is here. A missed person is a leak and a hidden town is not, so
 * after one of these words the town counts as somebody.
 */
const PERSON_WORD_BEFORE = new RegExp(
  String.raw`(?<![\p{L}])(?:t[íi]as?|t[íi]os?|abuel[ao]s?|prim[ao]s?|herman[ao]s?|hij[ao]s?|sobrin[ao]s?|mam[áa]|pap[áa]|madrina|padrino|profes?|profesora?|maestr[ao]|se[ñn]ora?|sr[ao]?\.?|srta\.?|do[ñn]a|don|doctora?|dra?\.|lic\.|licenciad[ao]|ing\.|ingenier[ao]|av[óô]|tia|tio|dona|senhora?|zi[ao]|nonn[ao]|signora?|sig\.?(?:ra)?|madame|monsieur|mme\.?|m\.|tante|oncle|onkel|frau|herr|oma|opa)[ \t]+$`,
  "iu",
);
export function isTownNamingAPerson(name: string, text: string): boolean {
  if (!isListedTown(name.toLowerCase())) return false;
  for (let i = text.indexOf(name); i !== -1; i = text.indexOf(name, i + 1))
    if (PERSON_WORD_BEFORE.test(text.slice(Math.max(0, i - 24), i))) return true;
  return false;
}

/**
 * Products named the way people are.
 *
 * Firefox, Opera, Maestro, Discover, Mastercard, Mozilla — a browser, a card
 * network and a foundation, all returned as people by a model that has seen
 * them used as names elsewhere. TECHNICAL_NOUNS covers the vocabulary of
 * computing; this covers the brands.
 */
const BRANDS = new Set([
  "firefox", "mozilla", "opera", "chrome", "safari", "edge", "brave", "vivaldi",
  "maestro", "mastercard", "visa", "discover", "amex", "diners", "jcb",
  "paypal", "stripe", "klarna", "revolut", "monzo", "starling",
  "android", "windows", "linux", "ubuntu", "debian", "fedora",
  "oracle", "azure", "alexa", "siri", "cortana", "watson", "gemini", "claude",
  // Software a developer asks about by name (realistic5, 2026-11-02:
  // "Kubernetes Deployment", "scheduler dalam Laravel").
  "kubernetes", "laravel", "docker", "terraform", "ansible", "nginx",
  "postgres", "postgresql", "mysql", "mongodb", "redis", "typescript", "javascript", "python",
]);

/** A name in code: words run together with a capital each, the last one a
 *  programmer's — "PaymentJob failed", "UserService", "OrderController"
 *  (realistic5, 2026-11-02). A person's double name, "McDonald" or
 *  "DeAndre", never ends in one of these. */
const CODE_NAME = /^\p{Lu}\p{Ll}+(?:\p{Lu}\p{Ll}+)*(?:Job|Jobs|Service|Controller|Manager|Handler|Error|Exception|Config|Client|Server|Factory|Provider|Repository|Worker|Queue|Module|Component|Helper|Util|Utils|Test|Spec)$/u;

const DATE_WORDS = new Set([
  "mon", "monday", "tue", "tues", "tuesday", "wed", "weds", "wednesday", "thu", "thur", "thurs",
  "thursday", "fri", "friday", "sat", "saturday", "sun", "sunday", "jan", "january", "feb",
  "february", "march", "apr", "april", "may", "jun", "june", "jul", "july", "aug",
  "august", "sep", "sept", "september", "oct", "october", "nov", "november", "dec", "december",
  "today", "tomorrow", "tonight", "yesterday", "next", "this", "last", "am", "pm", "and", "or", "at", "on",
]);

/**
 * Days, months and times, and nothing else: "Tue", "Sept 3", "Friday 5:30pm",
 * "Wed and Fri". A person's name has at least one word that is none of these.
 */
export function isDateWords(name: string): boolean {
  const words = name.toLowerCase().split(/[\s,]+/).map((w) => w.replace(/[.:]+$/, "")).filter(Boolean);
  if (words.length === 0) return false;
  let sawDay = false;
  // "Mar" is a month beside a number and a name on its own (Spanish).
  if (words.length > 1 && words[0] === "mar" && /^\d/.test(words[1])) words[0] = "march";
  for (const w of words) {
    if (DATE_WORDS.has(w)) { if (!["and", "or", "at", "on", "next", "this", "last", "am", "pm"].includes(w)) sawDay = true; continue; }
    if (/^\d{1,2}(?:st|nd|rd|th)?$/.test(w) || /^\d{1,2}(?::\d{2})?(?:am|pm)?$/.test(w)) continue;
    return false;
  }
  return sawDay;
}

/**
 * A label, a role, a description or a currency — none of them a person.
 *
 * All four lists came from one run of the live benchmark against 400
 * documents, where they accounted for roughly half of everything the model
 * named that was not a name. See cloudflare-worker/bench/liveStage.
 */
export function isNotAPerson(name: string): boolean {
  const lower = name.toLowerCase().replace(/[.,]+$/, "").trim();
  if (FIELD_LABELS.has(lower) || ROLE_WORDS.has(lower) || DESCRIBES_A_PERSON.has(lower)) return true;
  // A currency is usually written with the country in front of it — "Serbian
  // dinar", "South Sudanese pound" — so the last word is what to read.
  const last = lower.split(/\s+/).pop() ?? "";
  if (CURRENCIES.has(last) && lower !== last) return true;
  if (CURRENCIES.has(lower)) return true;
  // A title on its own. "Mr." is not somebody; the name after it is, and the
  // cue pass has already taken that.
  if (/^(?:mr|mrs|ms|miss|dr|prof|sir|madam|mx)\.?$/.test(lower)) return true;
  // An organisation, by the word it ends with.
  const tail = lower.split(/\s+/).pop() ?? "";
  if (lower.includes(" ") && ORGANISATION_TAILS.has(tail.replace(/\./g, ""))) return true;
  // A role with a word in front of it: "male client", "web specialist",
  // "forward marketing engineer". The last word is the one that says what
  // this is.
  if (lower.includes(" ") && ROLE_WORDS.has(tail)) return true;
  if (lower.includes(" ") && DESCRIBES_A_PERSON.has(words0(lower))) return true;
  // And the gender words that arrive with a prefix — "transexual",
  // "trigender", "cisgenders".
  if (/^(?:trans|cis|bi|tri|poly|demi|a|pan|omni|neutr)[a-z]*(?:gender|sexual|girl|boy|ois)s?$/.test(lower)) return true;
  if (BRANDS.has(lower)) return true;
  if (CODE_NAME.test(name.trim())) return true;
  if (isPlaceName(lower)) return true;
  if (isListedTown(lower)) return true;
  // An ordinary word that happens to be capitalised. EVERYDAY_WORDS is
  // consulted for phrases; a single one arrives here as "Amber" or "Grey"
  // and slips past every check built for lower case.
  if (!lower.includes(" ") && EVERYDAY_WORDS.has(lower)) return true;
  return false;
}

/** The first word, for the phrases whose head is the giveaway. */
function words0(lower: string): string {
  return lower.split(/\s+/)[0] ?? "";
}

export function isTechnicalTerm(name: string): boolean {
  const words = name.split(/[\s-]+/).filter(Boolean);
  if (words.length < 2) return false;
  const last = words[words.length - 1].toLowerCase().replace(/[^a-z]/g, "");
  return TECHNICAL_NOUNS.has(last);
}

/** A single lowercase word that is simply a word — see COMMON_LOWERCASE. */
export function isCommonLowercaseWord(name: string): boolean {
  return /^[a-z]+$/.test(name) && COMMON_LOWERCASE.has(name);
}

/**
 * A given name, from the US list or from every country's (redactionWorldGivenNames:
 * "Priya", "Thabo", "Svetlana"), and not an ordinary word in English or in the
 * other languages read here. Used where a given name adds a catch or keeps a
 * name from being dropped; never to drop anything.
 */
export function isGivenNameAnywhere(word: string): boolean {
  const lower = word.toLowerCase();
  if (GIVEN_NAMES.has(lower)) return true;
  if (!WORLD_GIVEN_NAMES.has(lower)) return false;
  const capital = lower.charAt(0).toUpperCase() + lower.slice(1);
  return !isCommonLowercaseWord(lower) && !COMMON_CAPITALISED.has(capital) && !isForeignCommonWords(lower) && !isNotAPerson(capital);
}

/**
 * Is there anything here worth paying an inference for?
 *
 * A capitalised word that is not a sentence opener and not in the list above.
 * Cheap, and wrong in the safe direction: a false positive costs one model
 * call, a false negative costs coverage on that message only.
 */
/**
 * Scripts that have no capital letters at all.
 *
 * The gate below is built on capitalisation, which is a property of the Latin,
 * Cyrillic and Greek alphabets and of almost nothing else. Japanese, Chinese,
 * Korean, Arabic, Hebrew, Thai and the Indic scripts have no upper case for a
 * name to be written in, so no word in a message written in one of them could
 * ever pass that test — the gate returned false, the model was never asked,
 * and the stage reported that it had decided there were no names.
 *
 * The effect was that name redaction did nothing whatsoever for those readers,
 * silently, and strict redaction could not catch it either: the outcome said
 * decided, so there was nothing for it to refuse over.
 *
 * A message containing any of these characters goes to the model. That costs
 * an inference on messages that would previously have skipped one, which is
 * the price of the stage running at all for most of the world.
 */
const CASELESS_SCRIPT =
  /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}\p{Script=Ethiopic}\p{Script=Georgian}\p{Script=Armenian}]/u;

/*
 * A message typed all in lower case is the caseless-script problem again, in
 * Latin letters: "my name is vitoria", "eva kleist lives at 255 hersnapvej
 * 18". Nothing in it can pass a test built on capitals. Measured on Microsoft's Presidio
 * Research corpus, where 11% of the texts that name somebody never reached
 * the model, most of them for this reason or the next.
 */
const HAS_CAPITAL = /\p{Lu}/u;

/*
 * But not every lower-case message: "what is the capital of france" names
 * nobody, and paying an inference on every message somebody types without
 * the shift key is the cost the gate exists to avoid. So a lower-case message
 * goes to the model when something in it points at a person: a name being
 * given ("my name is", "call me", "name:", "maiden name"), a title, a
 * greeting, a relation ("my daughter", "her boss"), a possessive, or a verb
 * that only people do to or with people ("follow up with", "lives at").
 */
const LOWERCASE_PERSON_CUE =
  /\b(?:(?:my|his|her|their|your|first|last|full|maiden|sur|nick)\s*name|name\s*[:=]|call(?:ed)?\s+me|people\s+call\s+me|i(?:'m|’m|\s+am)\s+called|(?:mr|mrs|ms|miss|mx|dr|prof)\.?\s+\p{L}{2}|(?:dear|hi|hello|hey|thanks|thank\s+you)\s+\p{L}{2}|(?:my|his|her|their|your|our)\s+(?:daughter|son|wife|husband|partner|friend|boss|mom|mum|mother|dad|father|brother|sister|colleague|manager|client|patient|neighbou?r|teacher|doctor|lawyer|cousin|aunt|uncle|grandma|grandpa|fianc[eé]e?)\b|(?:follow\s+up|speak|talk|meet|chat|spoke|talked|met)\s+(?:to|with)\s+\p{L}{2}|\p{L}+(?:'s|’s)\s|\blives?\s+(?:at|in|on)\b|\bgender\s+of\b|\bleave\s+me\b)/u;

/* The same cues in Spanish: "me llamo carlos mendoza", "hola ana",
   "mi hija lucía", "sra. treviño". Kept apart from the English list so that
   list reads as it was measured. Word ends are written as "not followed by a
   letter" rather than \b, which does not see accented letters as letters. */
const LOWERCASE_PERSON_CUE_ES =
  /(?<!\p{L})(?:me\s+llamo|mi\s+nombre\s+es|me\s+dicen|nombre\s*[:=]|(?:sr|sra|srta|lic|ing|dr|dra|don|doña)\.?\s+\p{L}{2}|(?:hola|estimad[oa]|querid[oa]|gracias)\s+\p{L}{2}|(?:mi|su|tu|nuestr[oa])\s+(?:hij[oa]|espos[oa]|herman[oa]|madre|padre|mamá|papá|jef[ea]|amig[oa]|cliente|paciente|vecin[oa]|abogad[oa]|doctor[a]?|médic[oa]|prim[oa]|tí[oa]|abuel[oa]|novi[oa]|compañer[oa]|gerente|contador[a]?)(?!\p{L})|(?:hablar|hablé|reunirme|reunión|llamar|llamé)\s+(?:con|a)\s+\p{L}{2}|\bvive\s+en(?!\p{L}))/u;

/*
 * A sentence opener is capitalised by grammar, so on its own it says nothing.
 * But "Scott is a very sympathetic person", "Leif, can I speak to your
 * boss?", "Stefanía K. Oddgeirsdóttir will be talking" and a one-word answer
 * — "What's your last name? Magnusson" — are a name at the front, and the
 * word after it is what gives that away: a comma, another capital, a
 * possessive, or a verb a person does.
 */
const AFTER_A_NAME = /^(?:is|was|has|had|will|and|said|says|asked|told|wants|needs|can|could|would|should|lives|works|called|wrote|sent|thinks|went|came|es|era|fue|está|estaba|tiene|tenía|ha|había|va|dijo|dice|pidió|pide|quiere|necesita|puede|vive|trabaja|llamó|envió|pagó|firmó|debe|y|et|est|était|dit|und|ist|war|hat|sagte|e|è|aveva|disse|foi|tem|tinha)$/;

export function mightContainNames(text: string): boolean {
  if (CASELESS_SCRIPT.test(text)) return true;
  const words = text.split(/\s+/);
  if (!HAS_CAPITAL.test(text) && (LOWERCASE_PERSON_CUE.test(text) || LOWERCASE_PERSON_CUE_ES.test(text))) return true;
  for (let i = 0; i < words.length; i++) {
    const raw = words[i];
    const word = raw.replace(/^[^\p{L}]+|[^\p{L}']+$/gu, "");
    if (word.length < 2) continue;
    if (!/^\p{Lu}/u.test(word)) continue;
    if (COMMON_CAPITALISED.has(word) || COMMON_CAPITALISED.has(word.replace(/'s$/, ""))) continue;
    const previous = i > 0 ? words[i - 1] : "";
    if (i === 0 || /[.!?]$/.test(previous)) {
      const next = (words[i + 1] ?? "").replace(/[^\p{L}.]+$/u, "");
      // A sentence of one word: the answer to "what's your last name?"
      const oneWordSentence = /[.!?]$/.test(raw) || i === words.length - 1;
      // The comma may stand apart, as French typography and text split into
      // tokens write it: "França , T .", "Schwarcz ( rapporteur )" (MAPA).
      if (/,$/.test(raw) || (/^[,;(]$/.test(words[i + 1] ?? "") && !isForeignCommonWords(word)) || /'s$|’s$/.test(word) || /^\p{Lu}/u.test(next) || AFTER_A_NAME.test(next) || oneWordSentence) return true;
      continue;
    }
    return true;
  }
  return false;
}

/**
 * Names the sentence itself points at, found without asking a model.
 *
 * The suite kept failing on "My name is Marta Kowalczyk. Greet me by name in
 * one short sentence." — intermittently, maybe one run in five, with the name
 * going to the provider exactly as written. The same name was caught in six
 * other cases, which is what made it look like flakiness worth shrugging at.
 *
 * It is not flakiness. It is the shape of the prompt. Every worked example
 * given to the model is a name in the third person — a note to Sarah Chen, a
 * neighbour called Tom Bradley — and a 3B model copies the shape it was shown
 * far more reliably than it applies the rule it was told. A self-introduction
 * is a shape it has not seen, and it is also a sentence carrying an
 * instruction, so the model's other failure mode — answering the message
 * instead of extracting from it — is pulling in the same direction.
 *
 * The real problem is that this is the single most sensitive sentence a person
 * can type. Somebody writing "my name is" has stated who they are, on purpose,
 * expecting the product to handle it. Letting that depend on a coin flip in a
 * small model is the wrong architecture regardless of how good the model gets.
 *
 * So the strongest cues are matched literally. This does not replace the
 * model — it cannot find a name that no phrase introduces, which is most of
 * them — it puts a floor under it. The cue list is deliberately short: "I'm"
 * and "I am" are not on it, because "I'm British" and "I am Sorry" are the
 * same shape as "I'm Marta" and there is no way to tell them apart here.
 */
/* Cased by hand rather than with the `i` flag, and that is not fussiness.
   Under `i`, Unicode case folding makes \p{Lu} match lower case too — so the
   pattern that was meant to accept only capitalised words accepted every word,
   and "My name is Marta Kowalczyk and my card is…" aliased a person called
   "Marta Kowalczyk and". Caught by the test below, which is why it is there. */
// And a person the writer introduces by who they are to them: "my lawyer
// Jennifer Ruiz-Okafor", "our landlord Derek Hollins" (third realistic
// hold-out, 2026-10-24: the taggers missed the hyphenated one).
const NAME_CUE_PATTERN =
  /(?:[Mm]y name(?:'s|\u2019s| is)|[Cc]all me|[Ii](?:'m|\u2019m| am) called|[Yy]ou can call me|(?:[Mm]y|[Oo]ur|[Hh]is|[Hh]er|[Tt]heir) (?:lawyer|attorney|solicitor|doctor|dentist|therapist|accountant|client|colleague|coworker|co-worker|boss|manager|friend|neighbou?r|landlord|landlady|tenant|husband|wife|partner|fianc[\u00e9e]e?|son|daughter|brother|sister|mother|father|mum|mom|dad|cousin|uncle|aunt|nephew|niece|grand(?:son|daughter|mother|father)|tutor|teacher|coach|nanny|employee|assistant|contractor|plumber|electrician|realtor|agent|advisor|adviser|caseworker|carer|patient|student))\s+([\p{Lu}][\p{L}'\u2019-]{1,20}(?:\s+[\p{Lu}][\p{L}'\u2019-]{1,20}){0,2})/gu;

/*
 * A title is the other cue: "Dr Reyes", "Mrs Okafor", "Prof. Lindqvist".
 * The model was asked and did not always answer — "a thank-you card for Dr
 * Reyes" came back empty while "call Dr Reyes back on 07700…" did not, and
 * the picture that request made said the doctor's name. Nobody writes a title
 * before anything but a person, so this needs no model. The title is kept in
 * the name, as the model keeps it, so the whole of "Dr Reyes" is swapped.
 *
 * Cased by hand for the same reason as the pattern above. Two capitalised
 * words at most: "Dr Reyes" and "Dr Ana Reyes", not "Dr Reyes Please Call".
 */
const NAME_TITLE_PATTERN =
  /(?<![\p{L}])((?:Dr|Mr|Mrs|Ms|Miss|Mx|Prof|Professor|Doctor|Herr|Frau|Mme|Mlle|Sra|Sr|Dott|Dra)\.?\s+[\p{Lu}][\p{L}'’-]{1,20}(?:\s+[\p{Lu}][\p{L}'’-]{1,20})?)/gu;

/*
 * A title and initials: "Mrs G.", "Mr D.R.", "Mr H.Ç. Akbulut". Court
 * judgments and police reports name people this way to protect them, and the
 * name models, trained on whole names, pass it over — on the Text
 * Anonymization Benchmark (2026-10-05) "Mrs G." went out eleven times in one
 * judgment. The pattern above wants two letters after the title, so it never
 * saw these. A surname may follow the initials; nothing else may.
 */
/* The same in the other languages of the field suites, where judgments name
   people the same way: "Mme A.", "Mes B.", "MM. X.", "Frau K.", "Sig. R.",
   "Sra. P.". MAPA writes the dot apart ("Mme A ."), so it may stand apart.
   Not "M." alone: "M. A." is a degree as often as a man. */
const NAME_TITLE_INITIALS_PATTERN =
  /(?<![\p{L}])((?:Dr|Mr|Mrs|Ms|Miss|Mx|Prof|Professor|Doctor|Mme|Mmes|Mlle|MM|Mes|Me|Herr|Frau|Sig|Sigra|Sra|Sr|Srta|Dott|Dra|Avv)[ \t]?\.?[ \t]+[\p{Lu}][ \t]?\.(?:[ \t]?[\p{Lu}][ \t]?\.){0,2}(?:[ \t][\p{Lu}][\p{L}'’-]{1,20})?)(?![\p{L}])/gu;

/*
 * The Spanish cues, kept apart from the English ones above so those behave
 * exactly as they were measured.
 *
 * A Spanish name is longer and not always capitalised all the way through:
 * two given names and two surnames, joined by "de", "del", "de la" or "y" —
 * "Ana María García de la Fuente". So a name here is up to four capitalised
 * words with those joiners allowed between them. The words are separated by
 * spaces or tabs, never a line break: in a form, the next line is the next
 * field ("Nombre: Ana López" then "Dirección: …"), not more of the name.
 *
 *   A title: Sr., Sra., Srta., Dra., Lic., Licda., Ing., Arq., Don, Doña.
 *     "Lic." and "Ing." are how Mexican business letters address people.
 *     Not "Dr": English uses it too, and the English pass above already
 *     reads it the way it was measured.
 *   A self-introduction: "Me llamo", "Mi nombre es".
 *   A greeting that opens a letter: "Estimada Laura", "Querido Tomás".
 *   A field that holds a person: "Nombre:", "Nombre completo:", "Titular:",
 *     "Titular de la cuenta:", "A nombre de".
 */
const ES_NAME = String.raw`[\p{Lu}][\p{L}'’-]{1,20}(?:(?:[ \t]+(?:de[ \t]+la|de[ \t]+las|de[ \t]+los|del|de|y))?[ \t]+[\p{Lu}][\p{L}'’-]{1,20}){0,3}`;
const ES_TITLES = new Set(["Sr", "Sra", "Srta", "Dr", "Dra", "Lic", "Licda", "Licdo", "Ing", "Arq", "Don", "Doña"]);
const ES_TITLE_PATTERN = new RegExp(String.raw`(?<![\p{L}])((?:Srta|Sra|Sr|Dra|Licda|Licdo|Lic|Ing|Arq)\.?[ \t]+${ES_NAME}|(?:Doña|Don)[ \t]+${ES_NAME})`, "gu");
const ES_CUE_PATTERN = new RegExp(String.raw`(?:(?<![\p{L}])(?:[Mm]e[ \t]+llamo|[Mm]i[ \t]+nombre[ \t]+es|[Ee]stimad[oa]|[Qq]uerid[oa])[ \t]+|(?<![\p{L}])(?:[Nn]ombre(?:[ \t]+completo)?|[Tt]itular(?:[ \t]+de[ \t]+la[ \t]+cuenta)?)[ \t]*:[ \t]*|(?<![\p{L}])[Aa][ \t]+nombre[ \t]+de[ \t]+)(${ES_NAME})`, "gu");

/* A company in a field that could hold a person: "Titular: Construcciones
   Garza S.A. de C.V.". The first word says so, or what follows the name does. */
const ES_COMPANY_WORDS = new Set([
  "Construcciones", "Constructora", "Servicios", "Grupo", "Distribuidora",
  "Comercializadora", "Transportes", "Inmobiliaria", "Banco", "Seguros",
  "Industrias", "Corporativo", "Corporación", "Consultores", "Asociados",
  "Hermanos", "Compañía", "Empresa", "Sociedad", "Fundación", "Instituto",
  "Clínica", "Hospital", "Farmacia", "Ferretería", "Talleres", "Taller",
  "Almacenes", "Laboratorio", "Laboratorios", "Despacho", "Agencia",
]);
const ES_COMPANY_AFTER = /^[ \t,]*(?:S\.?\s?A\.?|S\.?\s?L\.?|S\.?\s?de\s?R\.?\s?L\.?|S\.?\s?C\.?|A\.?\s?C\.?|S\.?\s?A\.?\s?P\.?\s?I\.?|Inc\.?|LLC|Ltd\.?|Corp\.?|y\s+(?:Cía|Compañía|Asociados|Hijos))(?![\p{L}])/u;

const ES_JOINERS = new Set(["de", "del", "la", "las", "los", "y"]);

/** Trims the common words, then any joiner left dangling at the end. */
function trimSpanishName(parts: string[]): string[] {
  const out = [...parts];
  while (out.length > 0 && (COMMON_CAPITALISED.has(out[out.length - 1]) || ES_JOINERS.has(out[out.length - 1]))) out.pop();
  return out;
}

/* Adds a name found by a Spanish cue. The English title pass may already
   have taken the first two words of it — "Sra. Beatriz Olmos" out of "Sra.
   Beatriz Olmos de la Garza" — and one person must not become two stand-ins,
   so the longer reading replaces the shorter. */
function addSpanishName(out: string[], name: string): void {
  if (out.some((n) => n === name || n.includes(name))) return;
  for (let i = out.length - 1; i >= 0; i--) if (name.includes(out[i])) out.splice(i, 1);
  out.push(name);
}

function spanishNamesFromCues(text: string, out: string[]): void {
  for (const match of text.matchAll(ES_TITLE_PATTERN)) {
    const parts = trimSpanishName(match[1].split(/[ \t]+/));
    if (parts.length < 2) continue;
    const name = parts.join(" ");
    const bare = parts.slice(1).join(" ");
    if (COMMON_CAPITALISED.has(parts[1]) || ES_COMPANY_WORDS.has(parts[1])) continue;
    if (isAcronym(bare) || isSentenceFragment(bare) || isTechnicalTerm(bare)) continue;
    if (!isSubstitutable(name)) continue;
    addSpanishName(out, name);
  }

  for (const match of text.matchAll(ES_CUE_PATTERN)) {
    const parts = trimSpanishName(match[1].split(/[ \t]+/));
    if (parts.length === 0) continue;
    // A title after the cue is the title pass's to take — "Estimada Sra.
    // López" is "Sra. López", not a person called "Sra".
    if (ES_TITLES.has(parts[0]) || ES_TITLES.has(parts[0].replace(/\.$/, ""))) continue;
    if (COMMON_CAPITALISED.has(parts[0]) || ES_COMPANY_WORDS.has(parts[0])) continue;
    const end = (match.index ?? 0) + match[0].length;
    if (ES_COMPANY_AFTER.test(text.slice(end))) continue;
    const name = parts.join(" ");
    if (name.length < 2) continue;
    if (isAcronym(name) || isSentenceFragment(name) || isTechnicalTerm(name) || isNotAPerson(name)) continue;
    if (!isSubstitutable(name)) continue;
    addSpanishName(out, name);
  }
}

/*
 * The same deterministic floor for the other five languages of the business
 * benchmark — French, German, Italian, Dutch, Swedish — and for the English
 * form fields none of the passes above read ("Full Name:", "Account
 * Holder:"). Kept apart from the English and Spanish cues so those behave
 * exactly as they were measured.
 *
 * A name is up to four capitalised words, a middle initial allowed ("Steven
 * R. Johnson"), with the particles these languages put inside surnames
 * between them ("Senna Schellekens-van der Berg", "Hans von der Heide",
 * "Anna di Stefano", "Karl af Klint"). Spaces and tabs only: the next line of
 * a form is the next field.
 *
 *   A title: M., Mme, Mlle, Monsieur, Madame, Herr, Frau, Sig., Sig.ra,
 *     Signor, Signora, Dott., Dott.ssa, Avv., Dhr., Mevr., Fru.
 *   A self-introduction: "Je m'appelle", "Ich heiße", "Mi chiamo", "Ik heet",
 *     "Jag heter", and "my name is" in each.
 *   A greeting that opens a letter: "Chère Aurélie", "Liebe Anna", "Gentile
 *     Marco", "Beste Joost", "Kära Karin".
 *   A field that holds a person, capitalised and followed by a colon: "Nom :",
 *     "Name:", "Full Name:", "Kontoinhaber:", "Nome e cognome:", "Naam:",
 *     "Namn:", "Mittente:", "Betalare:"...
 *
 * A company in the field is passed over, by its first word ("Banque",
 * "Sparkasse", "Stichting") or by the legal form after it ("GmbH", "S.p.A.",
 * "B.V.", "AB").
 */
/* A word that runs on into digits or an underscore is an identifier: "Name: WebApp1".
   A word followed by a colon is the next field's label: "Gebruiker: Vincent H. Bennett Status: Open". */
const EU_NAME_WORD = String.raw`[\p{Lu}][\p{L}'’-]{1,24}(?![\p{L}\d_@])(?![ \t]*:)`;
const EU_PARTICLE = String.raw`(?:van[ \t]+der|van[ \t]+den|van[ \t]+de|von[ \t]+der|von[ \t]+dem|de[ \t]+la|van|von|zu|du|des|de|di|da|del|della|dello|ter|te|af|le|la|'t)`;
const EU_NAME = String.raw`${EU_NAME_WORD}(?:(?:[ \t]+${EU_PARTICLE})?[ \t]+(?:${EU_NAME_WORD}|[\p{Lu}]\.)){0,3}`;
const EU_TITLES = new Set(["M", "Mme", "Mlle", "Monsieur", "Madame", "Mademoiselle", "Herr", "Herrn", "Frau", "Sig", "Sig.ra", "Signor", "Signora", "Signore", "Dott", "Dott.ssa", "Avv", "Dhr", "Mevr", "Mw", "Fru", "Fröken", "Sra", "Sr", "Srta", "Mr", "Mrs", "Ms", "Dr"]);
/* "M." is also a middle initial: "Erik M. Bray", "Mr M. Fischbach", "(Contributed
   by M. Felt)". It is Monsieur only where no name, English title or "by" is
   just before it. */
const EU_TITLE_PATTERN = new RegExp(String.raw`(?<![\p{L}.])((?:(?<!(?:[\p{Lu}][\p{L}'’-]*|Mrs?|Ms|Dr|by|and)\.?[ \t]+)M\.|Señor(?:a|ita)?|Dr\.[ \t]?med\.(?:[ \t]?dent\.)?|Mmes?\.?|Mlle\.?|Monsieur|Madame|Mademoiselle|Herrn?|Frau|Sig\.(?:ra)?|Signor[ae]?|Dott\.(?:ssa)?|Avv\.|Dhr\.|Mevr\.|Mw\.|Fru|Fröken)[ \t]+${EU_NAME})`, "gu");
/* No payee or beneficiary fields: in business paperwork those hold a shop or a
   company as often as a person ("Payee: ABC Online Store"). */
const EU_FIELD = String.raw`(?:Nom(?:[ \t]+(?:et[ \t]+prénom|complet|du[ \t]+client|du[ \t]+titulaire|de[ \t]+famille))?|Prénom(?:[ \t]+et[ \t]+nom)?|Titulaire(?:[ \t]+du[ \t]+compte)?|Expéditeur|Destinataire|Emprunteur|Name|Full[ \t]+Name|Legal[ \t]+Name|Full[ \t]+Legal[ \t]+Name|Customer[ \t]+Name|Client[ \t]+Name|Account[ \t]+Holder(?:[ \t]+Name)?|Cardholder(?:[ \t]+Name)?|Card[ \t]+Holder|Patient(?:[ \t]+Name)?|Employee[ \t]+Name|Applicant(?:[ \t]+Name)?|Borrower(?:[ \t]+Name)?|Policyholder|Policy[ \t]+Holder|Insured(?:[ \t]+Name)?|Sender(?:[ \t]+Name)?|Recipient(?:[ \t]+Name)?|Payer|Contact(?:[ \t]+Name|[ \t]+Person)?|Vollständiger[ \t]+Name|Vor-[ \t]+und[ \t]+Nachname|Nachname|Vorname|Kontoinhaber(?:in)?|Karteninhaber(?:in)?|Versicherungsnehmer(?:in)?|Antragsteller(?:in)?|Absender|Empfänger|Kunde|Kundin|Nome(?:[ \t]+(?:completo|e[ \t]+cognome|del[ \t]+cliente))?|Cognome(?:[ \t]+e[ \t]+nome)?|Intestatario(?:[ \t]+del[ \t]+conto)?|Titolare(?:[ \t]+del[ \t]+conto)?|Mittente|Destinatario|Contraente|Naam|Volledige[ \t]+naam|Achternaam|Voornaam|Rekeninghouder|Verzekeringnemer|Afzender|Ontvanger|Namn|Fullständigt[ \t]+namn|Efternamn|Förnamn|Kontoinnehavare|Kontohavare|Avsändare|Mottagare|Betalare|Försäkringstagare|Låntagare|Sökande|Gebruiker|Klantnaam|Kundenname|Kundnamn|Nome[ \t]+cliente|Shipper|Consignee|Signatory|Signed[ \t]+by|Plaintiff|PLAINTIFF|Defendant|DEFENDANT|Claimant|CLAIMANT|Respondent|RESPONDENT|Petitioner|PETITIONER|Appellant|APPELLANT|Tenant|TENANT|Landlord|LANDLORD|Witness|WITNESS|Debtor|DEBTOR|Guarantor|GUARANTOR|Beneficiary[ \t]+Name|Next[ \t]+of[ \t]+Kin|Emergency[ \t]+Contact|Unterzeichnet[ \t]+von|Förhandlat[ \t]+av|Signé[ \t]+par|Firmato[ \t]+da|Ondertekend[ \t]+door)`;
const EU_CUE_PATTERN = new RegExp(String.raw`(?:(?<![\p{L}])(?:[Jj]e[ \t]+m['’]appelle|[Mm]on[ \t]+nom[ \t]+est|[Ii]ch[ \t]+hei(?:ß|ss)e|[Mm]ein[ \t]+Name[ \t]+ist|[Mm]i[ \t]+chiamo|[Ii]l[ \t]+mio[ \t]+nome[ \t]+è|[Ii]k[ \t]+heet|[Mm]ijn[ \t]+naam[ \t]+is|[Jj]ag[ \t]+heter|[Mm]itt[ \t]+namn[ \t]+är|[Cc]her|[Cc]hère|[Ll]iebe[rs]?|[Gg]entile|[Gg]entilissim[oa]|[Cc]aro|[Cc]ara|[Bb]este|[Kk]ära|[Kk]äre|[Bb]ästa|Hej|Hallo|Bonjour|Buongiorno|Goedendag|Goedemorgen|Hoi)[ \t]+|(?<![\p{L}][ \t/-]*)${EU_FIELD}[ \t]*\**[ \t]*:[ \t]*\**[ \t]*)(${EU_NAME})`, "gu");

/* Three more places a document puts a person, in any of the languages:
   the line after a letter's sign-off ("Mit freundlichen Grüßen,\nMax
   Mustermann"), a markup element that holds a name and nothing else
   ("<Nombre>Timo Zuidweg</Nombre>"), and the party a contract opens with
   ("by and between Cornelia Dorsman, with a mailing address…"). */
/* Sign-offs in more of the languages people write letters in: Polish,
   Czech, Slovak, Hungarian, Romanian, Turkish, Norwegian, Danish, Finnish,
   Portuguese, and the warmer forms of the ones above ("Pozdrawiam, Piotr
   Kowalczyk", realistic3, where seed 13 missed it). */
const MORE_SIGN_OFFS = String.raw`(?:Serdecznie[ \t]+)?[Pp]ozdrawiam|Z[ \t]+poważaniem|Łączę[ \t]+pozdrowienia|S[ \t]+pozdravem|S[ \t]+pozdravom|S[ \t]+úctou|Üdvözlettel|Tisztelettel|Cu[ \t]+stimă|Cu[ \t]+respect|Cu[ \t]+drag|Saygılarımla|Saygılarımızla|Med[ \t]+vennlig[ \t]+hilsen|Vennlig[ \t]+hilsen|Med[ \t]+venlig[ \t]+hilsen|Venlig[ \t]+hilsen|Ystävällisin[ \t]+terveisin|Parhain[ \t]+terveisin|Terveisin|Atenciosamente|Cordialmente|Com[ \t]+os[ \t]+melhores[ \t]+cumprimentos|Melhores[ \t]+cumprimentos|Cumprimentos|Um[ \t]+abraço|Abraços|Un[ \t]+(?:cordial[ \t]+)?saludo|Un[ \t]+abrazo|Bien[ \t]+à[ \t]+vous|Salutations[ \t]+distinguées|Bien[ \t]+amicalement|Herzliche[ \t]+Grüße|Liebe[ \t]+Grüße|Schöne[ \t]+Grüße|Un[ \t]+saluto|Cari[ \t]+saluti|Hartelijke[ \t]+groet(?:en)?|Met[ \t]+hartelijke[ \t]+groet(?:en)?|Bästa[ \t]+hälsningar|Best[ \t]+wishes|Many[ \t]+thanks|With[ \t]+thanks|Warm[ \t]+wishes|All[ \t]+the[ \t]+best|Respectfully(?:[ \t]+yours)?`;
/* A second sign-off below the first ("Thank you!\n\nRegards,\nNancy Hall", Enron)
   is not the name, and must not use up the line the name is on. */
const SIGN_OFF_WORD = String.raw`(?:Thanks|Thank|Best|Regards|Cheers|Warmly|Kind|Warm|Sincerely|Yours|Many|With|All|Respectfully)(?![\p{L}])`;
const EU_SIGN_OFF_PATTERN = new RegExp(String.raw`(?<![\p{L}])(?:Mit[ \t]+freundlichen[ \t]+Grüßen|Freundliche[ \t]+Grüße|Viele[ \t]+Grüße|Beste[ \t]+Grüße|(?:Bien[ \t]+)?[Cc]ordialement|Sincères[ \t]+salutations|Cordiali[ \t]+saluti|Distinti[ \t]+saluti|(?:Met[ \t]+)?[Vv]riendelijke[ \t]+groet(?:en)?|(?:Med[ \t]+)?[Vv]änliga[ \t]+hälsningar|Atentamente|Saludos[ \t]+cordiales|Best[ \t]+regards|Kind[ \t]+regards|Warm[ \t]+regards|Sincerely(?:[ \t]+yours)?|Yours[ \t]+(?:sincerely|faithfully|truly)|${MORE_SIGN_OFFS})[ \t]*[,.]?[ \t]*(?:\r?\n[ \t]*){0,2}(?!${SIGN_OFF_WORD})(${EU_NAME})(?=[ \t]*(?:[,|\r\n]|$))`, "gu");
/* A letter signed by a desk or a committee, or a second sign-off on the line
   below the first ("Thanks\nBest Regards"): Enron, Gretel, WildChat. */
const SIGNED_BY_A_TEAM = new Set([
  "Best", "Regards", "Thanks", "Kind", "Warm", "Cheers", "Sincerely", "Admin", "Administrator", "Team", "Support", "Department",
  "Dept", "Office", "Staff", "Management", "Desk", "Service", "Services", "Customer", "Committee", "Board", "Secretariat",
  "Comissão", "Departamento", "Equipe", "Equipa", "Direção", "Secretaria", "Abteilung", "Équipe", "Service", "Servizio", "Ufficio",
  "Afdeling", "Avdelningen", "Zespół", "Dział", "Redakcja",
  // Who a mail goes to when it is not a person: "To: Prospective Natural Gas Supplier".
  "Supplier", "Suppliers", "Vendor", "Vendors", "Members", "Participants", "Shareholders", "Investors", "Subscribers", "Distribution",
  // Support desks in the other languages a header is written in.
  "Equipo", "Soporte", "Suporte", "Apoio", "Assistenza", "Ondersteuning", "Tým", "Tím", "Podpory", "Podpora", "Tiimi", "Echipa",
  "Suport", "Ekibi", "Ekip", "Destek", "Dukungan", "Pasukan", "Sokongan", "Ομάδα", "Υποστήριξης", "Служба", "Отдел", "Команда",
]);
/* The short ones are also how a sentence starts ("Thanks, Apple fixed it"),
   so only with the name on the line below, which is a signature. */
const SIGN_OFF_LINE_PATTERN = new RegExp(String.raw`(?<![\p{L}])(?:Thanks|Thank[ \t]+you|Best|Regards|Cheers|Warmly|Gracias|Merci|Danke|Grazie|Bedankt|Tack|Dzięki|Dziękuję|Obrigad[oa]|Saludos|Grüße|Groeten|Hälsningar|Mvh|LG)[ \t]*[,!.]?[ \t]*\r?\n(?:[ \t]*\r?\n)?[ \t]*(?!${SIGN_OFF_WORD})(${EU_NAME})(?=[ \t]*(?:[,|\r\n]|$))`, "gu");
/* The name under the "-- " line that opens a mail signature, and the person a
   reply quotes ("On Tue, 4 Jun, Ella Moss wrote:", "Am 3. Mai schrieb Max
   Weber <max@…>:"). The quoted writer is always a sender, never a place. */
const SIGNATURE_DASH_PATTERN = new RegExp(String.raw`(?:^|\n)--[ \t]?\r?\n[ \t]*(${EU_NAME})(?=[ \t]*(?:[,|\r\n]|$))`, "gu");
const QUOTE_WROTE_PATTERN = new RegExp(String.raw`(?:(?:^|\n|,[ \t])[ \t]*(${EU_NAME})[ \t]*(?:<[^<>\s]{3,80}>[ \t]*)?(?:wrote|a[ \t]+écrit|escribió|ha[ \t]+scritto|schreef|skrev|napisał\(a\)|napisała|napisał|escreveu|yazdı|menulis|kirjoitti)|(?<![\p{L}])schrieb[ \t]+(${EU_NAME})[ \t]*(?:<[^<>\s]{3,80}>[ \t]*)?)[ \t]*:`, "gu");
const EU_NAME_TAG_PATTERN = new RegExp(String.raw`<(?:[\w-]+:)?(?:[Nn]ame|[Nn]ombre|[Nn]om|[Nn]ome|[Nn]aam|[Nn]amn|FullName|PartyName|PersonName|CustomerName|ContactName|ClientName)(?:[ \t][^>\n]{0,60})?>[ \t]*(${EU_NAME})[ \t]*<\/`, "gu");
const EU_PARTY_PATTERN = new RegExp(String.raw`(?<![\p{L}])by[ \t]+and[ \t]+between[ \t]+(${EU_NAME})(?=[ \t]*[,(])`, "gu");

const EU_COMPANY_WORDS = new Set([
  "Banque", "Bank", "Banca", "Banco", "Sparkasse", "Volksbank", "Raiffeisenbank", "Crédit", "Caisse", "Versicherung", "Versicherungen",
  "Assurance", "Assurances", "Assicurazioni", "Groupe", "Gruppo", "Group", "Société", "Gesellschaft", "Firma", "Stiftung",
  "Fondation", "Fondazione", "Stichting", "Verein", "Association", "Associazione", "Vereniging", "Hotel", "Restaurant",
  "Company", "Compagnie", "Compagnia", "Holding", "Handels", "Immobilien", "Immobilier", "Immobiliare", "Consulting",
  "Services", "Service", "Solutions", "Systems", "Technologies", "Industries", "International", "Global", "Studio",
  "Kanzlei", "Cabinet", "Agence", "Agentur", "Agenzia", "Bureau", "Kantoor", "Klinik", "Clinique", "Clinica", "Hospital",
  "Apotheke", "Pharmacie", "Farmacia", "Universität", "Université", "Università", "Universiteit", "Universitet", "Ministerium",
  "Ministère", "Ministero", "Ministerie", "Gemeinde", "Commune", "Comune", "Gemeente", "Kommun", "Stadt", "Ville", "Città",
  "Staff", "Team", "Équipe", "Kunde", "Kunden", "Client", "Clients", "Cliente", "Clienti", "Klant", "Klanten", "Kund", "Kunder",
  "Customer", "Customers", "Madame", "Monsieur", "Herr", "Frau", "Signore", "Signora", "Heer", "Mevrouw", "Damen", "Herren",
  "Mesdames", "Messieurs", "Sehr", "Geehrte", "Geehrter", "Tutti", "Tous", "Alle", "Allen", "Allemaal", "Alla",
]);
const EU_COMPANY_AFTER = /^[ \t,]*(?:GmbH|AG|KG|OHG|e\.\s?V\.|SE|S\.?\s?A\.?(?:S\.?)?|SARL|SAS|SNC|S\.?\s?p\.?\s?A\.?|S\.?\s?r\.?\s?l\.?|S\.?\s?n\.?\s?c\.?|B\.?\s?V\.?|N\.?\s?V\.?|V\.?\s?O\.?\s?F\.?|AB|HB|Oy|A\/S|ApS|AS|ASA|Ltd\.?|Limited|Inc\.?|LLC|LLP|Corp\.?|PLC|plc|&\s?(?:Co|Cie|Söhne|Partner)|und\s+(?:Partner|Söhne)|et\s+(?:Fils|Cie)|e\s+(?:Figli|C\.))(?![\p{L}])/u;
const EU_JOINERS = new Set(["van", "von", "der", "den", "dem", "de", "zu", "du", "des", "di", "da", "del", "della", "dello", "ter", "te", "af", "le", "la", "'t"]);
/* A legal form anywhere in the name or just after it ("Deutsche Bank AG",
   "XYZ B.V.", "IKEA Sverige AB"), or a word that only a business, a place or a
   department carries ("ABC Online Store", "Thompson Family Farms", "Local
   Hospital"): the field holds an organisation. Measured on the practice
   documents, where "Business Name:", "Bank Name:" and these were most of the
   companies the new cues took. */
const EU_LEGAL_FORM = /(?:^|[ \t])(?:GmbH|AG|KG|OHG|SE|SA|SAS|SARL|SpA|Srl|SRL|SL|BV|NV|AB|HB|Oy|AS|ASA|ApS|Ltd|Inc|LLC|LLP|PLC|Corp|S\.\s?A\.|B\.\s?V\.|N\.\s?V\.|S\.\s?p\.\s?A\.|S\.\s?r\.\s?l\.|S\.\s?L\.|e\.\s?V\.)(?![\p{L}])/u;
const EU_ORG_WORDS = new Set([
  "Store", "Shop", "Shops", "Cafe", "Café", "Coffee", "Bakery", "Restaurant", "Bar", "Farm", "Farms", "Enterprises", "Enterprise",
  "Builders", "Construction", "Services", "Solutions", "Systems", "Technologies", "Tech", "Industries", "Group", "Holding", "Holdings",
  "Bank", "Railways", "Railway", "Airlines", "Airways", "Shipping", "Maritime", "Logistics", "Transport", "Therapy", "Hospital", "Clinic",
  "Department", "Procedures", "Health", "Healthcare", "Travel", "Experiences", "Motors", "Foods", "Partners", "Associates", "Consulting",
  "Insurance", "Market", "Markets", "Media", "Studios", "Energy", "Pharma", "Labs", "Trading", "Capital", "Ventures", "Investments",
  "Realty", "Properties", "Agency", "Office", "Institute", "Foundation", "University", "College", "School", "Academy", "Council",
  "Committee", "Commissione", "Comitato", "Comité", "Centro", "Center", "Centre", "Kulturcentrum", "Importaciones", "Elettroniche",
]);

/* A memo's or a mail's header lines ("From: Priya Shah", "An: Sabine Vogt;
   Jonas Ott", "Prepared by: Tomás Ruiz"). The sign-off-like labels say a
   person on their own. The short ones ("A:", "De:", "To:") are also a quiz's
   answer or a route's end ("From: London\nTo: Paris"), so only in a block that
   has a subject or sent line too, or with the address right after the name. */
const MAIL_BY_LABELS = [
  "Attn", "Attn.", "Attention", "Signed", "Signature", "Unterschrift", "Signé", "Firmado", "Firmato", "Getekend", "Undertecknat", "Podpisano", "Prepared by", "Approved by", "Reviewed by", "Written by", "Authored by", "Compiled by", "Requested by",
  "Submitted by", "Erstellt von", "Geprüft von", "Genehmigt von", "Verfasst von", "Préparé par", "Approuvé par", "Rédigé par",
  "Preparado por", "Aprobado por", "Elaborado por", "Revisado por", "Preparato da", "Approvato da", "Redatto da", "Opgesteld door",
  "Goedgekeurd door", "Upprättad av", "Godkänd av", "Sporządził", "Sporządziła", "Zatwierdził", "Zatwierdziła", "Hazırlayan", "Onaylayan",
];
const MAIL_HEADER_LABELS = [
  "From", "To", "Cc", "Bcc", "Von", "An", "Kopie", "De", "À", "A", "Para", "Da", "Per", "Van", "Aan", "Från", "Till", "Fra", "Til",
  "Od", "Do", "Kimden", "Kime", "Dari", "Kepada", "Feladó", "Címzett", "Lähettäjä", "Vastaanottaja", "Către", "Odesílatel", "Komu",
  "Remetente", "Destinatário", "От", "Кому", "Від", "Από", "Προς", "Sender", "Recipient", "Recipients",
];
const MAIL_BLOCK_LABELS = [
  "Subject", "Re", "Betreff", "Objet", "Asunto", "Oggetto", "Onderwerp", "Ämne", "Emne", "Temat", "Předmět", "Predmet", "Tárgy", "Aihe",
  "Konu", "Perihal", "Subiect", "Assunto", "Тема", "Θέμα", "Sent", "Gesendet", "Envoyé", "Enviado", "Inviato", "Verzonden", "Skickat",
  "Sendt", "Wysłano", "Odesláno", "Cc", "Bcc",
];
const labelAlternatives = (labels: string[]) =>
  [...new Set(labels.flatMap((l) => [l, l.toUpperCase()]))]
    .sort((a, b) => b.length - a.length)
    .map((l) => l.replace(/[.]/g, "\\.").replace(/ /g, "[ \\t]+"))
    .join("|");
const MAIL_FIELD_LINE = new RegExp(String.raw`(?:^|\n)[ \t>]*\**(${labelAlternatives([...MAIL_BY_LABELS, ...MAIL_HEADER_LABELS])})\**[ \t]*:[ \t]*([^\r\n]{1,200})`, "gu");
const MAIL_BLOCK_LINE = new RegExp(String.raw`(?:^|\n)[ \t>]*\**(?:${labelAlternatives(MAIL_BLOCK_LABELS)})\**[ \t]*:`, "u");
const MEMO_HEADING = /(?:^|\n)[ \t]*(?:MEMORANDUM|MEMO|Memorandum|INTERNAL MEMO|Internal memo|AKTENNOTIZ|NOTE DE SERVICE|MEMORÁNDUM)[ \t]*\r?\n/u;
const MAIL_BY = new Set(MAIL_BY_LABELS.flatMap((l) => [l, l.toUpperCase()]));
const WHOLE_EU_NAME = new RegExp(String.raw`^(?:${EU_NAME})$`, "u");

function mailHeaderFields(text: string): Array<RegExpExecArray & { 1: string }> {
  if (!text.includes(":")) return [];
  const block = MAIL_BLOCK_LINE.test(text) || MEMO_HEADING.test(text);
  const found: Array<RegExpExecArray & { 1: string }> = [];
  for (const line of text.matchAll(MAIL_FIELD_LINE)) {
    const label = line[1].replace(/[ \t]+/g, " ");
    const value = line[2];
    const strong = MAIL_BY.has(label);
    let at = (line.index ?? 0) + line[0].length - value.length;
    for (const piece of value.split(/([;,])/)) {
      const start = at;
      at += piece.length;
      if (piece === ";" || piece === ",") continue;
      const addressed = /<[^<>\s]+@[^<>\s]+>/.test(piece);
      if (!strong && !block && !addressed) continue;
      // A list's tag in capitals before a name: "ACTIVE Howard Low (E-mail)".
      const bare = piece.replace(/<[^<>]*>|\([^()]*\)|["'“”]/g, " ").replace(/[ \t]+/g, " ").trim().replace(/^(?:\p{Lu}{3,} )+(?=\p{Lu}\p{Ll})/u, "");
      if (!WHOLE_EU_NAME.test(bare)) continue;
      // One word alone is a desk ("From: Finance") unless it is a given name.
      if (!bare.includes(" ") && !isGivenNameAnywhere(bare)) continue;
      // A short word in capitals beside words that are not is a desk's: "Tim Dukungan TI", "BT Destek Ekibi".
      if (/\p{Ll}/u.test(bare) && bare.split(" ").some((w) => /^\p{Lu}{2,4}$/u.test(w))) continue;
      // In capitals it is as often a firm ("EVERGREEN INVESTMENT"): only from a given name.
      if (!/\p{Ll}/u.test(bare)) {
        const first = bare.split(" ")[0];
        if (!isGivenNameAnywhere(first.charAt(0) + first.slice(1).toLowerCase())) continue;
      }
      const index = start + piece.indexOf(bare.split(" ")[0]);
      found.push(Object.assign([bare, bare], { index, input: text }) as unknown as RegExpExecArray & { 1: string });
    }
  }
  return found;
}

function europeanNamesFromCues(text: string, out: string[]): void {
  const trim = (parts: string[]) => {
    const kept = [...parts];
    while (kept.length > 0 && (COMMON_CAPITALISED.has(kept[kept.length - 1]) || EU_JOINERS.has(kept[kept.length - 1]) || EU_COMPANY_WORDS.has(kept[kept.length - 1]))) kept.pop();
    return kept;
  };

  for (const match of text.matchAll(EU_TITLE_PATTERN)) {
    const parts = trim(match[1].split(/[ \t]+/));
    if (parts.length < 2) continue;
    if (COMMON_CAPITALISED.has(parts[1]) || EU_COMPANY_WORDS.has(parts[1])) continue;
    const name = parts.join(" ");
    const bare = parts.slice(1).join(" ");
    if (isAcronym(bare) || isSentenceFragment(bare) || isTechnicalTerm(bare)) continue;
    if (!isSubstitutable(name)) continue;
    addSpanishName(out, name);
  }

  const cued = [EU_CUE_PATTERN, EU_SIGN_OFF_PATTERN, SIGN_OFF_LINE_PATTERN, EU_NAME_TAG_PATTERN, EU_PARTY_PATTERN, SIGNATURE_DASH_PATTERN, QUOTE_WROTE_PATTERN]
    .flatMap((pattern) => [...text.matchAll(pattern)])
    .map((match) => Object.assign(match, { 1: match[1] ?? match[2] }));
  cued.push(...mailHeaderFields(text));
  for (const match of cued) {
    const parts = trim(match[1].split(/[ \t]+/));
    if (parts.length === 0) continue;
    // A title after the cue is the title passes' to take: "Chère Mme Leroy".
    if (EU_TITLES.has(parts[0].replace(/\.$/, "")) || ES_TITLES.has(parts[0].replace(/\.$/, ""))) continue;
    if (COMMON_CAPITALISED.has(parts[0]) || EU_COMPANY_WORDS.has(parts[0]) || ES_COMPANY_WORDS.has(parts[0])) continue;
    const end = (match.index ?? 0) + match[0].length;
    if (EU_COMPANY_AFTER.test(text.slice(end)) || ES_COMPANY_AFTER.test(text.slice(end))) continue;
    if (EU_LEGAL_FORM.test(match[1] + text.slice(end, end + 12))) continue;
    if (match[1].split(/[ \t]+/).some((w) => EU_ORG_WORDS.has(w) || EU_COMPANY_WORDS.has(w) || ES_COMPANY_WORDS.has(w) || SIGNED_BY_A_TEAM.has(w))) continue;
    const name = parts.join(" ");
    if (name.length < 2) continue;
    // camelCase is code, not a surname: "Name: WebApp". McDonald and MacLeod are surnames.
    if (/(?<!\bMa?c)\p{Ll}\p{Lu}/u.test(name)) continue;
    if (isAcronym(name) || isSentenceFragment(name) || isTechnicalTerm(name) || isNotAPerson(name)) continue;
    if (!isSubstitutable(name)) continue;
    addSpanishName(out, name);
  }
}

/** Titles that name a thing rather than a person, however they are cased. */
const TITLED_THINGS = new Set(["Dr Pepper", "Mr Bean", "Mr Robot", "Mr Men", "Dr Who", "Doctor Who", "Mr Potato", "Mrs Doubtfire", "Mr Blobby"]);

export function namesFromCues(text: string): string[] {
  const out: string[] = [];

  for (const match of text.matchAll(NAME_TITLE_PATTERN)) {
    const parts = match[1].split(/\s+/);
    // The title, then the name. Trim a common word from the right as below.
    while (parts.length > 1 && COMMON_CAPITALISED.has(parts[parts.length - 1])) parts.pop();
    if (parts.length < 2) continue;
    const name = parts.join(" ");
    const bare = parts.slice(1).join(" ");
    if (TITLED_THINGS.has(name.replace(".", ""))) continue;
    if (COMMON_CAPITALISED.has(parts[1])) continue;
    if (isAcronym(bare) || isSentenceFragment(bare) || isTechnicalTerm(bare)) continue;
    if (!isSubstitutable(name)) continue;
    if (!out.includes(name)) out.push(name);
  }

  // Initials are not checked as acronyms or words: "D.R." is both, and here
  // it is a man.
  for (const match of text.matchAll(NAME_TITLE_INITIALS_PATTERN)) {
    let name = match[1];
    // "Mr D.R. The court…": the next sentence, not a surname.
    const surname = name.match(/[\p{Lu}][\p{L}'’-]{1,20}$/u)?.[0];
    if (surname && (COMMON_CAPITALISED.has(surname) || isTechnicalTerm(surname))) name = name.slice(0, -surname.length).trimEnd();
    if (!out.includes(name)) out.push(name);
  }

  for (const match of text.matchAll(NAME_CUE_PATTERN)) {
    const parts = match[1].split(/\s+/);
    // Trim from the right: "My name is Marta and Tom is my brother" stops at
    // the lowercase "and" already, but "My name is Marta Tuesday" should not
    // carry the day of the week into the alias.
    while (parts.length > 0 && COMMON_CAPITALISED.has(parts[parts.length - 1])) parts.pop();
    if (parts.length === 0) continue;

    const name = parts.join(" ");
    // The same three filters the model's own answers go through. A cue is a
    // reason to look harder, not a licence to skip the checks.
    if (name.length < 2) continue;
    if (COMMON_CAPITALISED.has(parts[0])) continue;
    if (isAcronym(name)) continue;
    if (isSentenceFragment(name)) continue;
    if (isTechnicalTerm(name)) continue;
    if (!isSubstitutable(name)) continue;
    if (!out.includes(name)) out.push(name);
  }

  spanishNamesFromCues(text, out);
  europeanNamesFromCues(text, out);
  koreanNamesFromCues(text, out);
  chineseNamesFromCues(text, out);
  titledEastAsianNames(text, out);
  moreScriptsNamesFromCues(text, out);
  scriptGivenNames(text, out);
  lowerCaseGreetingNames(text, out);
  chatLogSpeakers(text, out);
  lowerCaseFullNames(text, out);

  nameColumns(text, out);
  eastAsianKinNames(text, out);
  namesTheTaggersCannotSee(text, out);
  moreCuedNames(text, out);
  return out;
}

/**
 * Names written where the taggers, which read capitals, cannot see them
 * (realistic5 misses, 2026-10-25):
 *   in a log's field:   customer="Lakatos Judit", user 'Megan O'Rourke'
 *   in capitals:        "OMG BRANDON STILL NOT ANSWERING", "NAMA: MOHD NAZRI
 *                       BIN ISMAIL", "NOM:MONTSERRAT FERRER I VIDAL"
 *   in lower case after a title, a relative or a sign-off: "frau dietz",
 *                       "sr quintana", "pak hendra", "mi hija alba", "lg sabine"
 * A word in capitals or lower case is taken only where it is a given name or
 * a family name, or a title stands in front of it; the words a title is
 * followed by that are no name ("pak rt", "frau doktor") are left.
 */
const LOG_NAME_FIELD = /(?<![\p{L}])(?:customer|user(?:name)?|name|full_?name|guest|owner|patient|employee|client|recipient|sender|cliente|kunde|nome|nombre|nom)\s*[=:]?\s*(["'])(\p{Lu}[\p{L}'’.-]*(?:[ ]\p{Lu}[\p{L}'’.-]*){1,3})\1(?![\p{L}])/gu;
// The field alone, not the end of another's name: "Account Name: CNC TRAVEL", "Resource Name : EOL US".
const CAPS_FORM_NAME = /(?<!\p{L}[ \t]*)(?:NAMA(?:\s+PEMEGANG\s+AKAUN)?|Nama(?:\s+Pemegang\s+Akaun)?|NAME|Name|NOM|Nom|NOMBRE|Nombre|APELLIDOS|Apellidos|NOME|Nome|NAAM|Naam|NAMN|NAVN|NIMI|ИМЯ|ФИО|ΟΝΟΜΑ)\s*[:：]\s*((?:[\p{Lu}][\p{Lu}'’.-]+|BIN|BINTI|A\/[LP])(?:[ ](?![\p{Lu}]+(?:[ ][\p{Lu}]+)?[ ]?[:：])(?:[\p{Lu}][\p{Lu}'’.-]+|I|Y|E|DE|DA|DI|BIN|BINTI|A\/[LP])){0,5})(?![\p{Ll}])/gu;
// Not the titles that are also a word of another language: Spanish "mas"
// (more), Turkish "bu" (this), Dutch and Swedish "om", English "bang".
const LOWER_TITLE = /(?<![\p{L}])(?:pan|pani|frau|herr|sr|sra|srta|se[ñn]or|se[ñn]ora|profe|prof|profa|mme|mlle|madame|monsieur|mr|mrs|ms|dr|pak|kak|mbak|tante|nonna|nonno|zio|zia|t[íi]a|t[íi]o)\.?\s+([a-zà-ÿąćęłńóśźżčďěňřšťůž][a-zà-ÿąćęłńóśźżčďěňřšťůž'’-]{2,15})(?![\p{L}])/gu;
const NOT_AFTER_A_TITLE = new Set(["president", "presidente", "doktor", "doctor", "dr", "guru", "rt", "rw", "direktor", "director", "manager", "teacher", "profesor", "professor", "kepala", "lurah", "camat", "haji", "hj", "dan", "yang", "dari", "und", "der", "die", "das", "von", "and", "the", "smith", "may", "will", "can"]);
const LOWER_KIN = /(?<![\p{L}])(?:mi\s+hij[oa]|mi\s+ni[ñn][oa]|mon\s+fils|ma\s+fille|mia\s+figlia|mio\s+figlio|meu\s+filho|minha\s+filha|mein\s+sohn|meine\s+tochter|my\s+son|my\s+daughter|min\s+s[øo]n|min\s+datter|min\s+dotter|mijn\s+zoon|mijn\s+dochter|adek\s+gw|adik\s+saya|anak\s+saya)\s+([a-zà-ÿ][a-zà-ÿ'’-]{2,15})(?![\p{L}])/gu;
const LOWER_SIGN_OFF = /(?<![\p{L}])(?:lg|vg|mfg|xoxo|cheers|thx|saludos|besos|bisous|baci|abra[çc]os|groetjes|hilsen|terveisin|pozdrawiam)[,!.]?\s+([a-zà-ÿ][a-zà-ÿ'’-]{2,15})\s*$/gmu;

// A company or a place in a name field: "CNC TRAVEL AND TOUR LIMITED".
const CAPS_NOT_A_PERSON = /\b(?:LIMITED|LTD|INC|LLC|CORP|GMBH|SDN|BHD|PLC|COMPANY|HOTEL|BANK|TRAVEL|AND|UNIVERSITY|SCHOOL|CENTER|CENTRE|PHONE|NUMBER|EMAIL|ADDRESS)\b/;
// Words in capitals that are also given names: months, places, words.
const CAPS_WORDS = new Set(["WILL", "JUNE", "APRIL", "AUGUST", "MARK", "BILL", "CASE", "RIVER", "WORTH", "HOPE", "GRACE", "FAITH", "ROSE", "DAWN", "SUMMER", "CHASE", "HUNTER", "PARIS", "INDIA", "YORK", "JORDAN", "GEORGIA", "VICTORIA", "FLORENCE", "DIJON", "LONDON", "SYDNEY", "AUSTIN", "DALLAS", "HOUSTON", "CHINA", "JAPAN", "KOREA", "ALLEY", "CHRISTIAN", "ANGEL", "MAXIMO", "MÁXIMO", "BELLA", "ALTA", "ARGENTINA", "CHANCE", "DENVER", "SIERRA", "WINTER", "AUTUMN", "SPRING",
  "JANUARY", "FEBRUARY", "MARCH", "JULY", "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER", "PHONE"]);

function namesTheTaggersCannotSee(text: string, out: string[]): void {
  const add = (name: string) => { if (name.length >= 2 && isSubstitutable(name) && !out.includes(name)) out.push(name); };
  for (const m of text.matchAll(LOG_NAME_FIELD)) {
    // A given name first, or a family name first and a given name after it
    // (Hungarian's order): "Lakatos Judit", not "Guiana Amazonian Park".
    const words = m[2].split(" ");
    const given = (w: string) => isGivenNameAnywhere(w) && !isCommonLowercaseWord(w.toLowerCase());
    if (given(words[0]) || (SURNAMES.has(words[0].toLowerCase()) && given(words[words.length - 1]))) add(m[2]);
  }
  for (const m of text.matchAll(CAPS_FORM_NAME)) {
    const value = m[1].trim();
    if (value.replace(/[^\p{L}]/gu, "").length < 4 || CAPS_NOT_A_PERSON.test(value)) continue;
    add(value);
  }
  // A short message in capitals: its given names, and the family name after
  // one. Not a long document in capitals (Enron's), where the words that are
  // also names (WILL, MAY, CASE) are words.
  const cased = text.match(/\p{L}/gu)?.filter((c) => c.toLowerCase() !== c.toUpperCase()) ?? [];
  const upper = cased.filter((c) => c === c.toUpperCase()).length;
  if (cased.length >= 15 && text.length <= 300 && upper / cased.length > 0.8) {
    // Word by word, the next only looked at: "OMG BRANDON" must not use up BRANDON.
    for (const m of text.matchAll(/(?<![\p{L}])(\p{Lu}{3,15})(?![\p{L}])(?=(?:[ ](\p{Lu}{3,15})(?![\p{L}]))?)/gu)) {
      const [first, second] = [m[1], m[2]];
      // Not a saint's place: "SAN MIGUEL DE LOS JUNOS".
      if (/(?:SAN|SANTA|SANTO|SAINT|ST\.?|SÃO)[ ]$/.test(text.slice(Math.max(0, (m.index ?? 0) - 7), m.index))) continue;
      if (first.length < 4 || CAPS_WORDS.has(first) || !isGivenNameAnywhere(first) || isCommonLowercaseWord(first.toLowerCase()) || isForeignCommonWords(first)) continue;
      // Not again inside a name already found: "TOBIAS" of "TOBIAS WREN".
      if (out.some((n) => n.split(/\s+/).includes(first))) continue;
      // Nor on a line that names a company: "RESPONDENT: HALE & DUNN LTD".
      const at = m.index ?? 0;
      const line = text.slice(text.lastIndexOf("\n", at) + 1, (text.indexOf("\n", at) + 1 || text.length + 1) - 1);
      if (/\b(?:LIMITED|LTD|INC|LLC|CORP|GMBH|SDN|BHD|PLC|COMPANY)\b|&/.test(line)) continue;
      add(second && SURNAMES.has(second.toLowerCase()) ? `${first} ${second}` : first);
    }
  }
  for (const m of text.matchAll(LOWER_TITLE)) {
    const w = m[1];
    if (NOT_AFTER_A_TITLE.has(w) || isCommonLowercaseWord(w) || isForeignCommonWords(w)) continue;
    if (isGivenNameAnywhere(w) || SURNAMES.has(w) || TYPED_LOWER.has(w)) add(w);
  }
  for (const m of text.matchAll(LOWER_KIN)) if (isGivenNameAnywhere(m[1]) && !isCommonLowercaseWord(m[1])) add(m[1]);
  for (const m of text.matchAll(LOWER_SIGN_OFF)) if (isGivenNameAnywhere(m[1]) && !isCommonLowercaseWord(m[1])) add(m[1]);
}

/**
 * A child or a relative named after the word for them, as East Asian
 * messages write it (realistic5 misses, 2026-10-24):
 *   Japanese  the relative, then the name with no particle between when it is
 *             in kanji ("息子蓮の予約"), or after の in hiragana ("娘のひなたが").
 *             Kanji after の is usually a thing (息子の学校), so not that.
 *   Chinese   儿子, 女儿 and the rest, then a doubled pet name ("女儿朵朵").
 *             Two characters after them are as often words (儿子很乖).
 *   Korean    the relative and a space ("딸 서아가"), and a one-syllable
 *             surname before a role and 님 ("박 선생님", "조 원장님").
 */
const JA_KIN = "息子|娘|祖母|祖父|孫|夫|妻|長男|長女|次男|次女";
const JA_KIN_KANJI = new RegExp(String.raw`(?:${JA_KIN})(\p{Script=Han}{1,2})(?=の|が|は|を|に|と|も|、|。|ちゃん|くん|君)`, "gu");
// Katakana is a child's name only before ちゃん, くん or さん ("娘のピアノ" is a
// piano), but a grandparent's in any case: トメ, キヨ.
const JA_KIN_KANA = new RegExp(String.raw`(?:${JA_KIN}|おばあちゃん|おじいちゃん)の(\p{Script=Hiragana}{2,5}|\p{Script=Katakana}{2,5}(?=ちゃん|くん|さん)|(?<=(?:祖母|祖父|おばあちゃん|おじいちゃん)の)\p{Script=Katakana}{2,4})(?=が|は|を|に|と|も|、|。|ちゃん|くん|さん)`, "gu");
const JA_NOT_A_NAME = new Set(["達", "たち", "母", "父", "妻", "夫", "母さん", "父さん", "夫婦", "婿", "嫁", "人", "子", "娘", "息子", "側", "さん", "様", "方", "学校", "家", "部屋"]);
const ZH_KIN = "儿子|女儿|兒子|女兒|老公|老婆|丈夫|妻子|孙子|孙女|孫子|孫女|外孙|外孫";
const ZH_KIN_DOUBLED = new RegExp(String.raw`(?:${ZH_KIN})((\p{Script=Han})\2)`, "gu");
const KO_KIN = new RegExp(String.raw`(?<![가-힣])(?:아들|딸|손자|손녀|아내|남편|조카)\s([가-힣]{2,3}?)(?:이가|이는|이를|이랑|이|가|는|은|를|을|와|과|랑|의|도|한테|에게)?(?=[\s,.!?]|$)`, "gu");
const KO_NOT_KIN_NAME = new Set([
  "아이", "녀석", "내외", "부부", "친구", "학교", "방", "생일", "결혼", "셋", "둘", "하나", "소득", "회사", "직장", "이름", "나이", "번호",
  "핸드폰", "휴대폰", "건강", "월급", "연봉", "명의", "계좌", "카드", "집", "사업", "보험", "연금", "수술", "병원", "성격", "취미",
  "선물", "공부", "성적", "숙제", "담임", "회사원", "직업", "세금", "통장", "차량", "얼굴", "사진", "대학", "유치원", "어린이집",
]);
// Built on first use: KO_SURNAME is declared further down.
let koSurnameRole: RegExp | null = null;

function eastAsianKinNames(text: string, out: string[]): void {
  const add = (name: string) => { if (isSubstitutable(name) && !out.includes(name)) out.push(name); };
  if (/[\p{Script=Hiragana}\p{Script=Katakana}]/u.test(text)) {
    for (const m of text.matchAll(JA_KIN_KANJI)) if (!JA_NOT_A_NAME.has(m[1])) add(m[1]);
    for (const m of text.matchAll(JA_KIN_KANA)) if (!JA_NOT_A_NAME.has(m[1])) add(m[1]);
  } else if (/\p{Script=Han}/u.test(text)) {
    for (const m of text.matchAll(ZH_KIN_DOUBLED)) add(m[1]);
  }
  if (/[가-힣]/.test(text)) {
    for (const m of text.matchAll(KO_KIN)) if (!KO_NOT_KIN_NAME.has(m[1]) && !KO_ROLES.has(m[1])) add(m[1]);
    koSurnameRole ??= new RegExp(String.raw`(?<![가-힣])(${KO_SURNAME})\s(?:선생|원장|교수|팀장|부장|과장|사장|대리|실장|의사|변호사)님`, "gu");
    for (const m of text.matchAll(koSurnameRole)) add(m[1]);
  }
}

/**
 * The names in a pasted table, under a header that says so in its own
 * language: "नाम,आधार,मोबाइल,शहर", "نام,شناختی کارڈ,موبائل,شہر",
 * "ime,oib,iznos", "meno;ico;suma", "pangalan,sss,cellphone". A tagger reads a
 * row of cells without a sentence round it, and in realistic5 missed most of
 * the names in them (2026-10-24).
 *
 * The header is a row of short cells with no digits, split by a comma,
 * semicolon, tab or bar; the rows under it split the same way into as many
 * cells. A cell under a name column is a name if it is one to four words of
 * letters. Given and family name columns are read one by one.
 */
const NAME_COLUMNS = new Set([
  "name", "names", "fullname", "full name", "customer name", "customer", "client", "employee", "employee name", "patient",
  "patient name", "first name", "firstname", "given name", "last name", "lastname", "surname", "family name",
  "nombre", "nombres", "nombre completo", "apellido", "apellidos", "nom", "prénom", "prenom", "nom complet", "nome", "cognome",
  "nome completo", "naam", "voornaam", "achternaam", "name des kunden", "vorname", "nachname", "navn", "fornavn", "etternavn",
  "efternavn", "namn", "förnamn", "efternamn", "nimi", "etunimi", "sukunimi", "név", "vezetéknév", "keresztnév", "imię",
  "nazwisko", "imię i nazwisko", "jméno", "příjmení", "meno", "priezvisko", "ime", "prezime", "ime i prezime", "nume", "prenume",
  "nume și prenume", "όνομα", "επώνυμο", "ονοματεπώνυμο", "имя", "фамилия", "фио", "ім'я", "ім’я", "прізвище", "піб", "ad",
  "soyad", "ad soyad", "adı soyadı", "isim", "pangalan", "buong pangalan", "nama", "nama lengkap", "tên", "họ tên", "họ và tên",
  "ชื่อ", "ชื่อ-นามสกุล", "นามสกุล", "नाम", "पूरा नाम", "নাম", "পূর্ণ নাম", "نام", "پورا نام", "الاسم", "اسم", "الاسم الكامل",
  "שם", "שם מלא", "שם פרטי", "שם משפחה", "பெயர்", "పేరు", "이름", "성명", "名前", "氏名", "姓名", "名字", "nom i cognoms",
]);
const CELL_NAME = /^[\p{L}\p{M}][\p{L}\p{M}'’.-]*(?: [\p{L}\p{M}][\p{L}\p{M}'’.-]*){0,3}$/u;

function nameColumns(text: string, out: string[]): void {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length - 1; i++) {
    const delimiter = [",", ";", "\t", "|"].find((d) => lines[i].includes(d));
    if (!delimiter) continue;
    const cellsOf = (line: string) => line.replace(/^\s*\|/, "").replace(/\|\s*$/, "").split(delimiter).map((c) => c.trim());
    const head = cellsOf(lines[i]);
    if (head.length < 2 || !head.every((c) => c.length > 0 && c.length <= 30 && !/\d/.test(c))) continue;
    // A header sits on its own line; a sentence before it may end in a colon:
    // "Turn this into a table: ime,oib,iznos".
    const columns = head.map((c, k) => (k === 0 ? c.replace(/^.*[:：]\s*/u, "") : c).toLowerCase().replace(/[_\s]+/g, " "));
    const at = columns.map((c, k) => (NAME_COLUMNS.has(c) ? k : -1)).filter((k) => k >= 0);
    if (!at.length) continue;
    for (let j = i + 1; j < lines.length; j++) {
      if (/^\s*\|?[\s:|-]+\|?\s*$/.test(lines[j])) continue; // a Markdown rule under the header
      const cells = cellsOf(lines[j]);
      // An amount may carry a decimal comma ("1.200,00"), one cell more.
      if (cells.length < head.length || cells.length > head.length + 2) break;
      for (const k of at) {
        const cell = cells[k];
        if (!CELL_NAME.test(cell) || !isSubstitutable(cell) || out.includes(cell)) continue;
        // Not a code name in capitals ("TWILIGHTVEGETABLE"), nor a word in
        // lower case under "name" in a key and value table ("age", "sodium
        // hydroxide"), unless it is a given name typed that way.
        if (!/\s/.test(cell) && /^\p{Lu}{2,}$/u.test(cell)) continue;
        if (/^\p{Ll}/u.test(cell) && !isGivenNameAnywhere(cell.split(" ")[0])) continue;
        // English "name" heads a product's or a setting's column as often as
        // a person's ("Ceiling Fan", "Budget Estimate"): there, a given name first.
        if ((columns[k] === "name" || columns[k] === "names") && !isGivenNameAnywhere(cell.split(" ")[0])) continue;
        out.push(cell);
      }
    }
  }
}

/**
 * The people talking in a pasted chat: "[10:42] أبو خالد: وين الملف",
 * "16/10/26 19:10 - Κατερίνα: …", "Kuba: masz numer do Bartka?", "たけし:
 * 明日の飲み会何時〜？". A tagger reads a line's first word without its
 * sentence, and in any script but a cased one has no capital to go by: 87 of
 * the names realistic5's two seeds missed were speakers (2026-10-24).
 *
 * A speaker opens a line with one to three words and a colon. The lines are
 * a chat only if there are two or more, with a time in front or a speaker
 * who speaks twice, so a form's "Nombre: Juan / Teléfono: …" is not one. A
 * key in lower case is left (YAML's "name: web"), and so are the words for
 * the people a chat is between: "Én", "Me", "Agent", "Customer", "CS".
 */
const CHAT_LINE = /^[ \t]*(\[?(?:오전|오후|午前|午後|上午|下午)?[ \t]?\d[\d./,: \t-]*\d\]?(?:[ \t]*[AaPp][Mm]\]?)?[ \t]*[-–,]?[ \t]*)?([\p{L}\p{M}][\p{L}\p{M}'’.-]*(?:[ \t][\p{L}\p{M}][\p{L}\p{M}'’.-]*){0,2}(?:_[\p{L}\d]{1,3})?)[ \t]*[:：](?![\/\d])[ \t]*\S/gmu;
const NOT_A_SPEAKER = new Set([
  "me", "you", "i", "user", "users", "assistant", "system", "bot", "chatbot", "ai", "gpt", "chatgpt", "claude", "agent", "customer",
  "client", "cliente", "kunde", "klant", "kund", "asiakas", "müşteri", "khách", "pembeli", "penjual", "pelanggan", "seller",
  "buyer", "staff", "support", "cs", "cskh", "admin", "moderator", "host", "guest", "operator", "agente", "atendente", "vendedor",
  "comprador", "yo", "ich", "moi", "io", "eu", "jag", "jeg", "minä", "én", "ja", "ik", "ben", "ako", "saya", "aku", "tôi", "em",
  "я", "аз", "ты", "вы", "пользователь", "ассистент", "бот", "клиент", "оператор", "менеджер", "εγώ", "أنا", "انا", "אני", "मैं", "আমি", "میں", "私", "わたし", "我", "나", "저",
  "from", "to", "cc", "bcc", "subject", "date", "sent", "re", "fwd", "fw", "von", "an", "betreff", "de", "para", "asunto", "objet",
  "à", "da", "oggetto", "note", "notes", "nb", "ps", "tip", "todo", "fixme", "error", "warning", "warn", "info", "debug", "fatal",
  "trace", "input", "output", "example", "result", "answer", "question", "q", "a", "step", "set-cookie", "cookie",
  // The parts of a script, and the people a chat names by role.
  "title", "episode", "scene", "character", "narrator", "announcer", "voiceover", "interviewer", "speaker", "caller", "chorus",
  "all", "both", "everyone", "owner", "boss", "attention", "usage", "current", "general", "price", "mother", "father", "mom",
  "mum", "dad", "teacher", "student", "doctor", "patient", "nurse", "officer", "police", "man", "woman", "boy", "girl", "kid",
  "mama", "mamá", "papa", "papá", "mamma", "mãe", "pai", "mutter", "vater", "mère", "père", "ibu", "ayah", "bapak", "nanay", "tatay",
  "mẹ", "bố", "ba", "baba", "мама", "папа", "мать", "отец",
  "வாடிக்கையாளர்", "முகவர்", "அம்மா", "அப்பா", "కస్టమర్", "ఏజెంట్", "అమ్మ", "నాన్న", "ลูกค้า", "แอดมิน", "แม่", "พ่อ", "ग्राहक",
  "एजेंट", "मम्मी", "पापा", "माँ", "গ্রাহক", "এজেন্ট", "মা", "বাবা", "گاہک", "ایجنٹ", "امی", "ابو", "عميل", "العميل",
  "الموظف", "موظف", "أمي", "ماما", "بابا", "לקוח", "נציג", "אמא", "אבא", "客", "お客様", "店員", "母", "父", "ママ", "パパ", "客户",
  "客服", "用户", "妈妈", "爸爸", "고객", "상담원", "엄마", "아빠",
]);

const SPEAKER_WORD = /^(?:\p{Lu}[\p{Ll}\p{M}]+(?:['’-]\p{L}[\p{Ll}\p{M}]*)*|[\p{Lo}\p{M}]+)$/u;

/* A chat pasted onto one line, its turns run together: "liam: footy at 6?
   chloe_w: gotta grab mason first liam: 6:30 then raj: bringing cones"
   (realistic5, 2026-10-25). Three turns or more on a line, a speaker among
   them speaking twice: each turn is put on a line of its own, and read as
   below. */
const RUN_ON_TURN = /(?<=\S)[ \t]+(?=[\p{L}][\p{L}\p{M}'’.-]*(?:_[\p{L}\d]{1,3})?:[ \t]+\S)/gu;
const TURN_SPEAKER = /(?:^|(?<=[ \t]))([\p{L}][\p{L}\p{M}'’.-]*(?:_[\p{L}\d]{1,3})?):(?=[ \t]+\S)/gu;

const CODE_CHARS = /[{};=<>]|\(\)/;
// Words before a colon that open a title, not a turn: "Captain America: The
// First Avenger", "Thor: Ragnarok".
const SPEAKER_NOT_ONCE = new Set(["America", "China", "Thor", "Captain", "Episode", "Chapter", "Part", "Act", "Scene", "Mario"]);

function unrunTurns(text: string): string {
  return text.split("\n").map((line) => {
    const speakers = [...line.matchAll(TURN_SPEAKER)].map((m) => m[1]);
    if (speakers.length < 3 || new Set(speakers).size === speakers.length || CODE_CHARS.test(line)) return line;
    return line.replace(RUN_ON_TURN, "\n");
  }).join("\n");
}

function chatLogSpeakers(original: string, out: string[]): void {
  const text = unrunTurns(original);
  if (!text.includes("\n")) return;
  const seen = new Map<string, number>();
  let lines = 0, timed = false, roleTurns = 0;
  for (const m of text.matchAll(CHAT_LINE)) {
    const speaker = m[2].replace(/[.’'-]+$/u, "");
    if (speaker.length < 2) continue;
    // "mama:", "amma:", "mẹ:" speak too, and make it a chat, though they are
    // not names (realistic5, 2026-10-27: "mama: Ucup udah makan? ucup: udah").
    if (NOT_A_SPEAKER.has(speaker.toLowerCase())) { roleTurns += 1; continue; }
    lines += 1;
    if (m[1]) timed = true;
    seen.set(speaker, (seen.get(speaker) ?? 0) + 1);
  }
  const familyChat = roleTurns >= 2 && seen.size >= 1 && !CODE_CHARS.test(text);
  if (!familyChat && (lines < 2 || (!timed && ![...seen.values()].some((n) => n >= 2)))) return;
  // Somebody speaks twice and somebody else is there too: the lines are
  // turns. One word opening one of them, capitalised or in a script without
  // case, is a speaker then though no list knows the name ("Verča: 731 245
  // 908" after Pepa's two turns, "ゆか:" between たけし's), and so is a
  // lower-case handle the chat writes with a capital elsewhere ("ucup:"
  // answering "mama: Ucup udah makan?"). realistic5, 2026-10-26.
  // The one who speaks twice has to be a person too, a given name or a word
  // of a script without case, or "Purpose:" and "Impact:" down a change
  // request would make a chat.
  const person = (s: string) => /^[\p{Lo}\p{M}]+$/u.test(s) || isGivenNameAnywhere(s.replace(/_[\p{L}\d]{1,3}$/u, "").split(/[ \t]+/)[0]);
  const aChat = familyChat || (seen.size >= 2 && [...seen].some(([s, n]) => n >= 2 && person(s)) && !CODE_CHARS.test(text));
  for (const [speaker, turns] of seen) {
    const one = speaker.replace(/_[\p{L}\d]{1,3}$/u, "");
    // A lower-case speaker the chat writes with a capital elsewhere, or that
    // a parent's turn addresses: "amma: kavi saapitiya kavi: ama".
    const addressed = familyChat && /^\p{Ll}[\p{L}\p{M}]+$/u.test(one) &&
      [...text.matchAll(new RegExp(String.raw`(?<![\p{L}])${one}(?![\p{L}])`, "giu"))].length >= 2;
    const capitalised = aChat && /^\p{Ll}[\p{L}\p{M}]+$/u.test(one) && (text.includes(one[0].toUpperCase() + one.slice(1)) || addressed);
    const once = aChat && turns === 1 && !/[ \t]/.test(one) && (SPEAKER_WORD.test(one) || capitalised);
    // A speaker speaks twice, or at a time: a heading is written once ("要求:").
    // A given name may speak once, in a chat where somebody speaks twice:
    // "raj: bringing cones", "Verča: 731 245 908".
    // Not in code, where "uri:" and "van:" are keys, nor a title's first word.
    if (turns < 2 && SPEAKER_NOT_ONCE.has(speaker)) continue;
    if (turns < 2 && !timed && !once && (CODE_CHARS.test(text) || !isGivenNameAnywhere(speaker.replace(/_[\p{L}\d]{1,3}$/u, "").split(/[ \t]+/)[0]))) continue;
    // Each word shaped like a name: a capital then small letters, or a word
    // of a script without case. Not a log's "INFO executor.Executor" or "D
    // PowerManagerService", nor a heading's "See also", "Purpose".
    // In lower case, a handle or a key, only a given name: "liam:",
    // "veera_k:", not YAML's "name:". Capitalised, a given name too unless
    // the lines carry times, since a heading is capitalised as well
    // ("Purpose:", "Impact:" down a change request). A script without case
    // has no headings to mistake.
    const bare = speaker.replace(/_[\p{L}\d]{1,3}$/u, "");
    const words = bare.split(/[ \t]+/);
    const given = isGivenNameAnywhere(words[0]);
    if (/^\p{Ll}/u.test(bare)) { if (words.length > 1 || (!given && !capitalised)) continue; }
    else if (!words.every((w) => SPEAKER_WORD.test(w))) continue;
    else if (/\p{Lu}/u.test(bare) && !timed && !given && !once) continue;
    if (words.some((w) => isCommonLowercaseWord(w.toLowerCase()) && !isGivenNameAnywhere(w))) continue;
    if (isAcronym(speaker) || COMMON_CAPITALISED.has(speaker) || isForeignCommonWords(speaker) || isNotAPerson(speaker)) continue;
    if (isSentenceFragment(speaker) || isTechnicalTerm(speaker) || !isSubstitutable(speaker)) continue;
    if (!out.includes(speaker)) out.push(speaker);
    const cap = one[0].toUpperCase() + one.slice(1);
    if (capitalised && !out.includes(cap)) out.push(cap);
  }
}

/**
 * A name typed in lower case after a greeting: "hey sam, kevin from accounts
 * said…", "hi priya, can you…". The taggers read capitals, so a name typed the
 * way people type in chat was missed (third realistic hold-out, 2026-10-24).
 *
 * Only the word between a greeting and a comma, and only a given name there:
 * the person being spoken to. The ordinary ways of addressing people ("hey
 * guys,", "hi all,", "thanks mate,") are left out, and so is any word on the
 * common-word list. One word, so "hi sam thanks," cannot take "thanks".
 */
const LOWER_GREETING_NAME = /(?<![\p{L}])(?:hey|hi|hello|hiya|dear|thanks|thank you|morning|evening)\s+([a-z][a-z'’-]{1,14})\s*[,!:]/gu;
const NOT_ADDRESSED_BY_NAME = new Set([
  "guys", "guy", "all", "there", "team", "everyone", "everybody", "folks", "man", "dude", "bro", "buddy", "mate", "babe", "baby",
  "honey", "love", "sweetie", "dear", "sir", "madam", "friend", "friends", "again", "you", "boss", "mom", "dad", "mum", "son",
  "girl", "girls", "boys", "ladies", "gentlemen", "chatgpt", "gpt", "bot", "assistant", "claude", "so", "much", "lot", "both",
]);

function lowerCaseGreetingNames(text: string, out: string[]): void {
  for (const m of text.matchAll(LOWER_GREETING_NAME)) {
    const word = m[1];
    if (NOT_ADDRESSED_BY_NAME.has(word) || isCommonLowercaseWord(word) || !isGivenNameAnywhere(word)) continue;
    if (isSubstitutable(word) && !out.includes(word)) out.push(word);
  }
}

/**
 * A full name typed in lower case: "my client john okafor", "ask priya
 * kowalczyk". Both seeds of round 7 missed one (realistic3, 2026-10-24).
 *
 * A given name and then a family name (redactionSurnames, from Wikidata),
 * neither an ordinary word in English or the other languages read here, and
 * the pair not a famous person ("elon musk"): two such words side by side are
 * a person far more often than a phrase. Not inside a path, an address or an
 * identifier: "src/john_smith", "john.smith@".
 */
// A place or a thing, though each word is also a surname: "river valley",
// "bell tower", "rose gold", "north east" (real chats and WildChat).
const NOT_A_FAMILY_NAME_HERE = new Set([
  "hall", "halls", "tower", "towers", "valley", "ridge", "hill", "hills", "east", "west", "north", "south", "gold", "silver",
  "diamond", "pine", "park", "street", "road", "lane", "avenue", "drive", "court", "square", "bridge", "lake", "river", "creek",
  "bay", "beach", "point", "springs", "field", "fields", "wood", "woods", "grove", "heights", "mount", "mountain", "island",
  "port", "harbor", "harbour", "castle", "palace", "church", "chapel", "house", "manor", "farm", "mill", "garden", "gardens",
  "center", "centre", "city", "town", "plaza", "carlo", "cape", "potter", "webb",
]);
const LOWER_PAIR = /(?<![\p{L}\p{N}'’@._/-])([a-z]{2,15})[ \t]+([a-z]{3,20})(?![\p{L}\p{N}'’@/-]|\.[a-z])/gu;

function lowerCaseFullNames(text: string, out: string[]): void {
  if (!/[a-z]{2,} [a-z]{3,}/.test(text)) return;
  const plain = (w: string) => !isCommonLowercaseWord(w) && !isForeignCommonWords(w) && !NOT_ADDRESSED_BY_NAME.has(w);
  const capital = (w: string) => w.charAt(0).toUpperCase() + w.slice(1);
  for (let m = LOWER_PAIR.exec(text); m; m = LOWER_PAIR.exec(text)) {
    const [, first, last] = m;
    // Overlapping pairs: "said john okafor" tries "said john", then "john okafor".
    LOWER_PAIR.lastIndex = (m.index ?? 0) + first.length + 1;
    if (!isGivenNameAnywhere(first) || !plain(first) || TYPED_LOWER.has(first)) continue;
    if (NOT_A_FAMILY_NAME_HERE.has(first) || NOT_A_FAMILY_NAME_HERE.has(last)) continue;
    if (!SURNAMES.has(last) || !plain(last) || COMMON_CAPITALISED.has(capital(last)) || isNotAPerson(capital(last))) continue;
    const name = `${first} ${last}`;
    if (isFamousPersonHere(`${capital(first)} ${capital(last)}`, text)) continue;
    if (isSubstitutable(name) && !out.includes(name)) out.push(name);
  }
  LOWER_PAIR.lastIndex = 0;
  // And a given name by the team it is from: "kevin from accounts said",
  // "ask sarah from hr" (realistic3).
  for (const m of text.matchAll(LOWER_FROM_TEAM)) {
    const word = m[1];
    if (!isGivenNameAnywhere(word) || !plain(word) || TYPED_LOWER.has(word)) continue;
    if (isSubstitutable(word) && !out.includes(word)) out.push(word);
  }
}
const LOWER_FROM_TEAM = /(?<![\p{L}\p{N}'’@._/-])([a-z]{2,15}) from (?:the )?(?:accounts|accounting|finance|hr|human resources|it|legal|sales|marketing|support|ops|operations|payroll|admin|procurement|compliance|engineering|design|product|security|facilities|reception|the office|head office)(?![\p{L}])/gu;

/**
 * Thai, Hebrew and Vietnamese names by the words that introduce them (third
 * realistic hold-out, 2026-10-24, where the taggers missed each):
 *   Thai        คุณ after a letter's greeting: "เรียนคุณสมชาย". Not คุณ alone,
 *               which also opens ordinary words (คุณภาพ, quality).
 *   Hebrew      a greeting: "היי דנה". "שלום רב" is not one. Apart from the
 *               name: the greeting glued on was the start of a word, "היום"
 *               read as "הי ום", "הישיבה" as "הי שיבה" (realistic5, 2026-11-08).
 *   Vietnamese  a title or a party: "ông Lê Minh Tuấn", "nguyên đơn Phạm Thu
 *               Hà" (the plaintiff), with two to four capitalised words.
 */
const TH_GREETING_NAME = /(?:เรียน|ถึง|สวัสดี(?:ครับ|ค่ะ)?)\s*คุณ\s?([ก-ฮะ-๎]{2,20})/gu;
const HE_GREETING_NAME = /(?<![֐-׿])(?:היי|הי|שלום|לכבוד|בוקר טוב|ערב טוב)(?:\s*,\s*|\s+)([א-ת][א-ת'"׳״]{1,11})(?=[\s,.!?:]|$)/gu;
const HE_NOT_A_NAME = new Set(["רב", "לכולם", "לכם", "וברכה", "עליכם", "חברים", "צוות", "שוב", "לך", "לכן", "גם", "מה", "רבה"]);
const VI_TITLE_NAME = /(?<![\p{L}])(?:[Nn]guyên đơn|[Bb]ị đơn|[Ôô]ng|[Bb]à|[Cc]hị|[Ll]uật sư)\s+(\p{Lu}[\p{Ll}̀-ͯ]*(?:\s+\p{Lu}[\p{Ll}̀-ͯ]*){1,3})(?![\p{L}])/gu;

function moreScriptsNamesFromCues(text: string, out: string[]): void {
  const add = (name: string) => { if (name.length >= 2 && isSubstitutable(name) && !out.includes(name)) out.push(name); };
  if (/[฀-๿]/.test(text)) for (const m of text.matchAll(TH_GREETING_NAME)) add(m[1]);
  if (/[֐-׿]/.test(text)) for (const m of text.matchAll(HE_GREETING_NAME)) if (!HE_NOT_A_NAME.has(m[1])) add(m[1]);
  if (/[ăâđêôơưĂÂĐÊÔƠƯ]/.test(text)) for (const m of text.matchAll(VI_TITLE_NAME)) add(m[1]);
  if (/[֐-׿]/.test(text)) for (const m of text.matchAll(HE_KIN_OR_ROLE_NAME)) if (!HE_NOT_A_NAME.has(m[1]) && !HE_NOT_AFTER_KIN.has(m[1])) add(m[1]);
  if (/[؀-ۿ]/.test(text)) {
    for (const m of text.matchAll(AR_UR_MY_NAME)) add(m[1]);
    for (const m of text.matchAll(AR_I_AM_NAME)) add(m[1]);
  }
  if (/[ऀ-ॿঀ-৿]/.test(text)) {
    for (const m of text.matchAll(HI_BN_MY_NAME)) add(m[1]);
    for (const m of text.matchAll(HI_BN_KIN_AFTER)) if (!SOUTH_ASIAN_NOT_A_NAME.has(m[1])) add(m[1]);
  }
  for (const m of text.matchAll(ROMAN_SOUTH_ASIAN_TITLE)) if (isGivenNameAnywhere(m[1])) add(m[1]);
}

/**
 * A given name in a script with no capitals, wherever it stands: "عيد ميلاد
 * جود", "আজ পিয়ালীর জন্মদিন", "לשלוח לתמר" (realistic5 misses, 2026-10-27).
 * The taggers find names by their capitals and miss most of these; the list
 * is redactionScriptGivenNames.ts, which holds no word that is also an
 * ordinary word there. Glued to a preposition or a case ending, as Arabic,
 * Hebrew, Bengali and the Dravidian languages write them: the name alone is
 * hidden ("لبسمة", "לתמר", "পিয়ালীর", "శిరీషకి").
 */
const SCRIPT_WORD = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Gujarati}\p{Script=Gurmukhi}‌‍]+/gu;
// "and" and "to" only: ب and מ open as many words as they glue on (بدون, بنات).
const SCRIPT_PREFIX = /^(?:[وفل]|ול|[ול])(?=\p{L}{3})/u;
const SCRIPT_NOT_A_PERSON_BEFORE = /(?:الملك|الأمير|الامير|السلطان|الإمام|الامام|علامہ|قائد اعظم|حضرت|זכרון|רמת)\s+$/u;
const SCRIPT_SUFFIX = /(?:এর|ের|কে|র|ও|க்கு|வுக்கு|யுடன்|உடன்|ை|కి|కు|తో|ను|ని|ది)$/u;

function scriptGivenNames(text: string, out: string[]): void {
  if (!/[֐-ۿݐ-ݿऀ-ൿ]/.test(text)) return;
  const add = (name: string) => { if (isSubstitutable(name) && !out.includes(name)) out.push(name); };
  for (const m of text.matchAll(SCRIPT_WORD)) {
    const word = m[0];
    if (word.length < 3) continue;
    // Not a king's or a poet's name, nor a town's: "الملك فيصل", "علامہ
    // اقبال", "فیصل آباد".
    const at = m.index ?? 0;
    if (SCRIPT_NOT_A_PERSON_BEFORE.test(text.slice(Math.max(0, at - 12), at)) || /^\s*آباد/u.test(text.slice(at + word.length))) continue;
    const name = SCRIPT_GIVEN_NAMES.has(word) ? word
      : [word.replace(SCRIPT_PREFIX, ""), word.replace(SCRIPT_SUFFIX, "")].find((w) => w !== word && w.length >= 3 && SCRIPT_GIVEN_NAMES.has(w));
    // Not somebody famous, met by another word of their name: "جمال عبد
    // الناصر", "सचिन तेंदुलकर".
    if (name && !isFamousPersonHere(name, text)) add(name);
  }
}

/**
 * More of the same, from realistic5's misses (2026-10-24):
 *   Hebrew   a relative or a role before the name: "הבת שלי אגם", "לבתי
 *            שולמית", "לגננת אסנת", "לבעל הבית שמוליק". One word.
 *   Arabic,  "my name is": "اسمي …", "میرا نام رابعہ ہے"; and "انا رنا من …"
 *   Urdu     (I am X from), only before من or و.
 *   Hindi,   "my name is" (मेरा नाम अनुराधा है, আমার নাম সোহেল), and a
 *   Bengali  relative's title after the name: "सरला मौसी", "নিখিল কাকু".
 *   Roman    a given name before garu, ji, sir or madam: "srinivas garu",
 *            "dinesh sir", "PRAVALLIKA MADAM".
 */
const HE_KIN_OR_ROLE_NAME = /(?<![֐-׿])(?:הבן שלי|הבת שלי|הנכד שלי|הנכדה שלי|לבתי|לבני|לנכדי|לנכדתי|אשתי|בעלי|אחותי|לגננת|הגננת|לשכן|השכן|לשכנה|השכנה|לבעל הבית|בעל הבית|המשכירה|המשכיר|לשוכר|השוכר|השוכרת|המורה|למורה)\s+([א-ת][א-ת'׳]{1,11})(?=[\s,.!?:]|$)/gu;
const HE_NOT_AFTER_KIN = new Set(["שלי", "שלו", "שלה", "שלנו", "הקטן", "הקטנה", "הגדול", "הגדולה", "היקר", "היקרה", "צריך", "צריכה", "רוצה", "אמר", "אמרה", "חולה", "לא", "גם", "עם", "של", "את", "הוא", "היא", "כבר", "עוד", "היה", "הייתה"]);
const AR_UR_MY_NAME = /(?:اسمي|إسمي|میرا نام|میرا\s+نام)\s+([؀-ۿ]{2,}(?:\s[؀-ۿ]{2,})?)\s+(?:ہے|ہیں|و|من|،)/gu;
const AR_I_AM_NAME = /(?<![؀-ۿ])(?:انا|أنا)\s+([؀-ۿ]{2,})\s+(?:من|و)(?![؀-ۿ])/gu;
const HI_BN_MY_NAME = /(?:मेरा नाम|मेरी नाम|আমার নাম)\s+([ऀ-ॿঀ-৿]{2,}(?:\s(?!(?:है|हैं|এবং|আর|और)(?![ऀ-ॿঀ-৿]))[ऀ-ॿঀ-৿]{2,})?)(?=[\s,.!?।]|$)/gu;
const HI_BN_KIN_AFTER = /(?<![ऀ-ॿঀ-৿])([ऀ-ॿঀ-৿]{2,})\s+(?:मौसी|चाची|चाचा|मामा|मामी|बुआ|भैया|दीदी|ताऊ|ताई|কাকু|কাকা|কাকিমা|মাসি|মাসিমা|দিদি|দাদা|খালা|মামা|মামি)(?![ऀ-ॿঀ-৿])/gu;
const SOUTH_ASIAN_NOT_A_NAME = new Set(["मेरी", "मेरा", "मेरे", "उनकी", "उसकी", "हमारी", "हमारे", "आपकी", "आपके", "तुम्हारी", "की", "के", "का", "और", "আমার", "ওর", "তার", "আমাদের", "তোমার", "আপনার", "এবং", "আর"]);
const ROMAN_SOUTH_ASIAN_TITLE = /(?<![\p{L}])([A-Za-z]{3,15})\s+(?:garu|ji|sir|madam|mam|ma'am)(?![\p{L}])/giu;

/**
 * Korean marks a person by what follows the name, not by its shape: 님 and
 * 씨 ("향숙님께", "민준 씨가"), and by the labels of a form ("성명: 김하린",
 * "이름(박도윤)"). Neither tagger reads them: the enclave pair caught 41.5% of
 * Korean names (namesEastAsia, practice, 2026-10-24).
 *
 * 님 also follows a role, which is nobody: 고객님, 선생님, 팀장님, 회원님. Those
 * words, and the role a name is followed by ("박서준 팀장님" keeps 박서준),
 * are left out. Two to four syllables a word, one to three words.
 */
const KO_ROLES = new Set([
  "고객", "회원", "선생", "사장", "팀장", "부장", "과장", "차장", "대리", "실장", "원장", "이사", "대표", "교수", "의사",
  "간호사", "기사", "손님", "여러분", "형", "누나", "언니", "오빠", "어머", "아버", "어머니", "아버지", "할머니", "할아버지",
  "부모", "담당자", "관리자", "작가", "감독", "목사", "신부", "스님", "교장", "교감", "총장", "회장", "국장", "본부장",
  "센터장", "매니저", "주인", "친구", "동생", "귀하", "환자", "보호자", "학부모", "주임", "반장", "조장", "점장", "소장",
  "위원", "위원장", "의원", "장관", "총리", "대통령", "판사", "검사", "변호사", "선배", "후배", "사모", "따님", "아드님",
  "형님", "누님", "가족", "직원", "사원", "연구원", "책임", "수석", "선임", "기자", "작가님", "모두", "여러분들",
  // Words that end in 씨 or 님 and are not names: 아저씨, 아가씨, 하나님.
  "아저", "아가", "하나", "임금", "왕자", "공주", "도련", "서방", "부처",
]);
const KO_NAME = String.raw`[가-힣]{2,4}(?:\s[가-힣]{1,4}){0,2}`;
// One word before 님 or 씨, or a common one-syllable surname and one word
// ("홍 길동"): a name is rarely more, and more would take in the words in front
// of it ("오늘 회의는 민준 씨가").
const KO_SURNAME = "김|이|박|최|정|강|조|윤|장|임|한|오|서|신|권|황|안|송|류|전|홍|고|문|양|손|배|백|허|유|남|심|노|하|곽|성|차|주|우|구|민|진|나|지|엄|채|원|천|방|공|현|함|변|염|여|추|도|소|석|선|설|마|길|연|위|표|명|기|반|왕|금|옥|육|인|맹|제|모|탁|국|어|은|편|용";
const KO_HONORIFIC = new RegExp(String.raw`(?<![가-힣])((?:(?:${KO_SURNAME})\s)?[가-힣]{2,4})\s?(?:님|씨)(?=[께은는이가을를의도과와,.!?\s)]|$)`, "gu");
const KO_LABEL = new RegExp(String.raw`(?:성명|이름|성함|수신인|수신자|발신인|신청인|담당자명|보호자명)\s*[:：(]\s*(${KO_NAME})(?=\s*[),\n/]|\s+(?:생년월일|연락처|전화|주소|이메일|님|씨)|$)`, "gu");

function koreanNamesFromCues(text: string, out: string[]): void {
  if (!/[가-힣]/.test(text)) return;
  const add = (raw: string) => {
    // A word ending in 님 or 씨 is a role or a greeting, never part of a name:
    // "성명: 선생님 물빛 박".
    const words = raw.split(/\s+/).filter((w) => !/(?:님|씨)$/.test(w));
    // "박서준 팀장님": the role after the name is not part of it.
    while (words.length && KO_ROLES.has(words[words.length - 1])) words.pop();
    if (!words.length || words.some((w) => KO_ROLES.has(w))) return;
    const name = words.join(" ");
    if (name.replace(/\s/g, "").length < 2 || !isSubstitutable(name)) return;
    if (!out.includes(name)) out.push(name);
  };
  for (const m of text.matchAll(KO_HONORIFIC)) add(m[1]);
  for (const m of text.matchAll(KO_LABEL)) add(m[1]);
  // 군 after a boy's name, written apart: "민수 군 어머님께" (realistic2). Also
  // an army, after a country or a side: 한국 군, 정부 군.
  // Nor a word and its particle: "본 정책은 군…", "우리 기업은 군…".
  for (const m of text.matchAll(KO_GUN)) if (!KO_ARMY_OF.has(m[1]) && !(m[1].length === 3 && /[은는이가을를의에도]$/u.test(m[1]))) add(m[1]);
}
const KO_GUN = /(?<![가-힣])([가-힣]{2,3})\s군(?=[께은는이가을를의도과와에,.!?\s)]|$)/gu;
const KO_ARMY_OF = new Set([
  "한국", "북한", "남한", "미국", "중국", "일본", "러시아", "영국", "프랑스", "독일", "이스라엘", "이란", "우크라", "정부", "반란",
  "연합", "동맹", "우리", "적국", "아군", "국방", "육군", "해군", "공군", "점령", "외국", "다국적", "평화", "유엔",
  // And words that are no name before it: "기타 군" (other).
  "기타", "해당", "일부", "전체", "관련", "소속", "각종", "모든",
]);

/**
 * Chinese names a person by surname and role: 李老师, 王经理, 陈先生, 赵总, and
 * among friends 小周, 老田. Neither tagger reads a one-character surname, and
 * both seeds of round 7 missed 李老师 (realistic2).
 *
 * The surname comes back alone, or with the given name when one stands
 * between it and the title after a word break ("请问张伟老师"). The swap takes
 * a one-character surname only before a title (ZH_TITLE in redactionMap).
 *
 * Many surnames are ordinary characters too, and Chinese writes no spaces, so
 * a title can follow the end of an ordinary word: 感谢老师 (thank the
 * teacher), 上周老师 (last week the teacher), 也许老师 (perhaps the teacher),
 * 对方律师 (opposing counsel), 老顾客 (a regular customer). Surnames that are
 * mostly words (文 史 方 时 国 白 …) are left out, and the words that end in
 * a surname's character are checked by name (ZH_WORD_BEFORE).
 */
const ZH_SURNAMES = new Set([..."王李张刘陈杨黄赵吴周徐孙马朱胡郭何林罗高郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘蒋蔡杜叶程魏苏吕丁沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付傅邹孟熊秦邱江尹薛闫段雷侯龙陶黎贺顾毛郝龚邵万钱严覃戴莫孔汤常温樊葛邢齐乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿焦俞左柳甘祝包宁尚符舒阮柯纪梅凌毕季裴霍涂成苗谷盛曲翁冉骆蓝路辛靳柴蒙鲍喻祁蒲滕屈饶牟艾尤阳穆农卓古吉缪简项连麦褚娄窦戚岑景党宫费卜冷晏卫米柏宗瞿桂佟臧闵苟邬卞姬仇栾隋刁荣巫寇桑郎甄丛仲虞敖巩池迟邝封谈匡鞠惠荆冀郁胥储栗燕楚鄢劳谌奚皮粟冼蔺盘满闻厉伊仝郜阚权帅屠豆朴盖练廉禹井祖漆巴丰支卿狄索宣晋芮普阙浦戈伏薄邸雍辜乌裘亓邰赫杭况宿鲜印逯隆茹诸战慕危玉银亢嵇湛宾戎勾茅揭冶束檀衣阴昝幸奉植衡尧陳黃趙吳劉張楊鄭謝許韓馮鄧蕭葉蘇呂盧鍾譚陸範賈鄒錢龔顏聶魯歐蘭閻嚴羅孫馬韋賀顧萬蔣龍"]);
const ZH_DOUBLE_SURNAME = "欧阳|歐陽|司马|司馬|诸葛|諸葛|上官|皇甫|令狐|慕容|公孙|公孫|夏侯|宇文|尉迟|尉遲|长孙|長孫|端木|南宫|南宮";
const ZH_WORD_BEFORE = new Set([
  "感谢", "感謝", "多谢", "多謝", "致谢", "答谢", "道谢", "鸣谢", "代谢", "上周", "下周", "本周", "每周", "这周", "這周", "那周", "一周",
  "两周", "几周", "半周", "也许", "或许", "允许", "期许", "赞许", "些许", "少许", "如何", "任何", "为何", "為何", "几何", "奈何",
  "一张", "两张", "几张", "紧张", "主张", "夸张", "开张", "扩张", "提高", "最高", "身高", "很高", "太高", "更高", "升高", "较高",
  "增高", "崇高", "调高", "罗马", "骑马", "斑马", "河马", "木马", "编程", "课程", "工程", "流程", "过程", "规程", "进程", "日程",
  "行程", "疗程", "章程", "航程", "里程", "全程", "教程", "押金", "资金", "奖金", "现金", "基金", "薪金", "租金", "定金", "美金",
  "佣金", "罚金", "税金", "礼金", "黄金", "学费", "免费", "收费", "缴费", "交费", "话费", "运费", "消费", "浪费", "花费", "经费",
  "照顾", "回顾", "光顾", "兼顾", "不顾", "祝贺", "庆贺", "道贺", "恭贺", "经常", "非常", "正常", "日常", "平常", "异常", "反常",
  "通常", "寻常", "家常", "完成", "组成", "形成", "造成", "达成", "变成", "促成", "赞成", "当成", "养成", "合成", "生成", "构成",
  "一万", "几万", "千万", "十万", "百万", "两万", "有钱", "付钱", "交钱", "花钱", "借钱", "赚钱", "挣钱", "还钱", "没钱", "价钱",
  "零钱", "支付", "应付", "对付", "交付", "树林", "森林", "园林", "竹林", "少林", "茶叶", "树叶", "落叶", "中叶", "时钟", "闹钟",
  "分钟", "点钟", "钟点", "警钟", "阶段", "手段", "片段", "地段", "大陆", "登陆", "着陆", "内陆", "示范", "规范", "模范", "防范",
  "师范", "典范", "不满", "充满", "圆满", "美满", "饱满", "新闻", "新郎", "辛劳", "功劳", "疲劳", "酬劳", "清楚", "痛楚", "苦楚",
  "会谈", "面谈", "访谈", "商谈", "交谈", "座谈", "接连", "相连", "一连", "亲戚", "教练", "训练", "熟练", "红包", "钱包", "书包",
  "面包", "打包", "承包", "文章", "规章", "印章", "奖章", "勋章", "道路", "马路", "铁路", "公路", "网路", "思路", "一路", "长江",
  "浙江", "珠江", "江苏", "恐龙", "长龙", "爱戴", "拥戴", "不曾", "未曾", "何曾", "油田", "农田", "稻田", "古董", "生姜", "包罗",
  "搜罗", "普罗", "子孙", "外孙", "儿孙", "荒唐", "园丁", "布丁", "零丁", "壮丁", "行李", "桥梁", "脊梁", "栋梁", "宝石", "钻石",
  "岩石", "化石", "结石", "实习", "毕业", "党委", "年级", "黑白", "复苏", "紫苏", "屠苏", "华夏", "初夏", "盛夏", "立夏", "早晚",
  "回应", "理解", "了解", "化解", "调解", "设施", "实施", "措施", "贸易", "容易", "交易", "健康", "安康", "荷兰", "儿童", "旅游",
  "导游", "厨房", "病房", "药房", "旁边", "身边", "这边", "那边", "电商", "厂商", "协商", "聪明", "说明", "证明", "检查", "调查",
  "审查", "排查", "邻居", "新居", "会展", "发展", "开展", "进展", "尊敬", "美容", "内容", "从容", "宽容", "首席", "主席", "出席",
  "公关", "有关", "相关", "海关", "机关", "对方", "双方", "甲方", "乙方", "我方", "校方", "院方", "警方", "官方", "当时", "同时",
  "平时", "有时", "及时", "按时", "那时", "这时", "外国", "中国", "美国", "英国", "各国", "全国", "回国", "出国", "主任", "担任",
  "前任", "现任", "新任", "兼任", "信任", "责任", "保安", "公安", "宿管", "主管",
]);
// 小 or 老 and a surname, a friend's name for a friend: 小周, 老田. Not where
// the pair is a word or the start of one: 小王子, 老顾客, 小程序, 养老金.
const ZH_PET_SURNAMES = new Set([..."王李张刘陈杨赵吴周徐孙朱胡郭何林罗高郑梁谢宋唐许韩冯邓曹彭曾田董袁潘蒋蔡杜程魏苏吕丁沈姚卢崔钟谭陆汪范金石廖贾夏韦傅邹孟秦邱江尹薛段雷侯陶黎贺顾郝龚邵万严戴莫温章鲁岳宁季"]);
const ZH_NOT_AFTER_PET = new Set([..."子末年期边围树地园湖库额点体达序天季日重暖度静头表打海列到可多客问一格名节程莽父母瓜色牛历八同旧开扬望贴口嘴兴跟潮考手鹃事经瓷明卡汪心"]);
const ZH_NOT_BEFORE_PET = new Set([..."养古元缩从最很太变减细胆弱矮狭短渺幼微妻大小老父尊年衰告偕苍资长垂遗月敬一"]);
// A word, not a given name, between surname and title: 高级经理, 王总经理.
const ZH_NOT_GIVEN = new Set([..."级副总大小老新前主部区店班首全各本该此那这男女好的和跟们位个名些都也还就才又再很太真最更说让叫是在给被把对向问请找帮带同与及或而但却只已曾将要会能可想去来到回过着了吗呢吧啊家里外上下中内长目分用库委生院特一二三四五六七八九十"]);
// Tried at each surname in turn (sticky), so one match never starts a
// character early and steps over the surname: 问张伟老师.
const ZH_TITLED = new RegExp(String.raw`(${ZH_DOUBLE_SURNAME}|\p{Script=Han})(\p{Script=Han}{0,2}?)(?=${ZH_TITLE})`, "uy");
const ZH_PET = /[小老](\p{Script=Han})(?=(\p{Script=Han})?)/gu;
const ZH_BREAK_BEFORE = /(?:^|[^\p{Script=Han}]|[给和跟向对找问请让把被叫是与及、的])$/u;

function chineseNamesFromCues(text: string, out: string[]): void {
  if (!/\p{Script=Han}/u.test(text) || /[\p{Script=Hiragana}\p{Script=Katakana}]/u.test(text)) return;
  const add = (name: string) => { if (isSubstitutable(name) && !out.includes(name)) out.push(name); };
  for (let at = 0; at < text.length; at++) {
    if (!ZH_SURNAMES.has(text[at]) && !ZH_DOUBLE_SURNAME.includes(text.slice(at, at + 2))) continue;
    ZH_TITLED.lastIndex = at;
    const m = ZH_TITLED.exec(text);
    if (!m) continue;
    const [surname, given] = [m[1], m[2]];
    const double = surname.length === 2;
    if (!double && !ZH_SURNAMES.has(surname)) continue;
    if (!double && ZH_WORD_BEFORE.has(text.slice(at - 1, at + 1))) continue;
    // A given name only after a word break, and only one that is not a word.
    if (given && (!ZH_BREAK_BEFORE.test(text.slice(0, at)) || [...given].some((c) => ZH_NOT_GIVEN.has(c)))) continue;
    add(surname + given);
    at += m[0].length - 1;
  }
  for (const m of text.matchAll(ZH_PET)) {
    const at = m.index ?? 0;
    if (!ZH_PET_SURNAMES.has(m[1]) || (m[2] && ZH_NOT_AFTER_PET.has(m[2]))) continue;
    if (at > 0 && ZH_NOT_BEFORE_PET.has(text[at - 1])) continue;
    if (ZH_WORD_BEFORE.has(text.slice(at + 1, at + 3))) continue;
    add(text.slice(at, at + 2));
  }
}

/**
 * A title in front of an East Asian name, the way forms and letters written
 * from a Western template set it: "Mr. 以熙 瞿", "尊敬的小姐其庆 时",
 * "chan かずまさ 安藤 様", "君 さきこ 高田 様", "yang 다예 임", "군 경재 원".
 * Neither tagger reads a name in these scripts after a title, and these were
 * most of the misses left in namesEastAsia (practice, 2026-10-30).
 *
 * The name is the words after the title, a space between each, each the
 * length a name's part is: kanji or hanzi one to three, kana two to six,
 * hangul one to three. An honorific or a particle on a word ends the name
 * there ("阿部様", "원님께"). A word that is longer, or holds a character that
 * is a word of the sentence (在, 的, 입니다), is not taken. A title native to
 * the script counts only with a space after it, or after 尊敬的 or 亲爱的:
 * "王先生说" is 王, and 先生 there starts nothing.
 */
const EA = String.raw`\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}`;
const EA_TITLE_LATIN = String.raw`(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\.?|chan|kun|sama|dono|sensei|hakase|kyoju|gun|yang|ssi|sajangnim|bujangnim|seonsaengnim|gwajangnim|timjangnim|daepyonim|nim`;
const EA_TITLE_NATIVE = "先生|小姐|女士|太太|夫人|君|ちゃん|くん|様|殿|군|양";
const EA_TITLED = new RegExp(
  String.raw`(?:(?<![\p{L}])(?:${EA_TITLE_LATIN})[ \t]*|(?<![${EA}])(?:${EA_TITLE_NATIVE})[ \t]+|(?:尊敬的|亲爱的|親愛的)[ \t]*(?:先生|小姐|女士|太太|夫人)[ \t]*)((?:[${EA}]+)(?:[ \t][${EA}]+){0,4})`,
  "giu",
);
const EA_HONORIFIC_END = /(?:さん|さま|様|君|くん|ちゃん|先生|氏|殿|님께서는|님께서|님께|님은|님이|님의|님과|님|씨가|씨는|씨|께서|께)$/u;
const EA_PARTICLE_ALONE = /^(?:은|는|이|가|을|를|의|와|과|が|は|を|に|の|と|も|へ)$/u;
const EA_PARTICLE_END = /(?:은|는|이|가|을|를|의|와|과|에게|が|は|を|に|の|と|も|へ)$/u;
// Characters that are words of the sentence, never part of a name here.
const EA_WORD_CHARS = /[邸宅的在是于為为请請将將和与與及把被给給对對向从從到说說等们們这這那吗嗎呢了着過过也就都]|입니다|합니다|에서|으로|로서|하는|하고|있는|없는|입니/u;
const EA_NOT_A_NAME = new Set([...KO_ROLES, "등", "및", "그때는", "선생님", "고객님", "여러분", "담당", "위해", "통해", "대한", "관련", "같은", "다른", "모든", "위한", "스타일", "리더", "전체", "주니어", "기업", "팀"]);

function titledEastAsianNames(text: string, out: string[]): void {
  if (!new RegExp(`[${EA}]`, "u").test(text)) return;
  const zh = !/[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u.test(text);
  for (const m of text.matchAll(EA_TITLED)) {
    const words: string[] = [];
    let closed = false;
    for (let w of m[1].split(/[ \t]/)) {
      // An honorific or a particle on its own ends the name: "かおり さん", "철우 님께".
      if (w.replace(EA_HONORIFIC_END, "") === "" || /^(?:さん|さま|様|님|씨)/u.test(w) || EA_PARTICLE_ALONE.test(w)) { closed = true; break; }
      // "손에", "집으로": a place in the sentence, not a name.
      if (/\p{Script=Hangul}(?:에|에서|으로|에게|하고|했다|한다|들었다)$/u.test(w)) break;
      const honorific = w.match(EA_HONORIFIC_END);
      if (honorific && honorific[0].length < w.length) { w = w.slice(0, -honorific[0].length); closed = true; }
      // A particle on a name in hangul or kanji, never on kana, where
      // the same syllables end names: "원은", "原田が", but "ゆうと".
      else if (/^\p{Script=Hangul}{3,}$/u.test(w) && EA_PARTICLE_END.test(w)) { w = w.replace(EA_PARTICLE_END, ""); closed = true; }
      else if (/^\p{Script=Han}+[がはをにのともへ]$/u.test(w)) { w = w.slice(0, -1); closed = true; }
      // Kanji and kana in one word is a word of the sentence: "加藤です", "が担当し".
      if (/\p{Script=Han}/u.test(w) && /[ぁ-ヿ]/u.test(w)) break;
      const max = /\p{Script=Hangul}/u.test(w) ? 3 : /[\p{Script=Hiragana}\p{Script=Katakana}]/u.test(w) ? 6 : zh ? 2 : 3;
      if (w.length > max || EA_WORD_CHARS.test(w) || EA_NOT_A_NAME.has(w) || /[가-힣][\p{Script=Han}ぁ-ヿ]|[\p{Script=Han}ぁ-ヿ][가-힣]/u.test(w)) break;
      words.push(w);
      if (closed) break;
    }
    if (!words.length) continue;
    // 군 and 양 are words too (an army, both hands): after them, only a name
    // that something closes: 님, a particle, the end of the sentence, or a
    // family name in Latin letters after it.
    if (/^(?:군|양)[ \t]/u.test(m[0])) {
      // Nor after a word: "한국 군 병력" is an army. The title starts the clause.
      if (/\p{Script=Hangul}$/u.test(text.slice(0, m.index ?? 0).trimEnd())) continue;
      const after = text.slice((m.index ?? 0) + m[0].indexOf(m[1]) + words.join(" ").length);
      if (words.length > 3 || !(closed || /^\s*(?:$|[,.!?，。、:：(（)\n]|입니다|\p{Script=Latin})/u.test(after))) continue;
    }
    const name = words.join(" ");
    if (name.replace(/\s/g, "").length < 2 && !/\p{Script=Han}|\p{Script=Hangul}/u.test(name)) continue;
    if (isSubstitutable(name) && !out.includes(name)) out.push(name);
  }
}
