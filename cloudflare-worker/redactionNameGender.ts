/**
 * Which stand-ins a first name should draw from (2026-10-28).
 *
 * "Maria Delgado" went to the model as "Casimir Ellingham", and a report on
 * her medical records came back saying "he": the model takes the stand-in's
 * gender from the name, and the person reads their client misgendered in a
 * document they meant to send. So a first name that is plainly a woman's or
 * a man's draws from stand-ins of the same kind, and any other name draws
 * from all of them as before.
 *
 * Deliberately short and deliberately one-sided: common given names that
 * are used overwhelmingly for one gender, in the languages the product is
 * used in most. A name on neither list (Alex, Jordan, Kim, Sasha, and every
 * name not here) is not guessed at.
 */

export const FEMALE_STAND_INS = [
  "Naomi", "Priya", "Ingrid", "Colette", "Marisol", "Elena", "Rosalind", "Farah",
  "Beatrix", "Solveig", "Anika", "Lorna", "Tessa", "Noor", "Sylvie",
] as const;

export const MALE_STAND_INS = [
  "Marcus", "Curtis", "Rafael", "Theo", "Grant", "Yusuf", "Damon", "Adrian",
  "Nolan", "Emmett", "Julian", "Desmond", "Casimir", "Gideon", "Warren", "Malik",
] as const;

const FEMALE = new Set(`
abigail ada adriana agnes aisha alejandra alessandra alexandra alice alicia alina alison amanda amber
amelia amy ana anastasia andrea angela angelica anita ann anna anne annette antonia ashley audrey ava
barbara beatriz bella betty beverly bianca brenda bridget brittany camila carla carmen carol caroline
carolyn catherine cecilia charlotte chiara chloe christina christine claire clara claudia cristina
cynthia daisy daniela danielle deborah debra denise diana dolores donna doris dorothy elena elif
elisabeth eliza elizabeth ella ellen elsa emily emma esperanza esther eva evelyn fatima fatma florence
frances francesca gabriela gabrielle gemma gloria grace hannah heather helen helena ines ingrid irene
isabel isabella jacqueline jane janet janice jasmine jennifer jessica joan joanna josephine joyce
judith judy julia julie karen katarzyna katherine kathleen kathryn katie kayla kelly kimberly laura
lauren leah leila lena linda lisa lucia lucy luisa lydia madison magdalena maria mariana marie
marilyn marina marta martha mary maya megan melissa mia michelle mila miriam monica nadia nancy natalia
natalie nicole nina noura olga olivia paola patricia paula pauline priya rachel rebecca regina rita
rosa rose ruth sabrina samantha sandra sara sarah sharon sofia sophia sophie stephanie susan svetlana
tamara teresa theresa valentina valeria vanessa veronica victoria virginia wendy yasmin yolanda zainab zoe
`.trim().split(/\s+/));

const MALE = new Set(`
aaron abdullah adam ahmed alan albert alejandro alexander alfredo ali andre andreas andrew angelo
anthony antonio arjun arthur benjamin bernard bill bob brandon brian bruce bryan carl carlos charles
christian christopher daniel darius david dennis diego dmitri donald douglas dylan edward eduardo
elijah eric ethan eugene fernando francesco francisco frank gabriel gary george gerald giovanni gregory
hans harold harry hassan henry hiroshi ibrahim ivan jack jacob james jason javier jeffrey jeremy jerry
jesse joe john jonathan jorge jose joseph joshua juan justin keith kenneth kevin klaus larry lawrence
liam lorenzo louis lucas luis marco marcus mario mark martin matteo matthew michael miguel mohammed
muhammad nathan nicholas noah oliver omar oscar pablo patrick paul pedro peter philip pierre rahul
ralph ramon randy raymond ricardo richard robert roberto roger ronald roy russell ryan samuel scott
sean sergei sergio stefan stephen steven terry thomas timothy tom tyler victor vincent walter wayne
william yusuf
`.trim().split(/\s+/));

/** The stand-in first names for this person's name: a woman's, a man's,
 *  or all of them when the first name does not say. Titles are skipped. */
export function standInFirstsFor(name: string, all: readonly string[]): readonly string[] {
  for (const word of name.toLowerCase().split(/\s+/)) {
    const w = word.replace(/[.,]/g, "");
    if (!w || /^(dr|mr|mrs|ms|miss|prof|sir|sr|sra|mme|herr|frau)$/.test(w)) continue;
    if (FEMALE.has(w)) return FEMALE_STAND_INS;
    if (MALE.has(w)) return MALE_STAND_INS;
    return all;
  }
  return all;
}
