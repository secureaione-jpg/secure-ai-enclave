import { describe, expect, it } from "vitest";
import { asWordPieces, organisations, people, pieces, places, readsAsEnglish, unsureOutsideEnglish } from "./localNameModel";

describe("the local name models' plumbing", () => {
  it("joins B-PER and I-PER word pieces into a name found in the text", () => {
    const text = "Email Sarah Chen and José García today.";
    const tokens = [
      { entity: "B-PER", word: "Sarah" }, { entity: "I-PER", word: "Chen" },
      { entity: "O", word: "and" },
      { entity: "B-PER", word: "Jos" }, { entity: "I-PER", word: "##é" }, { entity: "I-PER", word: "García" },
    ];
    expect(people(tokens, text)).toEqual(["Sarah Chen", "José García"]);
  });

  it("stretches a name the tagger split to the whole word", () => {
    expect(people([{ entity: "B-PER", word: "Kat" }], "Kattie could you share your notes?")).toEqual(["Kattie"]);
  });

  it("reads organisations from B-ORG and I-ORG, and people stay people", () => {
    const text = "Sarah Chen joined Acme Logistics in Leeds.";
    const tokens = [
      { entity: "B-PER", word: "Sarah" }, { entity: "I-PER", word: "Chen" }, { entity: "O", word: "joined" },
      { entity: "B-ORG", word: "Acme" }, { entity: "I-ORG", word: "Log" }, { entity: "I-ORG", word: "##istics" },
      { entity: "O", word: "in" }, { entity: "B-LOC", word: "Leeds" },
    ];
    expect(organisations(tokens, text)).toEqual(["Acme Logistics"]);
    expect(people(tokens, text)).toEqual(["Sarah Chen"]);
  });

  it("drops an organisation the tagger was unsure of, or found mid-word", () => {
    const text = "Die Klägerin beantragt, der Europäischen Kommission die Kosten aufzuerlegen.";
    const tokens = [
      { entity: "I-ORG", word: "K", score: 0.35 }, { entity: "I-ORG", word: "##l", score: 0.47 },
      { entity: "B-ORG", word: "##zu", score: 0.95 },
      { entity: "B-ORG", word: "Europäischen", score: 0.99 }, { entity: "I-ORG", word: "Kommission", score: 0.98 },
    ];
    expect(organisations(tokens, text)).toEqual(["Europäischen Kommission"]);
  });

  it("drops a name that is not in the text verbatim", () => {
    expect(people([{ entity: "B-PER", word: "Nobody" }], "no names here")).toEqual([]);
  });

  it("tells English from the other languages by their small words", () => {
    expect(readsAsEnglish("The claimant was employed by the company for ten years.")).toBe(true);
    expect(readsAsEnglish("Zweifellos hatte diese Entscheidung Auswirkungen auf die Klägerin und den Beklagten.")).toBe(false);
    expect(readsAsEnglish("Orbene, la qualificazione della Corte non può essere accolta e il ricorso del ricorrente è respinto nella sua interezza.")).toBe(false);
  });

  /* German capitalises every noun and the English tagger takes a capital
     for a name: MAPA's practice rows had 449 such words to 386 people. */
  it("drops an unsure lone word in German text that the other model did not find", () => {
    const text = "Zweifellos hatte diese Entscheidung Auswirkungen auf die Klägerin und den Beklagten.";
    const tokens = [{ entity: "B-PER", word: "Zweifellos", score: 0.55 }];
    expect(unsureOutsideEnglish("Zweifellos", tokens, text, [])).toBe(true);
  });

  it("drops a German word the tagger marked only the start of, however sure", () => {
    const text = "Zweifellos hatte diese Entscheidung Auswirkungen auf die Klägerin und den Beklagten.";
    expect(unsureOutsideEnglish("Zweifellos", [{ entity: "B-PER", word: "Z", score: 0.94 }], text, [])).toBe(true);
  });

  it("keeps a known first name however unsure the tagger was", () => {
    const text = "Cher Betty, nous pensons que vous devriez mettre à jour les données pour votre dossier dans les meilleurs délais.";
    expect(unsureOutsideEnglish("Betty", [{ entity: "B-PER", word: "Bet", score: 0.4 }], text, [])).toBe(false);
  });

  it("keeps the same word when the other model also found it, or the tagger was sure", () => {
    const text = "Die Klägerin Egenberger und der Beklagte haben die Kosten zu tragen.";
    expect(unsureOutsideEnglish("Egenberger", [{ entity: "B-PER", word: "Egenberger", score: 0.55 }], text, ["Egenberger"])).toBe(false);
    expect(unsureOutsideEnglish("Egenberger", [{ entity: "B-PER", word: "Egenberger", score: 0.95 }], text, [])).toBe(false);
  });

  it("keeps hyphenated and multi-word names, and leaves English alone", () => {
    const de = "Die Stellungnahme von Ruiz-Jarabo und der Kommission ist zu berücksichtigen.";
    expect(unsureOutsideEnglish("Ruiz-Jarabo", [{ entity: "B-PER", word: "Ruiz", score: 0.5 }], de, [])).toBe(false);
    const en = "The claim was filed by Balvan and the company for the refund.";
    expect(unsureOutsideEnglish("Balvan", [{ entity: "B-PER", word: "Balvan", score: 0.5 }], en, [])).toBe(false);
  });

  it("reads long text in overlapping pieces that cover all of it", () => {
    const text = "word ".repeat(600) + "Maria Lopez";
    const ps = pieces(text);
    expect(ps.length).toBeGreaterThan(1);
    expect(ps.some((p) => p.includes("Maria Lopez"))).toBe(true);
    expect(ps.every((p) => p.length <= 1000)).toBe(true);
  });

  it("reads a line in another script on its own too, so an English turn before it cannot hide its names", () => {
    const en = "Draft a short email to Maria Lopez. Sign it Daniel Kim.";
    const ja = "田中由美さんに、木曜日の打ち合わせを15時に変更するメールを書いてください。";
    expect(pieces(`${en}\n${ja}`)).toContain(ja);
    expect(pieces(ja)).toEqual([ja]);
    expect(pieces(`${en}\nThanks, Maria`)).toEqual([`${en}\nThanks, Maria`]);
  });
});

describe("our own model's SentencePiece tokens", () => {
  // What transformers.js hands back: `word` decoded bare, `index` counting <s>.
  const tok = (index: number, entity: string, word: string) => ({ index, entity, word, score: 0.99 });

  it("joins the second half of a split name onto the first, not as a new word", () => {
    const text = "Pani Anna Kowalska dzwoniła.";
    const raw = ["▁Pani", "▁Anna", "▁Kow", "alska", "▁dzwoni", "ła", "."];
    const tokens = asWordPieces(
      [tok(1, "O", "Pani"), tok(2, "B-PER", "Anna"), tok(3, "I-PER", "Kow"), tok(4, "I-PER", "alska"),
        tok(5, "O", "dzwoni"), tok(6, "O", "ła"), tok(7, "O", ".")],
      raw,
    );
    expect(tokens.map((t) => t.word)).toEqual(["Pani", "Anna", "Kow", "##alska", "dzwoni", "##ła", "##."]);
    expect(people(tokens, text)).toEqual(["Anna Kowalska"]);
  });

  it("drops a lone space piece and passes its B- on", () => {
    const text = "明日 田中太郎さんに連絡";
    const raw = ["▁明日", "▁", "田中", "太郎", "さん", "に", "連絡"];
    const tokens = asWordPieces(
      [tok(1, "O", "明日"), tok(2, "B-PER", ""), tok(3, "I-PER", "田中"), tok(4, "I-PER", "太郎"),
        tok(5, "O", "さん"), tok(6, "O", "に"), tok(7, "O", "連絡")],
      raw,
    );
    expect(tokens[1]).toMatchObject({ entity: "B-PER", word: "田中" });
    expect(people(tokens, text)).toEqual(["田中太郎"]);
  });

  it("drops a lone space piece and passes its B- on, without the B- carried into the next name", () => {
    expect(asWordPieces([tok(1, "B-PER", "")], ["▁"])).toEqual([]);
  });
});

describe("names in scripts written without spaces", () => {
  it("does not stretch a name over the rest of the sentence", () => {
    const text = "スミスさんは東京にいます";
    expect(people([{ entity: "B-PER", word: "スミス" }], text)).toEqual(["スミス"]);
    expect(places([{ entity: "B-LOC", word: "東京", score: 0.95 }], text)).toEqual(["東京"]);
  });

  it("reads a split name back as written", () => {
    const text = "田中太郎さんは東京にいます";
    const tokens = [{ entity: "B-PER", word: "田中" }, { entity: "I-PER", word: "##太郎" }, { entity: "O", word: "##さんは" }];
    expect(people(tokens, text)).toEqual(["田中太郎"]);
  });

  it("closes the gaps BERT puts between Chinese characters", () => {
    const text = "请联系唐冬梅确认";
    const tokens = [{ entity: "B-PER", word: "唐" }, { entity: "I-PER", word: "冬" }, { entity: "I-PER", word: "梅" }];
    expect(people(tokens, text)).toEqual(["唐冬梅"]);
  });

  it("keeps a space that is really in the text", () => {
    expect(people([{ entity: "B-PER", word: "佐藤" }, { entity: "I-PER", word: "真綾" }], "佐藤 真綾様")).toEqual(["佐藤 真綾"]);
  });

  it("finds a name with a space the tagger split elsewhere", () => {
    // "森田 一 郎" is neither the text's "森田 一郎" nor "森田一郎".
    const tokens = [{ entity: "B-PER", word: "森田" }, { entity: "I-PER", word: "一" }, { entity: "I-PER", word: "郎" }];
    expect(people(tokens, "部長の森田 一郎さんから連絡がありました")).toEqual(["森田 一郎"]);
    expect(people(tokens, "部長の森田　一郎さんから連絡がありました")).toEqual(["森田　一郎"]);
  });

  it("still completes a Korean name the tagger only began, since Korean has spaces", () => {
    expect(people([{ entity: "B-PER", word: "김" }], "김경수 씨가 내일 옵니다")).toEqual(["김경수"]);
  });

  it("stops a Latin name at the Chinese written straight after it", () => {
    expect(people([{ entity: "B-PER", word: "Mari" }], "Mariele组织了一场研讨会")).toEqual(["Mariele"]);
  });

  it("does not take a single character as a name", () => {
    expect(people([{ entity: "B-PER", word: "田" }], "田んぼ")).toEqual([]);
  });
});

describe("which name model an image runs", () => {
  it("runs our own model only when the image carries its quantised file", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { whichNameModel } = await import("./localNameModel");
    const dir = mkdtempSync(join(tmpdir(), "models-"));
    expect(whichNameModel(dir)).toBe("pair");
    mkdirSync(join(dir, "names", "onnx"), { recursive: true });
    expect(whichNameModel(dir)).toBe("pair"); // a folder alone is not a model
    writeFileSync(join(dir, "names", "onnx", "model_quantized.onnx"), "");
    expect(whichNameModel(dir)).toBe("own");
  });
});

describe("Korean, read for our own model", () => {
  it("keeps the particle off a name our model tagged exactly", async () => {
    const { AS_TAGGED_OWN } = await import("./nameReading");
    const tokens = [{ entity: "B-PER", word: "김민수" }, { entity: "O", word: "##님께서는" }];
    expect(people(tokens, "김민수님께서는 내일 오십니다", AS_TAGGED_OWN)).toEqual(["김민수"]);
    // Today's taggers still have a half-tagged name completed, as measured.
    expect(people([{ entity: "B-PER", word: "김" }], "김경수 씨가 내일 옵니다")).toEqual(["김경수"]);
  });
});
