import { existsSync } from "node:fs";
import { join } from "node:path";

import type { NameModel } from "../../cloudflare-worker/redaction.js";
import { AS_TAGGED_OWN, asWordPieces, organisations, people, pieces, places, unsureOutsideEnglish, type Token } from "./nameReading.js";

export * from "./nameReading.js";

/**
 * The name stage, answered inside the enclave.
 *
 * Until 2026-09-28 the enclave asked Llama 3.2 3B on Cloudflare Workers AI
 * which words were people, which meant showing Cloudflare the message in the
 * clear: the one hop in the sealed path the enclave's lock did not cover. Two
 * small named-entity models run here instead, on the enclave's own CPU, and
 * the message never leaves for this question at all.
 *
 * Two because each misses what the other finds. Measured on the 400-document
 * name benchmark (cloudflare-worker/bench/liveStage, ai4privacy practice set):
 *
 *   Llama 3.2 3B on Workers AI          recall 88.1%   no-harm precision 91.8%
 *   bert-base-NER (English) alone       recall 88.2%   no-harm precision 98.9%
 *   multilingual NER (10 languages)     recall 80.1%   no-harm precision 98.5%
 *   both, merged (this file)            recall 95.5%   no-harm precision 98.6%
 *
 * The models are files in the image, pinned by revision and checked by hash in
 * the Dockerfile, so they are measured into PCR0 like everything else here.
 * Nothing is fetched at runtime: remote models are switched off.
 *
 * It answers in the envelope redaction.ts already reads from Workers AI
 * ({ response: [...] }), so detectPersonalNames, its gate, its cue pass and
 * its filters run unchanged. The system prompt is ignored: these models are
 * not asked, they tag.
 */

export const LOCAL_NAME_MODELS = ["Xenova/bert-base-NER", "Xenova/bert-base-multilingual-cased-ner-hrl"] as const;

type Tagger = (text: string, opts: { ignore_labels: string[] }) => Promise<Token[]>;

/** Load both taggers from `modelDir` and wrap them as a NameModel. Loading
 *  takes a few seconds and happens once, before the server binds a port. */
export async function localNameModel(modelDir: string): Promise<NameModel> {
  const { pipeline, env } = await import("@huggingface/transformers");
  env.allowRemoteModels = false;
  env.localModelPath = modelDir.endsWith("/") ? modelDir : `${modelDir}/`;
  const taggers = (await Promise.all(
    LOCAL_NAME_MODELS.map((m) => pipeline("token-classification", m, { dtype: "q8" })),
  )) as unknown as Tagger[];

  return async (_system, user) => {
    const names: string[] = [];
    const orgs: string[] = [];
    const locs: string[] = [];
    for (const piece of pieces(user)) {
      const english = await taggers[0](piece, { ignore_labels: [] });
      const multilingual = await taggers[1](piece, { ignore_labels: [] });
      const second = people(multilingual, piece);
      const first = people(english, piece).filter((n) => !unsureOutsideEnglish(n, english, piece, second));
      for (const n of [...first, ...second]) if (!names.includes(n)) names.push(n);
      for (const tokens of [english, multilingual]) {
        for (const o of organisations(tokens, piece)) if (!orgs.includes(o)) orgs.push(o);
        for (const l of places(tokens, piece)) if (!locs.includes(l)) locs.push(l);
      }
    }
    // `organisations` and `places` ride beside `response`: a reader that
    // knows only `response` (and Workers AI, which has neither) is unchanged.
    return { response: names, organisations: orgs, places: locs };
  };
}

/** Where our own model sits under the models folder once it ships: the
 *  folder namemodel/export.py writes, copied in as models/names. */
export const OWN_NAME_MODEL = "names";

/** Which name model this image carries, decided by what is in it.
 *
 *  An enclave is started with no environment, so a setting could not choose;
 *  the image's contents can, and they are what PCR0 measures. An image with
 *  models/names/onnx/model_quantized.onnx runs our model. Any other runs the
 *  two Xenova taggers, exactly as before this existed. Switching is a new
 *  image either way, with its own PCR0, through enclave/RUNBOOK.md. */
export function whichNameModel(modelDir: string): "own" | "pair" {
  return existsSync(join(modelDir, OWN_NAME_MODEL, "onnx", "model_quantized.onnx")) ? "own" : "pair";
}

export async function nameModelIn(modelDir: string): Promise<{ which: "own" | "pair"; model: NameModel }> {
  const which = whichNameModel(modelDir);
  const model = which === "own" ? await ownNameModel(join(modelDir, OWN_NAME_MODEL)) : await localNameModel(modelDir);
  return { which, model };
}

/** Our own name model (namemodel/ in this repo), from the folder export.py
 *  writes: one tagger for people, organisations and places in all 40
 *  languages, where localNameModel merges two. No second opinion means no
 *  unsureOutsideEnglish either; that rule exists for an English tagger
 *  reading German, and this one was trained on German. */
export async function ownNameModel(modelPath: string): Promise<NameModel> {
  const { pipeline, env } = await import("@huggingface/transformers");
  env.allowRemoteModels = false;
  const path = modelPath.replace(/[\\/]+$/, "");
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  env.localModelPath = cut < 0 ? "./" : path.slice(0, cut + 1);
  const tagger = (await pipeline("token-classification", path.slice(cut + 1), { dtype: "q8" })) as unknown as Tagger & {
    tokenizer: { tokenize(text: string): string[] };
  };

  return async (_system, user) => {
    const names: string[] = [];
    const orgs: string[] = [];
    const locs: string[] = [];
    for (const piece of pieces(user)) {
      const tokens = asWordPieces(await tagger(piece, { ignore_labels: [] }), tagger.tokenizer.tokenize(piece));
      for (const n of people(tokens, piece, AS_TAGGED_OWN)) if (!names.includes(n)) names.push(n);
      for (const o of organisations(tokens, piece, AS_TAGGED_OWN)) if (!orgs.includes(o)) orgs.push(o);
      for (const l of places(tokens, piece, AS_TAGGED_OWN)) if (!locs.includes(l)) locs.push(l);
    }
    return { response: names, organisations: orgs, places: locs };
  };
}
