/**
 * PII redaction.
 *
 * Lifted out of worker.ts whole, unchanged except for one seam. It used to sit
 * in the middle of the Worker because that was the only place it ran; it now
 * has to run in two places — the Worker, and an AWS Nitro Enclave that does
 * nothing else — and a second copy of a thousand lines of security-critical
 * matching is how the two quietly stop agreeing.
 *
 * The seam is the name stage, and it is cut as narrowly as possible: only the
 * inference call itself is injected. The prompt stays here, because it is
 * tuned rather than obvious — the rules-only version scored 3/16 on the bench
 * and the version with worked examples scores 13/16 — and so does the reply
 * parsing, because "the platform sometimes hands back already-parsed JSON" is
 * exactly the kind of knowledge that gets lost in a second implementation.
 * What the caller supplies is a way to ask a model, and nothing else.
 *
 * The ordering that makes the product promise true still lives in the caller,
 * not here — redact, then key the cache, then tee the capture, then call the
 * provider, and restore only on the copy addressed to the user. This file is
 * the how; worker.ts is still the when.
 */

export * from "./redactionMap.js";
export * from "./redactionStructured.js";
export * from "./redactionNameWords.js";
export * from "./redactionNames.js";
export * from "./redactionMedical.js";
export * from "./redactionRecords.js";
export * from "./redactionNumbers.js";
export * from "./redactionRestore.js";
/* Not a stage. It answers "which of these stages is this machine running",
   which matters because the same source runs here and in the enclave from two
   separately deployed builds. See redactionBuild.ts. */
export * from "./redactionBuild.js";
