/**
 * Where the enclave gets its configuration.
 *
 * ── The problem this exists to solve ──
 *
 * `nitro-cli run-enclave` passes no environment. None. There is no `--env`, no
 * `-e`, and nothing in the EIF format that carries one — the image is measured
 * into PCR0 and a measured image cannot also be a configured one, which is the
 * whole point of the measurement.
 *
 * So an enclave that reads `process.env` reads an empty object, and this
 * service read three things from it: CF_ACCOUNT_ID, CF_AI_TOKEN, and the
 * ALLOW_NO_NAME_STAGE escape hatch. It therefore exited(1) on every boot with
 * "refusing to start: no name stage", rebooted, and did it again. The refusal
 * was correct; there was simply no way to satisfy it.
 *
 * The two obvious fixes are both worse:
 *
 *   • `ENV CF_AI_TOKEN=…` in the Dockerfile bakes the secret into the image.
 *     It lands in PCR0 and anyone holding the EIF can read it out of a layer.
 *     A machine whose argument is that nobody can get inside it should not
 *     carry a credential that anyone with the file can extract.
 *   • `ENV ALLOW_NO_NAME_STAGE=1` makes it boot by giving up the name stage,
 *     which is exactly the silent failure the startup check was written to
 *     prevent: other people's names reach the provider while every reply still
 *     answers `namesDecided: true`.
 *
 * So: ask the parent, over the same vsock channel everything else uses.
 *
 * ── What this does and does not trust the parent with ──
 *
 * It trusts the parent for the *name-stage credential* — a Cloudflare Workers
 * AI token. It does not trust the parent with anything a user wrote, and the
 * privacy argument is unchanged: message content still arrives, is redacted in
 * here, and the TLS to the provider is still established from inside.
 *
 * That is a real if narrow dependency and it is worth naming, because the
 * end state is not this. KMS with a key policy bound to PCR0 releases the
 * token only to an enclave that attests to the expected image, and needs no
 * trust in the parent at all. That is the next piece of work; this is the one
 * that makes the enclave boot without putting a secret in the measurement.
 */

/** Fetched once at boot. Absent fields simply stay absent. */
export type EnclaveConfig = {
  cfAccountId?: string;
  cfAiToken?: string;
  /** The structured-stages-only escape hatch, still opt-in and still typed
   *  out on purpose — it just gets typed on the parent now. */
  allowNoNameStage?: boolean;
  /**
   * The provider keys, for the sealed path.
   *
   * These are new here and they are the expensive part of the trade. Until
   * now the Worker held them and called the provider, which meant the Worker
   * held the plaintext too — it had to, to send it. Moving the call in here
   * is what takes the message away from the Worker, and moving the call means
   * moving the key.
   *
   * So the parent now holds two more secrets, in the same root-only file as
   * the name-stage token and for the same reason: anything in the image is
   * measured into PCR0 and readable by anyone with the EIF. The dependency is
   * unchanged in kind and larger in degree, and KMS with a key policy bound to
   * PCR0 is still what removes it.
   *
   * Absent is a working state, not a broken one: without them /chat refuses
   * and /redact carries on exactly as before.
   */
  anthropicKey?: string;
  openaiKey?: string;
  googleKey?: string;
  /**
   * What the Worker proves itself with, on /chat, /redact and /names.
   *
   * The tunnel puts every path of this server on the public internet, and
   * the public key and the sealing code are published, so without it anybody
   * could seal a chat and spend the provider keys above with no meter, no
   * plan and no output cap (security review, 2026-11-15). Kept on the parent
   * with the provider keys, never in the image. Absent: open, as before, with
   * a warning at boot, so the image and the config can ship in either order.
   */
  workerSecret?: string;
};

/**
 * The loopback port enclave-init.sh forwards to the parent's config responder.
 *
 * Matched in three places — here, scripts/enclave-init.sh, and
 * scripts/parent-up.sh — for the same reason the provider ports are: service
 * discovery on a machine with no network is worse than a number written down
 * three times. Change one, change all three.
 */
const CONFIG_PORT = 8446;

/**
 * Ask the parent for configuration.
 *
 * Deliberately forgiving about the parent being slow: the relays and the
 * enclave come up in whatever order the two machines manage, and an enclave
 * that gives up because socat had not finished binding yet is an enclave that
 * fails on a race rather than on a fault. Four tries over about seven seconds,
 * then give up and let the caller decide what an unconfigured start means.
 *
 * Environment still wins where it is set, so `npm run dev` on a laptop is
 * unchanged and no one has to run a vsock responder to work on redaction.
 */
export async function loadConfig(): Promise<EnclaveConfig> {
  const fromEnv: EnclaveConfig = {
    cfAccountId: process.env.CF_ACCOUNT_ID || undefined,
    cfAiToken: process.env.CF_AI_TOKEN || undefined,
    allowNoNameStage: process.env.ALLOW_NO_NAME_STAGE === "1" || undefined,
    anthropicKey: process.env.ANTHROPIC_API_KEY || undefined,
    openaiKey: process.env.OPENAI_API_KEY || undefined,
    googleKey: process.env.GOOGLE_API_KEY || undefined,
    workerSecret: process.env.ENCLAVE_WORKER_SECRET || undefined,
  };
  if (fromEnv.cfAccountId && fromEnv.cfAiToken) return fromEnv;
  if (fromEnv.allowNoNameStage) return fromEnv;

  // Only inside the enclave. On a laptop there is no parent to ask, and four
  // seconds of connection refused before every dev run is a tax on the wrong
  // people.
  if (process.env.ENCLAVE !== "1") return fromEnv;

  for (const wait of [0, 1000, 2000, 4000]) {
    if (wait) await new Promise((r) => setTimeout(r, wait));
    try {
      const res = await fetch(`http://127.0.0.1:${CONFIG_PORT}/config`, {
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) continue;
      const body = (await res.json()) as EnclaveConfig;
      return {
        cfAccountId: fromEnv.cfAccountId ?? body.cfAccountId,
        cfAiToken: fromEnv.cfAiToken ?? body.cfAiToken,
        allowNoNameStage: fromEnv.allowNoNameStage ?? body.allowNoNameStage,
        anthropicKey: fromEnv.anthropicKey ?? body.anthropicKey,
        openaiKey: fromEnv.openaiKey ?? body.openaiKey,
        googleKey: fromEnv.googleKey ?? body.googleKey,
        workerSecret: fromEnv.workerSecret ?? body.workerSecret,
      };
    } catch {
      // Parent not ready, or no responder. Retry, then fall through.
    }
  }
  console.error(
    "[enclave] no config from the parent after 4 attempts — is " +
      "enclave-config-server running there? See scripts/parent-up.sh.",
  );
  return fromEnv;
}
