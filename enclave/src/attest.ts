import { existsSync } from "node:fs";

/**
 * Attestation: the enclave proving what it is.
 *
 * Nitro's Security Module sits at /dev/nsm and will sign a document containing
 * the enclave's PCR measurements — hashes of the image, the kernel and the
 * application — along with up to three fields the caller supplies. The
 * signature chains to an AWS root certificate that anyone can pin.
 *
 * The field that matters is `public_key`. The enclave generates a keypair at
 * boot and asks the NSM to sign the public half *into* the document. That is
 * what turns "here is a signed measurement" into something usable: a client can
 * verify the measurements, then encrypt to that key knowing only this exact
 * image can read it. Attestation without a bound key proves an enclave exists
 * somewhere; it does not tell you who you are talking to.
 *
 * `nonce` is the client's, and it is what stops a document being replayed. A
 * verifier that skips the nonce check is verifying that an enclave was genuine
 * at some point in the past, which is not the question.
 *
 * ── What this file does not do ──
 *
 * Verify. Deliberately. A verifier that lives next to the thing it verifies is
 * theatre; the checking belongs on the client, or in a tool a sceptic can run
 * themselves. What is here is only the production half.
 *
 * Off real hardware there is no /dev/nsm, so this reports that plainly rather
 * than emitting something that could be mistaken for a real document. A stub
 * that returns a fake attestation is how an unattested deployment ships
 * believing it is attested.
 */

const NSM_DEVICE = "/dev/nsm";

export type Attestation =
  | { attested: true; document: string; publicKey: string }
  | { attested: false; reason: string; publicKey: string };

/**
 * The enclave's keypair for this boot.
 *
 * Ephemeral on purpose: it exists only in enclave memory, is never written
 * anywhere, and dies with the process. A restarted enclave is a new key and a
 * new attestation, which is the correct behaviour — the old key's guarantees
 * were about a running image, and that image is gone.
 */
const keyPair = await crypto.subtle.generateKey(
  { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["encrypt", "decrypt"],
);

const publicKeyDer = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
const publicKeyB64 = Buffer.from(publicKeyDer).toString("base64");

/** The private half never leaves this module, and there is no accessor for it —
 *  only the operation that needs it. */
export async function decryptToEnclave(ciphertext: Uint8Array): Promise<Uint8Array> {
  // Copied into a plain ArrayBuffer first: a Uint8Array can be backed by a
  // SharedArrayBuffer, which Web Crypto will not accept, and the type error is
  // the only warning you get before it is a runtime one.
  const buffer = new ArrayBuffer(ciphertext.byteLength);
  new Uint8Array(buffer).set(ciphertext);
  const plain = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, keyPair.privateKey, buffer);
  return new Uint8Array(plain);
}

export function enclavePublicKey(): string {
  return publicKeyB64;
}

/**
 * Ask the NSM for a document binding this boot's public key to this image's
 * measurements.
 *
 * The request is CBOR over an ioctl on /dev/nsm. Rather than take a native
 * addon into the trusted computing base for it, this shells out to the
 * `nsm-cli` helper baked into the image — one process, no compiled dependency,
 * and the same bytes either way.
 */
export async function attest(nonce: string): Promise<Attestation> {
  if (!existsSync(NSM_DEVICE)) {
    return {
      attested: false,
      reason: "No /dev/nsm — this process is not running inside a Nitro Enclave.",
      publicKey: publicKeyB64,
    };
  }

  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const run = promisify(execFile);
    // Base64 in, base64 COSE_Sign1 out. The helper does nothing but marshal.
    const { stdout } = await run("/usr/local/bin/nsm-cli", [
      "attest",
      "--nonce", Buffer.from(nonce, "utf8").toString("base64"),
      "--public-key", publicKeyB64,
    ]);
    return { attested: true, document: stdout.trim(), publicKey: publicKeyB64 };
  } catch (err) {
    // A failure here is not "no names found" — it is the enclave being unable
    // to prove itself, and a caller who cares must be able to tell.
    return {
      attested: false,
      reason: err instanceof Error ? err.message : "Attestation failed",
      publicKey: publicKeyB64,
    };
  }
}
