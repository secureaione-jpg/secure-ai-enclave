# Redaction enclave

The redaction step, moved into an AWS Nitro Enclave so that "we cannot see your
prompt" stops being a promise and becomes something a user can check.

## What it is

A Node service that runs inside an enclave and does exactly one job:

    encrypted prompt → strip PII → call the AI provider → hand back the reply

It holds nothing. The real↔fake map lives in memory for the length of one
request and goes back to the client, which is how the Worker already works —
see `X-Redaction-Map` in `cloudflare-worker/worker.ts`. There is no store to
compromise because there is nothing to store.

The redaction itself is `cloudflare-worker/redaction.ts` and the four `redaction*.ts` parts it re-exports, imported unchanged.
One implementation, two homes; a second copy is how the two stop agreeing.

## Why there is no vsock code here

An enclave's only channel to the world is an `AF_VSOCK` socket, and Node has no
native support for it. Rather than take a native addon into the trusted
computing base, `socat` does the translation at both ends and the Node process
speaks ordinary TCP on loopback:

    parent :9000  ──socat──▶ vsock CID:5000 ──socat──▶ enclave 127.0.0.1:8000

The service therefore has no idea it is in an enclave, which is also what makes
it runnable on a laptop. `npm run dev` is the same binary doing the same work
with the socat hops missing.

Outbound is the mirror image, and the direction that matters for the security
argument. The parent runs AWS's `vsock-proxy`, which is a dumb TCP relay with
an allowlist — the TLS session is enclave↔provider, so the parent moves
ciphertext it cannot read. If anything ever terminates TLS on the parent, the
enclave has bought nothing.

## Running it locally

    npm install
    npm run dev

    curl -s localhost:8000/health
    curl -s localhost:8000/attestation      # says "unattested" off real hardware
    curl -s localhost:8000/redact -X POST -H 'content-type: application/json' \
      -d '{"messages":[{"role":"user","content":"email me at sam@acme.com"}]}'

## Deferred, deliberately

KMS keys bound to PCR conditions, and any kind of HA. (Streaming, client→
enclave encryption and reproducible builds have since landed: see
PUBLIC-README.md for how anyone rebuilds the image and checks PCR0.) The prototype exists to
prove the path end to end; each of those is a separate piece of work with its
own way of being wrong.
