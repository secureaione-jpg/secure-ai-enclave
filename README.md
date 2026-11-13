# Secure AI enclave

The code that runs inside [Secure AI](https://secureai.one)'s AWS Nitro Enclave,
published so you can check what handles your messages instead of taking our
word for it.

When the app sends a message the private way, it is sealed to a key only this
enclave holds. Inside, names, numbers and IDs are replaced before the message
goes to the AI provider, and the reply is put back together before it leaves.
The enclave keeps nothing, and the machine it runs on cannot read inside it —
including us.

## What you can check

An enclave proves which code it runs with a signed **attestation**: AWS's
hardware signs a fingerprint of the exact image it booted, called **PCR0**. Our
app checks that signature, and that PCR0, before it sends anything.

This repository lets you check the other half: that the PCR0 the app accepts is
built from this source. Build it yourself and compare.

## Verifying the enclave

You need an x86-64 Amazon Linux 2023 machine (any EC2 instance; it does not
need enclaves turned on) with Docker, Docker Buildx and the Nitro CLI:

```bash
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git
sudo systemctl enable --now docker
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-buildx \
  https://github.com/docker/buildx/releases/download/v0.19.3/buildx-v0.19.3.linux-amd64
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
nitro-cli --version     # PCR0 depends on it: use the version RELEASES.md names
```

Then build:

```bash
git clone https://github.com/secureaione-jpg/secure-ai-enclave && cd secure-ai-enclave
git checkout <release tag from RELEASES.md>
sudo ./enclave/scripts/build-reproducible.sh enclave.eif
```

It prints three measurements. **PCR0** must equal the one listed for that
release in [RELEASES.md](RELEASES.md).

To check the live enclave, ask it for an attestation with a fresh random nonce
and verify the signature against the
[AWS Nitro root certificate](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html);
the PCR0 inside should be the one you built:

```bash
curl -s "https://enclave.secureaione.com/attestation?nonce=$(openssl rand -hex 16)"
```

## How the build stays the same

Everything that goes into the image is fixed by this source:

- base images pinned by digest, not by tag;
- Debian packages from `snapshot.debian.org` at one date;
- npm packages from `package-lock.json` (`npm ci`), Rust crates from `Cargo.lock` (`--locked`);
- the two public name models fetched at a pinned revision and checked by SHA-256;
- BuildKit at a pinned version, with every file's timestamp set to 0.

## Our own name model

One part is not public: the weights of the name model we trained. They are
**not in the image**. The image carries only their SHA-256 hashes
(`enclave/names-model.sha256`); at boot the enclave fetches the files from its
host and keeps each one only if it matches (`enclave/src/modelFetch.ts`). A
host that sends anything else gets an enclave that refuses to start. You can't
see the weights, but which weights may run is fixed by PCR0 like everything
else.

## What's in here

| Path | What it is |
|---|---|
| `enclave/src/` | The service: sealed messages in, redaction, the call to the AI provider, the reply out |
| `cloudflare-worker/redaction*.ts` | The redaction itself, the same code the rest of Secure AI runs |
| `lib/sealedEnvelope.ts` | The encryption format between the app and the enclave |
| `enclave/nsm-cli/` | A small Rust helper that asks the Nitro hardware for attestations |
| `enclave/scripts/` | Boot script, host relays, and the reproducible build |
| `enclave/Dockerfile` | The image |

`SOURCE_COMMIT` names the commit in our private repository this was exported from.

## License

Published so it can be read and verified. All rights reserved; not licensed for reuse.

## Found a problem?

See [secureai.one/security](https://secureai.one/security), or email company@secureai.one.
