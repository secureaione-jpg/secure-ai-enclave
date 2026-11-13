# The enclave image.
#
# Built from the repo root, not from enclave/, because the redaction module it
# runs lives in cloudflare-worker/ and is shared with the Worker on purpose:
#
#   docker build -f enclave/Dockerfile -t secure-ai-enclave .
#
# Kept deliberately small. Everything in here is measured into PCR0, so every
# package added is something a reader verifying an attestation has to accept.
# A smaller image is a shorter argument.
#
# ── Reproducible (2026-11-13) ──
#
# Anyone can rebuild this image from the public source and get the same PCR0
# (README, "Verifying the enclave"). That holds only if nothing in here can
# change under the same source, so: every base image is pinned by digest,
# Debian packages come from snapshot.debian.org at one date, npm installs from
# the lockfile (npm ci), cargo from Cargo.lock (--locked), our own model is
# fetched at boot rather than baked in (src/modelFetch.ts), and the build is
# run with SOURCE_DATE_EPOCH and rewrite-timestamp so no file carries the time
# it was built. enclave/scripts/build-reproducible.sh is the one command.
ARG SOURCE_DATE_EPOCH=0
ARG DEBIAN_SNAPSHOT=20261101T000000Z

FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS build
WORKDIR /build

COPY enclave/package.json enclave/package-lock.json* ./enclave/
WORKDIR /build/enclave
RUN npm ci --omit=dev --no-audit --no-fund

WORKDIR /build
COPY enclave/tsconfig.json ./enclave/
COPY enclave/src ./enclave/src
# Eight files since 2026-09-22: the patterns, the name stage's word lists and
# the build stamp left redaction.ts and redactionNames.ts for files of their
# own. A file named here and not copied fails tsc, the docker build fails,
# and the old :latest tag builds an identical image -- see the runbook.
# Twelve since 2026-10-04: the scan folding, the field reader and the given
# names. enclave/buildFiles.test.ts fails when one is imported and not here.
COPY cloudflare-worker/redaction.ts cloudflare-worker/redactionMap.ts cloudflare-worker/redactionStructured.ts cloudflare-worker/redactionNames.ts cloudflare-worker/redactionNumbers.ts cloudflare-worker/redactionRestore.ts cloudflare-worker/restoreCore.ts cloudflare-worker/redactionPatterns.ts cloudflare-worker/redactionNameWords.ts cloudflare-worker/redactionBuild.ts cloudflare-worker/redactionFold.ts cloudflare-worker/redactionFields.ts cloudflare-worker/redactionFamous.ts cloudflare-worker/redactionGivenNames.ts cloudflare-worker/redactionWorldGivenNames.ts cloudflare-worker/redactionSurnames.ts cloudflare-worker/redactionNameWordsIntl.ts cloudflare-worker/redactionAddressAsia.ts cloudflare-worker/redactionArabic.ts cloudflare-worker/redactionMoreScripts.ts cloudflare-worker/redactionLearned.ts cloudflare-worker/redactionMedical.ts cloudflare-worker/redactionRecords.ts cloudflare-worker/redactionAddressWorld.ts cloudflare-worker/redactionFamousAlone.ts cloudflare-worker/redactionNameCuesMore.ts cloudflare-worker/redactionThaiGivenNames.ts cloudflare-worker/redactionPhoneContext.ts cloudflare-worker/redactionNameGender.ts cloudflare-worker/redactionRows.ts cloudflare-worker/redactionTowns.ts cloudflare-worker/redactionFamousAliases.ts cloudflare-worker/redactionScriptGivenNames.ts ./cloudflare-worker/
# The envelope the client seals to and the enclave answers under. Shared
# with the clients for the same reason redaction.ts is shared with the
# Worker: two implementations of one wire format drift, and the drift is
# only visible as messages that will not open.
COPY lib/sealedEnvelope.ts ./lib/sealedEnvelope.ts

WORKDIR /build/enclave
RUN npm ci --no-audit --no-fund && npx tsc -p tsconfig.json

# The enclave's memory holds the whole image, so what the name models' runtime
# ships for other machines comes out: GPU providers (CUDA alone is 343 MB),
# macOS, Windows and ARM builds, the browser runtime's source maps and WebGPU
# variant, sharp's musl builds, and the dev dependencies tsc needed above.
RUN npm prune --omit=dev --no-audit --no-fund \
 && cd node_modules/onnxruntime-node/bin/napi-v3 \
 && rm -rf darwin win32 linux/arm64 \
      linux/x64/libonnxruntime_providers_cuda.so linux/x64/libonnxruntime_providers_tensorrt.so \
 && cd /build/enclave/node_modules \
 && find onnxruntime-web/dist -name '*.map' -delete \
 && rm -f onnxruntime-web/dist/*jsep* \
 && rm -rf @img/sharp-linuxmusl-x64 @img/sharp-libvips-linuxmusl-x64

# ---------------------------------------------------------------------------
# The attestation helper.
#
# Talking to /dev/nsm needs the NSM ioctl protocol, which Node cannot speak
# without a native addon. A separate binary keeps the service free of compiled
# dependencies — src/attest.ts spawns it and reads base64 off stdout.
#
# Built on the same Debian release as the runtime image on purpose: a binary
# linked against a different glibc runs on the build machine and fails inside
# the enclave, where there is no way to see why.
FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS nsm
WORKDIR /src
COPY enclave/nsm-cli/Cargo.toml enclave/nsm-cli/Cargo.lock ./
COPY enclave/nsm-cli/src ./src
RUN cargo build --release --locked && strip target/release/nsm-cli

# ---------------------------------------------------------------------------
# The name models (src/localNameModel.ts).
#
# Two small named-entity models, so the enclave finds names itself instead of
# showing the message to Workers AI. Fetched at a pinned revision and checked
# against the hashes below: a model is code as far as PCR0 is concerned, and a
# file that changed upstream must fail the build, not quietly change what a
# verifier is vouching for.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS models
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /models
RUN set -eu; \
  fetch() { mkdir -p "$(dirname "$1/$3")"; curl -fsSL --retry 5 -o "$1/$3" "https://huggingface.co/$1/resolve/$2/$3"; }; \
  for f in config.json tokenizer.json tokenizer_config.json onnx/model_quantized.onnx; do \
    fetch Xenova/bert-base-NER 8e892123e8b7c2c0c2bd1dcb598b7d244c4e53aa "$f"; \
    fetch Xenova/bert-base-multilingual-cased-ner-hrl 263e82c06569c8c2ac46238a7ae5107598934234 "$f"; \
  done; \
  printf '%s\n' \
    "a73a2eccc921bbdea95a94b49a157d3694b5c2abbae7a6f3000e14404a9c31a8  Xenova/bert-base-NER/config.json" \
    "343989712a36cd8b253efeaf8baf6a08b9d2583f78e395e83832e8ee9f8d8ee1  Xenova/bert-base-NER/tokenizer.json" \
    "5be1a180e9badb4811a6c31502d70fb35a085af5457982937419c42d7530bae6  Xenova/bert-base-NER/tokenizer_config.json" \
    "caaee70a5518ec7f9e46e5308fcc9263a8c227703a9ce46cf61c69a552349648  Xenova/bert-base-NER/onnx/model_quantized.onnx" \
    "7aa891abae067f95a40f5e2005b3de44824a083f256802934a993d301ec25076  Xenova/bert-base-multilingual-cased-ner-hrl/config.json" \
    "bf1b59b7b11c95f194f51708d918eea378e09d05f84c0e1656dc5180e8117088  Xenova/bert-base-multilingual-cased-ner-hrl/tokenizer.json" \
    "e6f3b96db926a37d4039995fbf5ad17de158dfb8f6343d607e4dbaad18d75f5a  Xenova/bert-base-multilingual-cased-ner-hrl/tokenizer_config.json" \
    "5b65139844be260b624a2a13782b01d122e613d64ce16ed0ba4d82e0b816f1a9  Xenova/bert-base-multilingual-cased-ner-hrl/onnx/model_quantized.onnx" \
  | sha256sum -c -

# Our own name model (namemodel/) is not in the image (2026-11-13).
#
# Its weights are private, and an image that holds them cannot be rebuilt by
# anyone else, so the image carries only their hashes, enclave/names-model.sha256
# (committed, public), and src/modelFetch.ts fetches the files from the parent
# at boot and keeps each one only if it hashes as listed. Which model runs is
# still fixed by PCR0: a different model is a different list, and a different
# image.
#
# When the list names files, the two Xenova taggers are removed, since
# whichNameModel (src/localNameModel.ts) would never load them and an
# enclave's disk is its memory. An empty list keeps them and runs them.
COPY enclave/names-model.sha256 /stage/names-model.sha256
RUN set -eu; \
  if grep -qE '^[0-9a-f]{64}' /stage/names-model.sha256; then rm -rf /models/Xenova; fi; \
  install -D -m 0644 /stage/names-model.sha256 /out/names-model.sha256; \
  rm -rf /stage

# ---------------------------------------------------------------------------

FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
ARG DEBIAN_SNAPSHOT
# socat is the whole reason there is no AF_VSOCK code in this repo. It bridges
# vsock to loopback at both ends so the service speaks ordinary TCP and the
# trusted computing base gains no native addon.
#
# iproute2 is here for one line: `ip link set dev lo up` in enclave-init.sh.
# An enclave boots with no interfaces at all, so without it nothing can bind to
# 127.0.0.1 and every socat hop fails — but the failure arrives as
# "ip: not found" and the enclave reboots in under a second, which reads as the
# image being broken rather than a package being absent.
#
# From snapshot.debian.org at DEBIAN_SNAPSHOT, so the same versions every
# time. The logs and caches apt and ldconfig leave behind hold the time they
# ran, so they go too.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" > /etc/apt/sources.list \
 && apt-get -o Acquire::Retries=5 update \
 && apt-get install -y --no-install-recommends socat ca-certificates iproute2 \
 && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache /var/cache/debconf/*-old /var/lib/dpkg/*-old

WORKDIR /app
COPY --from=build /build/enclave/dist ./dist
COPY --from=build /build/enclave/node_modules ./node_modules
COPY --from=models /models /app/models
COPY --from=models /out/names-model.sha256 /app/names-model.sha256
COPY --from=nsm /src/target/release/nsm-cli /usr/local/bin/nsm-cli
COPY enclave/scripts/enclave-init.sh /app/enclave-init.sh
RUN chmod +x /app/enclave-init.sh /usr/local/bin/nsm-cli

ENV ENCLAVE=1
ENV NODE_ENV=production
ENTRYPOINT ["/app/enclave-init.sh"]
