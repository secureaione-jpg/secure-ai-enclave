#!/bin/sh
# Copy what the enclave image is built from into a folder of its own, for the
# public repository (github.com/secureaione-jpg/secure-ai-enclave).
#
#   enclave/scripts/export-public.sh <folder>
#
# Exactly the build context: enclave/ (its source, Dockerfile and scripts),
# the redaction files the Dockerfile copies from cloudflare-worker/, and
# lib/sealedEnvelope.ts, in the same layout, so the same Dockerfile and
# build-reproducible.sh run unchanged there. Plus enclave/PUBLIC-README.md as
# the README. Not the runbook (it is how we operate our account, not how the
# image is made), not the model's weights (private; only their hashes, which
# the image carries), not node_modules or build output.
set -eu
dst=${1:?usage: export-public.sh <folder>}
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

# The worker files, read off the Dockerfile's own COPY line, so the two cannot
# disagree.
worker=$(grep '^COPY cloudflare-worker/' enclave/Dockerfile | tr ' ' '\n' | grep '^cloudflare-worker/')

mkdir -p "$dst"
find "$dst" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
git ls-files enclave | grep -v -e '^enclave/RUNBOOK.md$' -e '^enclave/buildFiles.test.ts$' -e '^enclave/PUBLIC-README.md$' -e '^enclave/RELEASES.md$' \
  | while read -r f; do mkdir -p "$dst/$(dirname "$f")"; cp -p "$f" "$dst/$f"; done
for f in $worker lib/sealedEnvelope.ts; do mkdir -p "$dst/$(dirname "$f")"; cp -p "$f" "$dst/$f"; done
cp enclave/PUBLIC-README.md "$dst/README.md"
cp enclave/RELEASES.md "$dst/RELEASES.md"
git rev-parse HEAD > "$dst/SOURCE_COMMIT"
echo "exported $(find "$dst" -type f ! -path '*/.git/*' | wc -l | tr -d ' ') files to $dst"
