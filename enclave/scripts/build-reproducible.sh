#!/bin/sh
# Build the enclave image the way anyone checking PCR0 builds it.
#
#   enclave/scripts/build-reproducible.sh [out.eif]
#
# Run from the root of the source (this repo, or the public
# secure-ai-enclave repo, which has the same layout), on Amazon Linux 2023
# with Docker and aws-nitro-enclaves-cli installed. Prints PCR0, PCR1 and
# PCR2; PCR0 is the one the running enclave attests to.
#
# Same source, same tools, same PCR0: the Dockerfile pins what it pulls, and
# this pins what builds it. BuildKit is a fixed version, run in its own
# container (the docker-container driver), and rewrite-timestamp sets every
# file's time to SOURCE_DATE_EPOCH, so nothing in the image says when it was
# built. nitro-cli's own kernel and init are part of PCR0 too, which is why
# the version below is checked rather than assumed.
set -eu

OUT=${1:-enclave.eif}
TAG=secure-ai-enclave:reproducible
BUILDKIT=moby/buildkit:v0.17.3@sha256:b2498ea62630c147e98f96145c2988a74720700b250e4cf7a4328e14f5b99fc3
NITRO_CLI_VERSION=${NITRO_CLI_VERSION:-}

[ -f enclave/Dockerfile ] || { echo "run from the root of the source" >&2; exit 2; }

if [ -n "$NITRO_CLI_VERSION" ] && ! nitro-cli --version | grep -qF "$NITRO_CLI_VERSION"; then
  echo "nitro-cli is $(nitro-cli --version), not $NITRO_CLI_VERSION: PCR0 will differ" >&2
  exit 1
fi

docker buildx inspect sai-repro >/dev/null 2>&1 \
  || docker buildx create --name sai-repro --driver docker-container --driver-opt "image=$BUILDKIT" >/dev/null

docker buildx build --builder sai-repro \
  -f enclave/Dockerfile \
  --build-arg SOURCE_DATE_EPOCH=0 \
  --provenance=false --sbom=false \
  --output "type=docker,name=$TAG,rewrite-timestamp=true" \
  .

export NITRO_CLI_ARTIFACTS=${NITRO_CLI_ARTIFACTS:-${HOME:-/root}/nitro-artifacts}
mkdir -p "$NITRO_CLI_ARTIFACTS"
nitro-cli build-enclave --docker-uri "$TAG" --output-file "$OUT"
