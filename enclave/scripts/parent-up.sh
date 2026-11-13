#!/bin/bash
# Runs on the parent EC2 instance, after the enclave is up.
#
# The parent is not trusted and does not need to be. Everything it carries in
# either direction is either a request it is relaying or TLS it cannot read.
#
#   ./parent-up.sh <ENCLAVE_CID>
#
# The CID is printed by `nitro-cli run-enclave` and is 16 by default in
# scripts/run.sh.
set -euo pipefail

CID="${1:-16}"

# ── Outbound relays ────────────────────────────────────────────────────────
# vsock-proxy ships with nitro-cli. It listens on a vsock port and opens a
# plain TCP connection to one allowlisted host, and that is all it does — it
# has no view into the bytes, which is what makes it safe to run out here.
vsock-proxy 8001 api.anthropic.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
vsock-proxy 8002 api.openai.com    443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
vsock-proxy 8005 generativelanguage.googleapis.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &

# ── Configuration responder ────────────────────────────────────────────────
# The enclave asks for its settings here at boot, because run-enclave gives it
# no environment to read them from. The secret stays on the parent's disk,
# root-only, and never enters the image — so PCR0 stays free of it and the EIF
# stays publishable.
#
# A shell script behind socat rather than a service: it answers one request
# with one JSON object and has no state, and anything larger would be a second
# thing to keep running.
CONFIG_FILE="${ENCLAVE_CONFIG_FILE:-/etc/secure-ai-enclave/config.json}"
if [ ! -r "$CONFIG_FILE" ]; then
  echo "parent-up: no config at $CONFIG_FILE — the enclave will refuse to start." >&2
  echo "  Create it with CF_ACCOUNT_ID and CF_AI_TOKEN; see enclave/RUNBOOK.md." >&2
fi
socat VSOCK-LISTEN:8004,fork,reuseaddr \
  EXEC:"$(dirname "$0")/enclave-config-server.sh" &

# ── Model responder ────────────────────────────────────────────────────────
# Our own name model's files, which the image no longer carries (the weights
# are private and the image is rebuilt in public). The enclave checks each
# file against the hashes in its image, so this responder is trusted with
# nothing: a wrong file is a refused start, not a different model.
MODEL_DIR="${ENCLAVE_MODEL_DIR:-/etc/secure-ai-enclave/names-model}"
if [ ! -r "$MODEL_DIR/onnx/model_quantized.onnx" ]; then
  echo "parent-up: no model at $MODEL_DIR — an image built for our own model will refuse to start." >&2
fi
socat VSOCK-LISTEN:8006,fork,reuseaddr \
  EXEC:"$(dirname "$0")/enclave-model-server.sh" &

# ── Inbound relay ──────────────────────────────────────────────────────────
# Requests arrive on 9000 and go to the enclave. Bound to loopback on purpose:
# ingress is a Cloudflare Tunnel started separately, so this port is never
# exposed to the internet and the instance needs no inbound security group rule
# at all.
socat TCP-LISTEN:9000,fork,reuseaddr,bind=127.0.0.1 VSOCK-CONNECT:"${CID}":5000 &

echo "parent relays up; enclave CID ${CID}"
echo "point a Cloudflare Tunnel at http://127.0.0.1:9000"
wait
