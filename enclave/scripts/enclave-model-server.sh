#!/bin/sh
# The parent's model responder, run per connection by socat (parent-up.sh).
#
# Answers GET /<path> with one file of our own name model, from
# ENCLAVE_MODEL_DIR (/etc/secure-ai-enclave/names-model, root-only). Only the
# files named in names-model.sha256 are served, so the request line cannot be
# used to read anything else on the parent. The enclave hashes what it gets
# (src/modelFetch.ts); this script is not trusted to send the right bytes,
# only to send some.
set -e

MODEL_DIR="${ENCLAVE_MODEL_DIR:-/etc/secure-ai-enclave/names-model}"
LIST="$(dirname "$0")/../names-model.sha256"

read -r method path _ || exit 0
# Drain the headers, as the config responder does, so the client is not reset
# while it is still writing.
while IFS= read -r line; do
  case "$line" in ""|"$(printf '\r')") break ;; esac
done

want=${path#/}
if [ "$method" != "GET" ] || ! grep -v '^#' "$LIST" | awk '{ f = $2; sub(/^\*/, "", f); print f }' | grep -qxF "$want" \
  || [ ! -r "$MODEL_DIR/$want" ]; then
  printf 'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
  exit 0
fi

size=$(wc -c < "$MODEL_DIR/$want" | tr -d ' ')
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' "$size"
cat "$MODEL_DIR/$want"
