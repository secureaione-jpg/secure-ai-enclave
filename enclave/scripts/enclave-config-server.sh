#!/bin/sh
# The parent's config responder, run per-connection by socat.
#
# One request, one JSON object, then close. The enclave asks for this at boot
# because run-enclave passes it no environment — see src/config.ts.
#
# A file rather than an inline socat SYSTEM: string, and that is not a style
# preference. The inline form dropped every vsock connection before a byte
# arrived — the enclave saw "Transport endpoint is not connected" on all four
# retries and refused to start, which reads as a missing responder rather than
# a quoting problem in the one that is running.
#
# The request is drained before answering. A client that is still writing
# headers into a socket whose peer has already exited gets a reset instead of
# the response it is waiting for.
set -e

CONFIG_FILE="${ENCLAVE_CONFIG_FILE:-/etc/secure-ai-enclave/config.json}"

# Read the request head and discard it. Stops at the blank line that ends the
# headers; there is no body to worry about, since the enclave only ever GETs.
while IFS= read -r line; do
  case "$line" in
    ""|$'\r') break ;;
  esac
done

if [ ! -r "$CONFIG_FILE" ]; then
  printf 'HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n'
  exit 0
fi

BODY=$(cat "$CONFIG_FILE")
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
  "${#BODY}" "$BODY"
