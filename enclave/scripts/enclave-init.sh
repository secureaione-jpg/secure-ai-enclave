#!/bin/sh
# Runs as PID 1 inside the enclave.
#
# Three jobs, in order: give the kernel a loopback interface, open the socat
# hops in both directions, then hand over to the service.
#
# Ports here are matched in two other places — src/outbound.ts, which dials
# them, and scripts/parent-up.sh, which answers them. Three copies of one
# number is two too many, and the alternative is service discovery on a machine
# with no network, which is worse. Change one, change all three.
set -e

# An enclave boots with no interfaces at all. Without this, nothing can bind to
# 127.0.0.1 and every socat hop below fails with a message that does not say so.
ip link set dev lo up

# ── Inbound: parent → enclave ──────────────────────────────────────────────
# The parent connects to vsock port 5000; requests come out on loopback 8000,
# which is where the Node service is listening.
socat VSOCK-LISTEN:5000,fork,reuseaddr TCP:127.0.0.1:8000 &

# ── Outbound: enclave → provider ───────────────────────────────────────────
# Each provider gets a loopback port that forwards to a vsock port on the
# parent (CID 3), where a vsock-proxy relays it to the allowlisted host.
#
# The relay is a dumb TCP pipe. TLS is established end to end from in here to
# the provider's real certificate — see src/outbound.ts — so what crosses the
# parent is ciphertext for a session it has no key to. That property is the
# entire point; nothing in this file may terminate TLS.
socat TCP-LISTEN:8443,fork,reuseaddr,bind=127.0.0.1 VSOCK-CONNECT:3:8001 &   # api.anthropic.com
socat TCP-LISTEN:8444,fork,reuseaddr,bind=127.0.0.1 VSOCK-CONNECT:3:8002 &   # api.openai.com
socat TCP-LISTEN:8447,fork,reuseaddr,bind=127.0.0.1 VSOCK-CONNECT:3:8005 &   # generativelanguage.googleapis.com

# ── Configuration: enclave → parent ────────────────────────────────────────
# run-enclave passes no environment, so the settings this service needs are
# fetched from the parent at boot instead. See src/config.ts, which explains
# why the two obvious alternatives — baking the token or the escape hatch into
# the image — are both worse than one more socat line.
socat TCP-LISTEN:8446,fork,reuseaddr,bind=127.0.0.1 VSOCK-CONNECT:3:8004 &   # config

# ── Our own name model: enclave → parent ───────────────────────────────────
# The weights are private, so they are not in the image; the image carries
# their hashes and src/modelFetch.ts checks every file it is sent here.
socat TCP-LISTEN:8448,fork,reuseaddr,bind=127.0.0.1 VSOCK-CONNECT:3:8006 &   # model


exec node /app/dist/enclave/src/server.js
