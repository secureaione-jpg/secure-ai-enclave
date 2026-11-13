import { Agent, type AgentOptions } from "node:https";
import {
  checkServerIdentity as tlsCheckServerIdentity,
  connect as tlsConnect,
  type ConnectionOptions,
} from "node:tls";

/**
 * Outbound HTTPS from inside the enclave.
 *
 * This is the file the whole security argument rests on, so it is worth being
 * exact about what it does.
 *
 * The enclave has no network. Its only channel is a vsock socket to the parent,
 * and the parent runs AWS's `vsock-proxy`: a relay that accepts a connection on
 * a vsock port and opens a plain TCP connection to one allowlisted host:port.
 * The relay never sees anything but bytes.
 *
 * That is only true if the TLS session is ours. So we connect to a loopback
 * port that socat forwards over vsock, and then perform a full TLS handshake
 * *through* it, against the real provider's certificate. The parent is
 * carrying ciphertext for a session it has no key to.
 *
 * Two things make that work, and both are easy to get subtly wrong:
 *
 *   • `servername` — the SNI we send must be the provider's hostname, not the
 *     loopback address we dialled. Without it the provider has no idea which
 *     certificate to present and the handshake fails or, worse, succeeds
 *     against a default vhost.
 *
 *   • `checkServerIdentity` — Node would otherwise check the certificate
 *     against "127.0.0.1" and reject a perfectly good one. We check it against
 *     the provider's hostname instead. This is emphatically *not* disabling
 *     verification: the chain, the expiry and the hostname are all still
 *     verified, just against the name we actually intended to reach.
 *
 * If you ever find yourself reaching for `rejectUnauthorized: false` in here,
 * stop. That single flag converts this from an enclave into an expensive proxy
 * with a man in the middle by design.
 */

/** One allowlisted destination, and the local port that reaches it. */
export type Upstream = {
  /** The real hostname. Used for SNI and certificate verification. */
  host: string;
  /** Loopback port that socat forwards to the parent's vsock-proxy for `host`. */
  localPort: number;
};

/**
 * Where each provider is reachable.
 *
 * Ports are assigned here and must match both `scripts/enclave-init.sh` (which
 * opens the socat hops) and the parent's `vsock-proxy` allowlist. Three places
 * for one number is two too many; the alternative is service discovery inside
 * a machine with no network, which is worse.
 *
 * 8446 is missing from this table on purpose: it is the config hop back to the
 * parent, not a provider, so Google took 8447 rather than the next free-looking
 * number. Reusing 8446 would have pointed the model at the file holding the
 * keys.
 */
export const UPSTREAMS: Record<string, Upstream> = {
  anthropic: { host: "api.anthropic.com", localPort: 8443 },
  openai: { host: "api.openai.com", localPort: 8444 },
  google: { host: "generativelanguage.googleapis.com", localPort: 8447 },
};

/**
 * Whether to route through the vsock hops at all.
 *
 * Off a laptop there is no parent and no relay, so the same code dials the
 * provider directly. That keeps one code path for both, which matters more
 * than it sounds: a prototype with a separate "local mode" is a prototype
 * whose real mode is untested until the day it has to work.
 */
const IN_ENCLAVE = process.env.ENCLAVE === "1";

const agents = new Map<string, Agent>();

/**
 * An HTTPS agent that reaches `upstream` through the loopback hop while still
 * proving it is talking to the real host.
 */
export function agentFor(upstream: Upstream): Agent {
  const existing = agents.get(upstream.host);
  if (existing) return existing;

  const options: AgentOptions = { keepAlive: true, maxSockets: 16 };
  const agent = new Agent(options);

  if (IN_ENCLAVE) {
    // Replace only the socket-creation step. Everything else about the agent —
    // pooling, keep-alive, HTTP semantics — is stock.
    (agent as unknown as { createConnection: unknown }).createConnection = (
      opts: ConnectionOptions,
      callback: (err: Error | null, socket?: unknown) => void,
    ) => {
      const socket = tlsConnect(
        {
          ...opts,
          host: "127.0.0.1",
          port: upstream.localPort,
          servername: upstream.host,
          checkServerIdentity: (_host, cert) => {
            // Verified against where we meant to go, not where we dialled.
            //
            // Imported at the top rather than required here. This file compiles
            // to a real ES module, where `require` does not exist — so this line
            // threw ReferenceError inside the TLS handshake callback, which node
            // does not treat as a rejected promise: it killed the process, and
            // the enclave rebooted. It survived review because nothing reached
            // it until the name stage was configured, and until then no outbound
            // TLS was ever established.
            return tlsCheckServerIdentity(upstream.host, cert);
          },
        },
        () => callback(null, socket),
      );
      socket.on("error", (err) => callback(err));
      return socket;
    };
  }

  agents.set(upstream.host, agent);
  return agent;
}

/**
 * Fetch, pinned to an allowlisted upstream.
 *
 * Takes a path rather than a URL so a caller cannot accidentally send an
 * enclave request somewhere the allowlist has never heard of — the host is
 * chosen from UPSTREAMS by name and is not something a request body can
 * influence.
 */
export async function upstreamFetch(
  name: keyof typeof UPSTREAMS,
  path: string,
  init: RequestInit,
): Promise<Response> {
  const upstream = UPSTREAMS[name];
  if (!upstream) throw new Error(`No upstream named ${String(name)}`);

  // Node's fetch does not take an agent, so the pinned path uses the classic
  // client. Same request either way; only the socket beneath it differs.
  if (!IN_ENCLAVE) {
    return fetch(`https://${upstream.host}${path}`, init);
  }

  const { request } = await import("node:https");
  return new Promise<Response>((resolve, reject) => {
    const req = request(
      {
        method: init.method ?? "GET",
        path,
        headers: init.headers as Record<string, string>,
        agent: agentFor(upstream),
        host: upstream.host,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve(
            new Response(Buffer.concat(chunks), {
              status: res.statusCode ?? 502,
              headers: Object.fromEntries(
                Object.entries(res.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : String(v ?? "")]),
              ),
            }),
          ),
        );
      },
    );
    req.on("error", reject);
    if (init.body) req.write(init.body);
    req.end();
  });
}

/**
 * The same pinned request, but the body arrives as it is produced.
 *
 * `upstreamFetch` collects the whole response before resolving, which is right
 * for the name stage — a small JSON verdict — and useless for a chat
 * completion. A reply takes several seconds to finish and is read a token at a
 * time; buffering it here would hold every one of them until the last, turning
 * a stream into a pause and then a wall of text.
 *
 * It matters more than presentation. The enclave seals each piece of the reply
 * to the client as it goes (lib/sealedEnvelope.ts), so the shape of what leaves
 * here is the shape the reader sees. Buffering would mean one enormous sealed
 * blob, which is a different product.
 *
 * Resolves as soon as the status and headers are known, so a caller can refuse
 * a 429 without waiting for a body it is going to discard.
 */
export async function upstreamStream(
  name: keyof typeof UPSTREAMS,
  path: string,
  init: RequestInit,
): Promise<Response> {
  const upstream = UPSTREAMS[name];
  if (!upstream) throw new Error(`No upstream named ${String(name)}`);

  // Off the enclave, fetch already streams. One code path for both, for the
  // reason agentFor gives: a local mode that differs from the real one is a
  // real mode nobody has exercised.
  if (!IN_ENCLAVE) {
    return fetch(`https://${upstream.host}${path}`, init);
  }

  const { request } = await import("node:https");
  return new Promise<Response>((resolve, reject) => {
    const req = request(
      {
        method: init.method ?? "GET",
        path,
        headers: init.headers as Record<string, string>,
        agent: agentFor(upstream),
        host: upstream.host,
      },
      (res) => {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            res.on("data", (c: Buffer) => controller.enqueue(new Uint8Array(c)));
            res.on("end", () => controller.close());
            /* An error after the headers have arrived cannot be reported by
               rejecting the promise -- it has already resolved. Erroring the
               stream is what reaches the caller, and it has to reach them:
               a truncated provider response that closes cleanly is
               indistinguishable from a complete one, and the reader would take
               a half-finished answer for a whole one. */
            res.on("error", (err) => controller.error(err));
          },
          cancel() {
            // The reader stopped caring. Nothing is coming back through a
            // socket left open on a machine with no other way to close it.
            res.destroy();
          },
        });

        resolve(
          new Response(body, {
            status: res.statusCode ?? 502,
            headers: Object.fromEntries(
              Object.entries(res.headers).map(([k, v]) => [
                k,
                Array.isArray(v) ? v.join(", ") : String(v ?? ""),
              ]),
            ),
          }),
        );
      },
    );
    req.on("error", reject);
    if (init.body) req.write(init.body);
    req.end();
  });
}
