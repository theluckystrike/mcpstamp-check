// Node-only DNS resolver for the host guard: uses the system resolver (the same one Node's fetch
// uses, so /etc/hosts and LAN DNS answers are seen). Pass it as checkServer(url, { resolve: nodeResolve }).
// The Worker does not import this file; it uses DNS-over-HTTPS (makeHostGuard default).
import { lookup } from 'node:dns/promises';

export async function nodeResolve(host) {
  const r = await lookup(host, { all: true, verbatim: true });
  return r.map((x) => x.address);
}
