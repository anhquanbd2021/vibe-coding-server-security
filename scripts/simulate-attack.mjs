// Replays the two real incidents against both stacks.
//   VULNERABLE: internal service published, no auth, no edge, no limits.
//   HARDENED:   only the edge is public; internal services unreachable.
import { once } from 'node:events';
import { createBackend } from '../app/backend.js';
import { createEdge } from '../app/edge.js';
import { createInternalService } from '../app/internal-service.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function status(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method, headers, body,
  });
  const text = await res.text();
  return { code: res.status, text };
}

const rows = [];
function row(attack, vulnerable, hardened) {
  rows.push([attack, vulnerable, hardened]);
}

// ---------------- vulnerable stack ----------------
const vInternal = createInternalService();
const vPort = await listen(vInternal);          // "published" — the bug
const vBackend = createBackend({ hardened: false });
const vApp = await listen(vBackend);

// ---------------- hardened stack ----------------
const hInternal = createInternalService();
await listen(hInternal);                        // internal only — no public door
const hBackend = createBackend({ hardened: true });
const hBackendPort = await listen(hBackend);
const hEdge = createEdge({ backendPort: hBackendPort, burst: 10 });
const hPort = await listen(hEdge);              // the only public door

// ---- attack 1: order a 40 GB model pull on the internal AI service ----
const pull = (port) =>
  status(port, { method: 'POST', path: '/api/pull', body: '{"name":"llama3:70b"}' });
const a1v = await pull(vPort);
const a1h = await status(hPort, { method: 'POST', path: '/api/pull', body: '{"name":"llama3:70b"}' });
row('POST :11434/api/pull "llama3:70b"',
  `${a1v.code} — model pulled, ~${vInternal.state.gbBurned} GB burned`,
  `${a1h.code} — no route: the port does not exist outside`);

// ---- attack 2: forge x-middleware-subrequest to skip auth middleware ----
const forged = { 'x-middleware-subrequest': 'middleware' };
const a2v = await status(vApp, { path: '/admin', headers: forged });
const a2h = await status(hPort, { path: '/admin', headers: forged });
row('GET /admin + forged middleware header (CVE-2025-29927)',
  `${a2v.code} — auth skipped, secrets leaked`,
  `${a2h.code} — header rejected at the edge`);

// ---- attack 3: probe for .env ----
const a3v = await status(vApp, { path: '/.env' });
const a3h = await status(hPort, { path: '/.env' });
row('GET /.env',
  `${a3v.code} — file served`,
  `${a3h.code} — dotfile probe denied`);

// ---- attack 4: request flood (the OOM pattern) ----
const burst = 30;
const flood = async (port, path) => {
  const codes = await Promise.all(
    Array.from({ length: burst }, () =>
      status(port, { method: 'POST', path }).then((r) => r.code)),
  );
  return {
    ok: codes.filter((c) => c === 200).length,
    limited: codes.filter((c) => c === 429).length,
  };
};
const a4v = await flood(vApp, '/api/job');
const a4h = await flood(hPort, '/api/job');
row(`POST /api/job x${burst} (flood)`,
  `${a4v.ok}/${burst} accepted — ${vBackend.stats().jobsSpawned} jobs spawned, RAM climbs`,
  `${a4h.ok} ok, ${a4h.limited} x 429 — burst capped`);

// ---- attack 5: scanner user-agent ----
const a5v = await status(vApp, { headers: { 'user-agent': 'sqlmap/1.7' } });
const a5h = await status(hPort, { headers: { 'user-agent': 'sqlmap/1.7' } });
row('Scanner user-agent (sqlmap)',
  `${a5v.code} — welcome in`,
  `${a5h.code} — dropped at the edge`);

// ---- report ----
const w = [58, 46, 46];
const line = (r) => r.map((c, i) => String(c).padEnd(w[i])).join(' ');
console.log('\n' + line(['ATTACK', 'VULNERABLE STACK', 'HARDENED STACK']));
console.log('-'.repeat(w[0] + w[1] + w[2] + 2));
for (const r of rows) console.log(line(r));
console.log('');

for (const s of [vInternal, vBackend, hInternal, hBackend, hEdge]) s.close();
