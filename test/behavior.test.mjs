import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createBackend } from '../app/backend.js';
import { createEdge } from '../app/edge.js';
import { createInternalService } from '../app/internal-service.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

const get = (port, path, headers = {}) =>
  fetch(`http://127.0.0.1:${port}${path}`, { headers });

test('vulnerable: forged x-middleware-subrequest skips auth and leaks /admin', async () => {
  const app = createBackend({ hardened: false });
  const port = await listen(app);
  const res = await get(port, '/admin', { 'x-middleware-subrequest': 'middleware' });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.EXAMPLE_SETTING);
  app.close();
});

test('hardened backend: the same header is ignored, /admin stays 401', async () => {
  const app = createBackend({ hardened: true });
  const port = await listen(app);
  const res = await get(port, '/admin', { 'x-middleware-subrequest': 'middleware' });
  assert.equal(res.status, 401);
  app.close();
});

test('hardened edge: forged header is rejected before reaching the app', async () => {
  const app = createBackend({ hardened: true });
  const backendPort = await listen(app);
  const edge = createEdge({ backendPort });
  const port = await listen(edge);
  const res = await get(port, '/admin', { 'x-middleware-subrequest': 'middleware' });
  assert.equal(res.status, 403);
  app.close();
  edge.close();
});

test('vulnerable: dotfile probe serves secrets', async () => {
  const app = createBackend({ hardened: false });
  const port = await listen(app);
  const res = await get(port, '/.env');
  assert.equal(res.status, 200);
  assert.match(await res.text(), /EXAMPLE_SETTING/);
  app.close();
});

test('hardened edge: dotfile probes return 404', async () => {
  const app = createBackend({ hardened: true });
  const backendPort = await listen(app);
  const edge = createEdge({ backendPort });
  const port = await listen(edge);
  for (const p of ['/.env', '/.git/config', '/.ssh/id_rsa', '/.aws/credentials']) {
    assert.equal((await get(port, p)).status, 404, p);
  }
  app.close();
  edge.close();
});

test('vulnerable: published internal service accepts remote model pulls', async () => {
  const svc = createInternalService();
  const port = await listen(svc);
  const res = await fetch(`http://127.0.0.1:${port}/api/pull`, {
    method: 'POST',
    body: '{"name":"llama3:70b"}',
  });
  assert.equal(res.status, 200);
  assert.equal(svc.state.pulls, 1);
  assert.ok(svc.state.gbBurned >= 40);
  svc.close();
});

test('hardened: internal service has no route through the public edge', async () => {
  const app = createBackend({ hardened: true });
  const backendPort = await listen(app);
  const edge = createEdge({ backendPort });
  const port = await listen(edge);
  const res = await fetch(`http://127.0.0.1:${port}/api/pull`, {
    method: 'POST',
    body: '{"name":"llama3:70b"}',
  });
  assert.equal(res.status, 404);
  app.close();
  edge.close();
});

test('flood: vulnerable app accepts every request; hardened edge caps the burst', async () => {
  const vApp = createBackend({ hardened: false });
  const vPort = await listen(vApp);
  const vCodes = await Promise.all(
    Array.from({ length: 30 }, () =>
      fetch(`http://127.0.0.1:${vPort}/api/job`, { method: 'POST' }).then((r) => r.status)),
  );
  assert.equal(vCodes.filter((c) => c === 200).length, 30);
  assert.equal(vApp.stats().jobsSpawned, 30);

  const hApp = createBackend({ hardened: true });
  const hBackendPort = await listen(hApp);
  const edge = createEdge({ backendPort: hBackendPort, burst: 10 });
  const hPort = await listen(edge);
  const hCodes = await Promise.all(
    Array.from({ length: 30 }, () =>
      fetch(`http://127.0.0.1:${hPort}/api/job`, { method: 'POST' }).then((r) => r.status)),
  );
  assert.ok(hCodes.filter((c) => c === 200).length <= 10);
  assert.ok(hCodes.filter((c) => c === 429).length >= 20);
  assert.ok(hApp.stats().jobsSpawned <= 10);

  vApp.close();
  hApp.close();
  edge.close();
});

test('hardened edge: scanner user-agents are dropped', async () => {
  const app = createBackend({ hardened: true });
  const backendPort = await listen(app);
  const edge = createEdge({ backendPort });
  const port = await listen(edge);
  for (const ua of ['sqlmap/1.7', 'masscan/1.3', 'nuclei - scan']) {
    assert.equal((await get(port, '/', { 'user-agent': ua })).status, 403, ua);
  }
  app.close();
  edge.close();
});

test('hardened edge: legitimate traffic still reaches the app', async () => {
  const app = createBackend({ hardened: true });
  const backendPort = await listen(app);
  const edge = createEdge({ backendPort });
  const port = await listen(edge);
  assert.equal((await get(port, '/health')).status, 200);
  const res = await get(port, '/admin', { cookie: 'session=ok' });
  assert.equal(res.status, 200);
  app.close();
  edge.close();
});
