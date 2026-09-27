import test from 'node:test';
import assert from 'node:assert/strict';
import { startProduction } from '../app/server.js';

test('production starts only hardened public edge', async () => {
  const previousGit = process.env.GIT_COMMIT;
  const previousRender = process.env.RENDER_GIT_COMMIT;
  process.env.GIT_COMMIT = 'test-commit';
  process.env.RENDER_GIT_COMMIT = 'test-commit';
  const deployment = await startProduction({ port: 0 });
  const base = `http://127.0.0.1:${deployment.edge.address().port}`;
  try {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.deepEqual(await (await fetch(`${base}/version`)).json(), {
      service: 'vibe-coding-server-security',
      commit: 'test-commit',
    });
    const home = await fetch(`${base}/`);
    assert.equal(home.status, 200);
    assert.match(home.headers.get('content-type'), /^text\/html/);
    assert.match(home.headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(await home.text(), /See what the edge stops/);
    const guide = await fetch(`${base}/guide.html`);
    assert.match(await guide.text(), /Server Security Guide/);
    assert.match((await fetch(`${base}/styles.css`)).headers.get('content-type'), /^text\/css/);
    assert.match((await fetch(`${base}/app.js`)).headers.get('content-type'), /^text\/javascript/);
    assert.equal((await fetch(`${base}/missing.js`)).status, 404);

    assert.equal((await fetch(`${base}/admin`, {
      headers: { 'x-middleware-subrequest': 'middleware' },
    })).status, 403);
    assert.equal((await fetch(`${base}/.env`)).status, 404);
    assert.equal((await fetch(`${base}/api/pull`, { method: 'POST' })).status, 404);
    assert.equal((await fetch(base, { headers: { 'user-agent': 'sqlmap/1.7' } })).status, 403);
  } finally {
    await deployment.close();
    if (previousGit === undefined) delete process.env.GIT_COMMIT;
    else process.env.GIT_COMMIT = previousGit;
    if (previousRender === undefined) delete process.env.RENDER_GIT_COMMIT;
    else process.env.RENDER_GIT_COMMIT = previousRender;
  }
});
