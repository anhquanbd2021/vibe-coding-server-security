import http from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const STATIC_FILES = new Map([
  ['/', ['text/html; charset=utf-8', readFileSync(join(publicDir, 'index.html'))]],
  ['/guide.html', ['text/html; charset=utf-8', readFileSync(join(publicDir, 'guide.html'))]],
  ['/styles.css', ['text/css; charset=utf-8', readFileSync(join(publicDir, 'styles.css'))]],
  ['/app.js', ['text/javascript; charset=utf-8', readFileSync(join(publicDir, 'app.js'))]],
  ['/test-cases.js', ['text/javascript; charset=utf-8', readFileSync(join(publicDir, 'test-cases.js'))]],
]);
const STATIC_HEADERS = {
  'cache-control': 'public, max-age=300',
  'content-security-policy': "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
};


const DEMO_DATA = {
  EXAMPLE_SETTING: 'not-sensitive',
};

// The "product" app. In vulnerable mode it reproduces the CVE-2025-29927
// pattern: requests carrying x-middleware-subrequest skip middleware
// entirely — including the auth check in front of /admin.
// It also naively serves dotfiles, the way a sloppy static config does.
export function createBackend({ hardened = false } = {}) {
  let jobsSpawned = 0;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://backend');

    const forgedHeader =
      req.headers['x-middleware-subrequest'] !== undefined;
    const middlewareSkipped = !hardened && forgedHeader;

    if (!middlewareSkipped && url.pathname.startsWith('/admin')) {
      if (req.headers.cookie !== 'session=ok') {
        res.writeHead(401);
        res.end('unauthorized');
        return;
      }
    }

    if (url.pathname === '/admin') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(DEMO_DATA));
      return;
    }

    if (!hardened && /^\/\.(env|git|ssh|aws|config)/i.test(url.pathname)) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('EXAMPLE_SETTING=not-sensitive\n');
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/job') {
      jobsSpawned += 1; // every request spawns work with no ceiling
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ job: jobsSpawned }));
      return;
    }

    if (url.pathname === '/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        service: 'vibe-coding-server-security',
        commit: process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || 'local',
      }));
      return;
    }

    if (url.pathname === '/health') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('ok');
      return;
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      const asset = STATIC_FILES.get(url.pathname);
      if (asset) {
        res.writeHead(200, { ...STATIC_HEADERS, 'content-type': asset[0] });
        res.end(req.method === 'HEAD' ? undefined : asset[1]);
        return;
      }
    }

    res.writeHead(404);
    res.end('not found');
  });

  server.stats = () => ({ jobsSpawned });
  return server;
}
