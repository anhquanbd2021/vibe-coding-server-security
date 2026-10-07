import http from 'node:http';

// Minimal stand-in for the hardened Nginx layer. Everything the real
// nginx.hardened.conf does at the edge, expressed in Node so the demo
// runs without Docker:
//   - reject forged x-middleware-subrequest headers (CVE-2025-29927)
//   - deny dotfile / secrets probes
//   - drop known scanner user-agents
//   - per-IP rate limit
//   - proxy only the web app — internal services are unreachable here
const DENY_PATH = /^\/\.(env|git|ssh|aws|npm|config|docker|svn|hg)/i;
const SCANNER_UA = /(masscan|zgrab|zmap|nmap|sqlmap|nikto|acunetix|nuclei)/i;

export function createEdge({ backendPort, burst = 10, windowMs = 1000 } = {}) {
  const buckets = new Map();

  const server = http.createServer((req, res) => {
    if (req.headers['x-middleware-subrequest'] !== undefined) {
      res.writeHead(403);
      res.end('blocked: forged middleware header');
      return;
    }
    if (DENY_PATH.test(req.url || '')) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    if (SCANNER_UA.test(req.headers['user-agent'] || '')) {
      res.writeHead(403);
      res.end('blocked: scanner');
      return;
    }

    const ip = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let b = buckets.get(ip);
    if (!b || now > b.reset) b = { count: 0, reset: now + windowMs };
    b.count += 1;
    buckets.set(ip, b);
    if (b.count > burst) {
      res.writeHead(429, { 'retry-after': '1' });
      res.end('rate limited');
      return;
    }

    const proxy = http.request(
      {
        host: '127.0.0.1',
        port: backendPort,
        path: req.url,
        method: req.method,
        headers: { ...req.headers, host: 'web' },
      },
      (up) => {
        res.writeHead(up.statusCode || 502, up.headers);
        up.pipe(res);
      },
    );
    proxy.on('error', () => {
      res.writeHead(502);
      res.end('bad gateway');
    });
    req.pipe(proxy);
  });

  return server;
}
