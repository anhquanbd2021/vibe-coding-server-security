export const cases = [
  {
    id: 'internal-service', title: 'Exposed internal AI service', mode: 'live', method: 'POST', path: '/api/pull', expected: 404, stop: 5,
    request: 'POST :11434/api/pull { "name": "llama3:70b" }',
    vulnerable: '200 — unauthenticated model pull accepted; simulated 40 GB consumed.',
    hardened: '404 — no public route reaches internal AI service.',
    control: 'Publish only edge ports. Keep model, database, and cache services on private networks.',
    source: 'test/behavior.test.mjs · compose/compose.hardened.yaml'
  },
  {
    id: 'middleware-bypass', title: 'Forged middleware header', mode: 'live', method: 'GET', path: '/admin', expected: 403, stop: 1,
    headers: { 'x-middleware-subrequest': 'middleware' },
    request: 'GET /admin + x-middleware-subrequest: middleware',
    vulnerable: '200 — middleware skipped and protected fixture returned.',
    hardened: '403 — edge rejects forged header before application code.',
    control: 'Patch affected frameworks, reject header at edge, and keep authorization inside trusted handlers.',
    source: 'test/behavior.test.mjs · nginx/nginx.hardened.conf'
  },
  {
    id: 'dotfile-probe', title: 'Dotfile probe', mode: 'live', method: 'GET', path: '/.env', expected: 404, stop: 1,
    request: 'GET /.env',
    vulnerable: '200 — unsafe static configuration serves a fixture setting.',
    hardened: '404 — edge denies sensitive dotfile paths.',
    control: 'Use explicit static roots and deny hidden configuration, VCS, SSH, and cloud credential paths.',
    source: 'test/behavior.test.mjs · nginx/nginx.hardened.conf'
  },
  {
    id: 'request-flood', title: 'Unbounded job flood', mode: 'replay', method: 'POST', path: '/api/job', expected: 429, stop: 3,
    request: 'POST /api/job × 30',
    vulnerable: '30/30 accepted — every request spawns simulated work.',
    hardened: '9 accepted, 21 rate-limited — deterministic replay of tested burst policy.',
    control: 'Apply request and connection limits plus CPU, memory, and PID ceilings.',
    source: 'test/behavior.test.mjs · test/config.test.mjs'
  },
  {
    id: 'scanner', title: 'Known scanner traffic', mode: 'replay', method: 'GET', path: '/', expected: 403, stop: 1,
    request: 'GET / + User-Agent: sqlmap/1.7',
    vulnerable: '200 — scanner reaches application.',
    hardened: '403 — deterministic replay; browsers cannot set User-Agent.',
    control: 'Drop obvious automation at edge, while treating signatures as noise reduction—not authentication.',
    source: 'test/behavior.test.mjs · app/edge.js'
  }
];
