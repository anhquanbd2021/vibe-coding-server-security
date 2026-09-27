import http from 'node:http';

// Stand-in for Ollama: an internal service with no authentication at all.
// Anyone who can reach the port can order multi-GB model pulls.
export function createInternalService() {
  const state = { pulls: 0, gbBurned: 0, models: [] };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://internal');

    if (req.method === 'POST' && url.pathname === '/api/pull') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        let model = 'unknown';
        try {
          model = JSON.parse(body).name || model;
        } catch { /* keep default */ }
        const sizeGB = 40; // llama3:70b-class model
        state.pulls += 1;
        state.gbBurned += sizeGB;
        state.models.push(model);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: `pulling ${model}`, simulatedGB: sizeGB }));
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/tags') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ models: state.models, gbBurned: state.gbBurned }));
      return;
    }

    res.writeHead(404);
    res.end('not found');
  });

  server.state = state;
  return server;
}
