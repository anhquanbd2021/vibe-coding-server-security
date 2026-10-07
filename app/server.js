import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createBackend } from './backend.js';
import { createEdge } from './edge.js';

export async function startProduction({ port = Number(process.env.PORT) || 3000 } = {}) {
  const backend = createBackend({ hardened: true });
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');

  const edge = createEdge({ backendPort: backend.address().port });
  edge.listen(port, '0.0.0.0');
  await once(edge, 'listening');

  const close = async () => {
    await Promise.all([backend, edge].map(server => new Promise(resolve => server.close(resolve))));
  };
  return { backend, edge, close };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const deployment = await startProduction();
  console.log(`Hardened demo listening on ${deployment.edge.address().port}`);
  const shutdown = async () => {
    await deployment.close();
    process.exit(0);
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
