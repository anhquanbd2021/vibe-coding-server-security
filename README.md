# Vibe-coded VPS, visited twice — companion demo

Recreates the two incidents from the article on localhost, then proves the
hardened stack closes the same doors. Zero dependencies — Node 20+ only.

- **Incident 1**: an internal AI service (Ollama stand-in) published on
  `11434` with no auth — bots ordered multi-GB model pulls.
- **Incident 2**: `x-middleware-subrequest` skipped auth middleware
  (the CVE-2025-29927 pattern), dotfile probes, and a request flood that
  spawned work until the host ran out of memory.

## Two stacks

| | `compose/compose.vulnerable.yaml` | `compose/compose.hardened.yaml` |
|---|---|---|
| Public ports | `3000`, `11434`, `27017`, `6379` | `80`, `443` only |
| Internal services | published on the host IP | `expose:` on a private network |
| Resource limits | none | `mem_limit` / `cpus` / `pids_limit` |
| Edge protection | none | `nginx/nginx.hardened.conf`: rate limit, conn cap, dotfile denylist, scanner-UAs drop, `x-middleware-subrequest` rejected |

## Run it

```text
npm run simulate    # replays all 5 attacks against both stacks
npm test            # config + behavior assertions
npm run check       # both
```

`scripts/simulate-attack.mjs` boots both stacks on localhost and prints a
side-by-side table: every attack that succeeds on the vulnerable stack is
blocked on the hardened one.

## Optional: real containers

```text
docker compose -f compose/compose.hardened.yaml up
```

The vulnerable compose file exists so the diff is visible. It is
intentionally insecure — do not deploy it, and never run it on a host with
a public IP.

## Design limits

- Localhost cannot emulate Docker network namespaces, so `app/edge.js`
  stands in for Nginx and the "internal-only" property is asserted in the
  compose files (`test/config.test.mjs`) plus proven at the edge: there is
  simply no route to internal services through the public door.
- Secrets in `app/backend.js` are fake fixtures. The flooder payload and
  process explosion are simulated as counters — the point is which
  requests get through, not real resource exhaustion.

## Live hardened deployment

Render runs only `app/server.js`: a hardened backend on loopback behind the
public filtering edge. The vulnerable stack and internal-service simulator are
source/test fixtures and are never started in production.

- Health: `/health`
- Version: `/version`
- Blueprint: `render.yaml`


## Interactive web lab

The root page now presents all five attack cases as an accessible request-flow
visualization. Safe checks run against the hardened deployment; flood and
browser-restricted user-agent cases are clearly labeled deterministic replays.

- Lab: `/`
- Detailed guide: `/guide.html`
- Scenario presets: `/?scenario=internal-service`, `middleware-bypass`,
  `dotfile-probe`, `request-flood`, or `scanner`


- This is an educational demo, not production infrastructure.
