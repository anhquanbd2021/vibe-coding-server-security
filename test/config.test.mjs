import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

const vuln = read('compose/compose.vulnerable.yaml');
const hard = read('compose/compose.hardened.yaml');
const nginx = read('nginx/nginx.hardened.conf');

test('vulnerable stack publishes every internal port (documents the bug)', () => {
  for (const mapping of ['11434:11434', '27017:27017', '6379:6379']) {
    assert.match(vuln, new RegExp(mapping), `expected published ${mapping}`);
  }
});

test('vulnerable stack has no resource ceilings', () => {
  const noComments = vuln.replace(/^\s*#.*$/gm, '');
  assert.doesNotMatch(noComments, /mem_limit|pids_limit|cpus:/);
});

test('hardened stack publishes only 80/443', () => {
  // internal service ports must never appear in a host:container mapping
  for (const port of ['11434', '27017', '6379', '3000']) {
    assert.doesNotMatch(hard, new RegExp(`"${port}:${port}"`), `${port} must not be published`);
    assert.doesNotMatch(hard, new RegExp(`- "${port}:${port}"`), `${port} must not be published`);
  }
  assert.match(hard, /"80:80"/);
  assert.match(hard, /"443:443"/);
});

test('hardened stack keeps internal services on a private network', () => {
  assert.match(hard, /networks:\s*\[internal\]/);
  assert.match(hard, /expose:\s*\n\s*- "11434"/);
});

test('hardened stack sets memory, cpu, and pid ceilings on the app', () => {
  assert.match(hard, /mem_limit:\s*512m/);
  assert.match(hard, /pids_limit:\s*100/);
  assert.match(hard, /cpus:\s*1\.0/);
  assert.match(hard, /read_only:\s*true/);
});

test('nginx edge rejects forged middleware headers (CVE-2025-29927)', () => {
  assert.match(nginx, /if \(\$http_x_middleware_subrequest\)/);
  assert.match(nginx, /proxy_set_header x-middleware-subrequest ""/);
});

test('nginx edge rate-limits and caps connections per IP', () => {
  assert.match(nginx, /limit_req_zone\s+\$binary_remote_addr/);
  assert.match(nginx, /limit_req\s+zone=perip/);
  assert.match(nginx, /limit_conn\s+addr/);
});

test('nginx edge denies dotfile probes and scanner user-agents', () => {
  assert.match(nginx, /location ~\* \/\\\.\(env\|git\|ssh\|aws/);
  assert.match(nginx, /masscan\|zgrab\|zmap\|nmap\|sqlmap/);
});

test('nginx proxies only the web app — no internal service upstreams', () => {
  assert.match(nginx, /proxy_pass http:\/\/web_app/);
  assert.doesNotMatch(nginx, /proxy_pass.*(ollama|mongo|redis)/i);
});


test('public lab catalogs every safe attack case', () => {
  const catalog = read('public/test-cases.js');
  for (const id of ['internal-service', 'middleware-bypass', 'dotfile-probe', 'request-flood', 'scanner']) {
    assert.match(catalog, new RegExp(`id: '${id}'`));
  }
  assert.match(read('public/index.html'), /prefers-reduced-motion|Security pipeline/);
  assert.match(read('public/styles.css'), /prefers-reduced-motion/);
  assert.match(read('public/guide.html'), /Vulnerable outcomes are local fixtures/);
});

