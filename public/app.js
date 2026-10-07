import { cases } from '/test-cases.js';

const $ = id => document.getElementById(id);
const flow = [...document.querySelectorAll('#flow li')];
for (const item of cases) {
  const option = document.createElement('option');
  option.value = item.id;
  option.textContent = item.title;
  $('scenario').append(option);
}

const requested = new URLSearchParams(location.search).get('scenario');
if (cases.some(item => item.id === requested)) $('scenario').value = requested;

function selected() { return cases.find(item => item.id === $('scenario').value); }
function paint(item, running = false) {
  flow.forEach((stage, index) => {
    stage.className = index < item.stop ? 'passed' : index === item.stop ? 'blocked' : '';
    stage.style.setProperty('--delay', `${index * 90}ms`);
  });
  $('flow-state').textContent = running ? 'Running' : 'Blocked safely';
  $('flow-state').className = `badge ${running ? 'running' : 'success'}`;
}
function show() {
  const item = selected();
  history.replaceState(null, '', `/?scenario=${item.id}`);
  $('mode').textContent = item.mode;
  $('mode').className = `badge mode-${item.mode}`;
  $('expected').textContent = item.expected;
  $('method').textContent = item.method;
  $('source').textContent = item.source;
  $('request').textContent = item.request;
  $('vulnerable').textContent = item.vulnerable;
  $('hardened').textContent = item.hardened;
  $('control').textContent = item.control;
  $('status').textContent = `Expected ${item.expected}`;
  $('output').textContent = item.mode === 'live' ? 'Ready for one safe live request.' : 'Ready for deterministic replay. No production attack traffic will be sent.';
  $('run').textContent = item.mode === 'live' ? 'Run hardened check' : 'Replay tested result';
  flow.forEach(stage => stage.className = '');
  $('flow-state').textContent = 'Ready';
  $('flow-state').className = 'badge';
}
$('scenario').addEventListener('change', show);
show();

$('run').addEventListener('click', async () => {
  const item = selected();
  paint(item, true);
  $('status').textContent = item.mode === 'live' ? 'Request in flight' : 'Replaying';
  if (item.mode === 'replay') {
    await new Promise(resolve => setTimeout(resolve, 350));
    paint(item);
    $('status').textContent = `${item.expected} expected`;
    $('output').textContent = `REPLAY — isolated local test evidence\n${item.request}\n\n${item.hardened}\nSource: ${item.source}`;
    return;
  }
  try {
    const response = await fetch(item.path, { method: item.method, headers: item.headers || {} });
    const body = await response.text();
    paint(item);
    $('status').textContent = `${response.status} ${response.statusText}`;
    $('output').textContent = `LIVE — hardened deployment\n${item.request}\n\nStatus: ${response.status}\nBody: ${body || '(empty)'}\nExpected: ${item.expected}`;
  } catch {
    $('flow-state').textContent = 'Network error';
    $('flow-state').className = 'badge danger';
    $('status').textContent = 'Network error';
    $('output').textContent = 'Request could not reach the demo service. No attack was attempted.';
  }
});
