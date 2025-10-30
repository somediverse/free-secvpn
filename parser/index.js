// parser/index.js
import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import { createConnection } from 'net';

const CONFIG_URL = 'https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt';
const RESULT_FILE = '../vpn_filtered.txt';
const PING_TIMEOUT = 3000;

// ... [весь код parseLine, passesFilters — оставьте БЕЗ ИЗМЕНЕНИЙ] ...

// ---------- TCP-ping (ESM) ----------
function tcpPing(host, port = 443, timeout = PING_TIMEOUT) {
  return new Promise(resolve => {
    const sock = createConnection({ host, port }, () => {
      sock.destroy();
      resolve(true);
    });
    sock.setTimeout(timeout);
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.on('error', () => resolve(false));
  });
}

// ---------- Основная логика ----------
async function run() {
  console.log('Downloading config…');
  const resp = await fetch(CONFIG_URL);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const txt = await resp.text();
  const lines = txt.split('\n').map(l => l.trim());

  const valid = [];
  for (const raw of lines) {
    if (!raw || raw.startsWith('#') || raw.startsWith('---')) continue;
    if (!/^([a-z]+):\/\//i.test(raw)) continue;

    let parsed, uri;
    try { parsed = parseLine(raw); } catch (_) { continue; }
    if (!parsed) continue;
    try { uri = passesFilters(parsed); } catch (_) { continue; }
    if (!uri) continue;

    let host;
    try {
      const u = new URL(uri.replace(/^([a-z]+):\/\//i, 'http://'));
      host = u.hostname;
    } catch (_) { continue; }

    let reachable = false;
    try { reachable = await tcpPing(host); } catch (_) {}
    if (reachable) valid.push(uri);
  }

  await fs.writeFile(RESULT_FILE, valid.join('\n'), 'utf8');
  console.log(`Done! ${valid.length} servers saved.`);
}

run().catch(e => {
  console.error('FATAL:', e.message);
  process.exit(1);
});
