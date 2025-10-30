// ==== parser/index.js ====
import fetch from 'node-fetch';
import { JSDOM } from 'jsdom';
import { promises as fs } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const net = require('net');   // встроенный модуль

// ---------- Конфигурация ----------
const CONFIG_URL = 'https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt';
const RESULT_FILE = '../vpn_filtered.txt';
const PING_TIMEOUT = 3000;   // ms
const BATCH_SIZE = 10;

// ---------- Base64 ----------
const decodeBase64 = s => {
  try { return Buffer.from(s, 'base64').toString('utf8'); }
  catch { return null; }
};
const encodeBase64 = s => Buffer.from(s, 'utf8').toString('base64');

// ---------- Парсер строки (тот же, что в HTML) ----------
function parseLine(line) {
  const m = line.match(/^([a-z]+):\/\/(.*)$/i);
  if (!m) return null;
  const protocol = m[1].toLowerCase();
  let payload = m[2];
  const original = line;

  const commentMatch = original.match(/(\s+#.*)$/);
  const comment = commentMatch ? commentMatch[1] : '';

  const params = {};
  let finalUri = original;
  let decoded = false;

  // порт из URI
  const portM = original.match(/:(\d+)(?:[/?#]|$)/);
  if (portM) params.port = portM[1];

  // query‑параметры
  const qM = original.match(/\?(.+)$/);
  if (qM) {
    qM[1].split('&').forEach(p => {
      const [k, v] = p.split('=');
      try { params[k] = decodeURIComponent(v || ''); }
      catch { params[k] = v || ''; }
    });
  }

  // JSON‑payload
  const jsonM = payload.match(/^\{([\s\S]*)\}$/);
  if (jsonM) {
    try {
      const cfg = JSON.parse(jsonM[1]);
      params.security = cfg.scy || cfg.security || cfg.tls;
      params.method   = cfg.method || cfg.aid;
      params.cipher   = cfg.cipher;
      params.port     = cfg.port || params.port;
      params.insecure = cfg['skip-cert-verify'] || cfg.insecure;

      const b64 = encodeBase64(JSON.stringify(cfg));
      if (b64) { finalUri = `${protocol}://${b64}${comment}`; decoded = true; }
    } catch (_) {}
  }

  // Base64‑payload
  const b64M = payload.match(/^([A-Za-z0-9+/=]+)@(.*)$/);
  if (b64M) {
    const b64Str = b64M[1];
    const rest   = b64M[2];
    const dec    = decodeBase64(b64Str);
    if (dec) {
      try {
        const cfg = JSON.parse(dec);
        params.security = cfg.security || cfg.tls || cfg.scy;
        params.method   = cfg.method   || cfg.aid;
        params.cipher   = cfg.cipher;
        params.port     = cfg.port || params.port;
        params.insecure = cfg.skipCertVerify || cfg.insecure;
        const b64 = encodeBase64(JSON.stringify(cfg));
        if (b64) { finalUri = `${protocol}://${b64}${comment}`; decoded = true; }
      } catch (_) {
        const parts = dec.split(':');
        if (parts.length === 2) {
          const [cipher] = parts;
          params.cipher = cipher;
          const b64 = encodeBase64(dec);
          if (b64) {
            const hostPort = rest.split(' ')[0];
            finalUri = `${protocol}://${b64}@${hostPort}${comment}`;
            decoded = true;
          }
        }
      }
    }
  }

  return { protocol, params, originalLine: original, finalUri, isDecoded: decoded };
}

// ---------- Фильтры ----------
function passesFilters(data) {
  const p = {};
  for (const k in data.params) {
    const lk = k.toLowerCase();
    if (lk === 'scy') p.security = data.params[k];
    else if (lk === 'method') p.method = data.params[k];
    else if (lk === 'cipher') p.cipher = data.params[k];
    else if (lk === 'insecure' || lk === 'skip-cert-verify') p[lk] = data.params[k];
    else if (lk === 'port') p.port = data.params[k];
    else p[lk] = data.params[k];
  }

  const ok = v => typeof v === 'string' && (
    v.toLowerCase() === 'tls' ||
    v.toLowerCase() === 'reality' ||
    v.endsWith('-gcm') ||
    v.endsWith('-poly1305')
  );

  const hasCrypto = (p.security && ok(p.security)) ||
                    (p.method   && ok(p.method))   ||
                    (p.cipher   && ok(p.cipher));
  if (!hasCrypto) return false;

  if (p.port && p.port !== '443') return false;

  if (p.security && ['none','auto'].includes(p.security.toLowerCase())) return false;
  if (p.insecure === true || p.insecure === 'true' || p.insecure === 1) return false;
  if (p['skip-cert-verify'] === true || p['skip-cert-verify'] === 'true' || p['skip-cert-verify'] === 1) return false;

  return data.finalUri;
}

// ---------- TCP‑ping ----------
function tcpPing(host, port = 443, timeout = PING_TIMEOUT) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host, port }, () => {
      socket.end();
      resolve(true);
    });
    socket.setTimeout(timeout);
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => { resolve(false); });
  });
}

// ---------- Основная логика ----------
async function run() {
  console.log('Downloading config…');
  const resp = await fetch(CONFIG_URL);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const txt = await resp.text();
  const lines = txt.split('\n');

  const valid = [];
  for (let i = 0; i < lines.length; i += BATCH_SIZE) {
    const batch = lines.slice(i, i + BATCH_SIZE);
    await Promise.all(batch.map(async raw => {
      raw = raw.trim();
      if (!raw || raw.startsWith('#') || raw.startsWith('---')) return;
      if (!/^([a-z]+):\/\//i.test(raw)) return;

      const parsed = parseLine(raw);
      if (!parsed) return;
      const uri = passesFilters(parsed);
      if (!uri) return;

      // извлекаем хост
      let host;
      try {
        const u = new URL(uri.replace(/^([a-z]+):\/\//i, 'http://')); // любой протокол
        host = u.hostname;
      } catch (_) { return; }

      const ok = await tcpPing(host);
      if (ok) valid.push(uri);
    }));
    await new Promise(r => setTimeout(r, 50)); // небольшая пауза
  }

  const result = valid.join('\n');
  await fs.writeFile(RESULT_FILE, result, 'utf8');
  console.log(`Done! ${valid.length} servers saved to ${RESULT_FILE}`);
}

run().catch(e => {
  console.error(e);
  process.exit(1);
});
