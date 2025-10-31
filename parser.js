/**
 * Parser module with concurrency, TCP reachability, TLS handshake and UDP probe (QUIC-ish) checks.
 * - Uses a concurrency limit (default 50) to run connection probes in parallel.
 * - Performs TCP connect to host:port.
 * - Performs a TLS handshake (tls.connect) when port reachable to verify TLS server is responding.
 * - Performs a UDP probe: send an empty packet and wait for any response (best-effort for UDP/QUIC).
 *
 * NOTE: UDP/QUIC detection is best-effort — QUIC may not respond to an empty UDP packet. This step
 * improves detection for many UDP-capable VPN servers but cannot guarantee 100% for all QUIC servers.
 * upd. Parser module with concurrency, TCP reachability, TLS handshake and UDP
 * updated:
 * - Гарантировано нет undefined.includes
 * - checkInsecureFlags безопасна
 * - normalizeLine всегда возвращает строку
 * - lower определён до фильтров
 */
const fetch = require('node-fetch');
const net = require('net');
const tls = require('tls');
const dgram = require('dgram');
const pLimit = require('p-limit');
const PROTOCOL_RE = /^([a-zA-Z0-9+\-.]+):\/\/.*$/s;
function safeJsonParse(s) {
  if (!s) return null;
  try { return JSON.parse(s); } catch { return null; }
}
function isBase64(str) {
  if (!str || typeof str !== 'string') return false;
  const cleaned = str.split('?')[0].split('#')[0].replace(/[\r\n\s]/g, '');
  return /^[A-Za-z0-9+/=]+$/.test(cleaned) && cleaned.length % 4 === 0;
}
function decodeBase64IfNeeded(s) {
  if (!s) return s;
  if (isBase64(s)) {
    try {
      const decoded = Buffer.from(s, 'base64').toString('utf8');
      if (/[{}]|add|port|:\/\/|security/.test(decoded)) return decoded;
    } catch {}
  }
  return s;
}
function flattenJsonToUrl(protocol, obj, suffix) {
  if (!obj) return `${protocol}://${suffix || ''}`.trim();
  const host = obj.add || obj.address || obj.host || obj.ip || obj.server || '';
  const port = obj.port || obj.p || obj.sport || '';
  const userinfo = obj.id || obj.uuid || obj.user || obj.password || obj.auth || '';
  let authority = userinfo ? `${userinfo}@` : '';
  authority += host;
  if (port) authority += `:${port}`;
  const q = Object.keys(obj)
    .filter(k => !['add','address','host','ip','server','port','p','id','uuid','user','password','pass','auth','ps'].includes(k))
    .filter(k => obj[k] != null && obj[k] !== '')
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(String(obj[k]))}`);
  const query = q.length ? `?${q.join('&')}` : '';
  const comment = suffix ? ` ${suffix}` : '';
  return `${protocol}://${authority}${query}${comment}`.trim();
}
function checkInsecureFlags(inputLine, jsonObj) {
  const lineLower = typeof inputLine === 'string' ? inputLine.toLowerCase() : '';
  if (!lineLower) return false;
  const patterns = [
    'insecure=1', 'insecure: 1', 'allowinsecure=1',
    'skip-cert-verify=true', 'skip-cert-verify: true', 'insecure: true', 'insecure:true'
  ];
  if (patterns.some(p => lineLower.includes(p))) return true;
  if (jsonObj) {
    return ['insecure', 'allowInsecure', 'skip-cert-verify'].some(key => {
      const val = jsonObj[key];
      return val === true || val === 'true' || val === '1' || val === 1;
    });
  }
  return false;
}
function securityForbidden(inputLine, jsonObj) {
  const lineLower = typeof inputLine === 'string' ? inputLine.toLowerCase() : '';
  if (!lineLower) return false;
  const m = lineLower.match(/(security|scy|sc)\s*[=:]?\s*([^\s;,&}]+)/i);
  if (m && m[2] && ['none', 'auto'].includes(m[2].toLowerCase())) return true;
  return jsonObj?.security && ['none', 'auto'].includes(String(jsonObj.security).toLowerCase());
}
function hasRequiredParam(inputLine, jsonObj) {
  const lineLower = typeof inputLine === 'string' ? inputLine.toLowerCase() : '';
  if (!lineLower) return false;
  const ok = v => v && (/tls|reality/.test(v) || /-(gcm|poly1305)$/.test(v));
  const m = lineLower.match(/(security|method|cipher|scy|sc|crypt)\s*[=:\"]?\s*([^\s;,&}]+)/i);
  if (m && m[2] && ok(m[2])) return true;
  return ['security', 'scy', 'method', 'cipher'].some(k => jsonObj?.[k] && ok(String(jsonObj[k]).toLowerCase()));
}
function portIs443(inputLine, jsonObj) {
  const lineLower = typeof inputLine === 'string' ? inputLine.toLowerCase() : '';
  if (!lineLower) return false;
  const m = lineLower.match(/port\s*[=:]?\s*(\d+)/i);
  if (m && m[1] === '443') return true;
  return jsonObj?.port === 443 || jsonObj?.port === '443';
}
function parseHostPortFromNormalized(normalized) {
  if (!normalized) return null;
  try {
    const u = new URL(normalized.replace(/^[a-z]+:\/\//i, 'http://'));
    return { host: u.hostname, port: u.port || '443' };
  } catch { return null; }
}
function extractCommentSuffix(raw) {
  if (!raw) return '';
  
  const i1 = raw.indexOf(' # ');
  if (i1 >= 0) return raw.slice(i1);
  
  const i2 = raw.lastIndexOf('#');
  return i2 >= 0 && i2 > raw.length - 60 ? raw.slice(i2) : '';
}
// === НОРМАЛИЗАЦИЯ (всегда строка) ===
function normalizeLine(protocol, payload, suffix) {
  if (!protocol) return '';
  const decoded = decodeBase64IfNeeded(payload) || payload || '';
  let result = `${protocol}://${decoded}${suffix || ''}`.trim();
  const trimmedDecoded = decoded.trim();
  if (trimmedDecoded && trimmedDecoded.match(/^\{[\s\S]*\}$/)) {
    const jsonObj = safeJsonParse(trimmedDecoded);
    if (jsonObj) result = flattenJsonToUrl(protocol, jsonObj, suffix);
  }
  return result || '';
}
// === ПРОБНИКИ ===
async function tcpReachable(host, port) {
  return new Promise(r => {
    const s = net.createConnection({ host, port }, () => { s.destroy(); r(true); });
    s.setTimeout(2000, () => { s.destroy(); r(false); });
    s.on('error', () => r(false));
  });
}
async function tlsHandshake(host, port) {
  return new Promise(r => {
    const s = tls.connect({ host, port, rejectUnauthorized: false }, () => { s.end(); r(true); });
    s.setTimeout(2500, () => { s.destroy(); r(false); });
    s.on('error', () => r(false));
  });
}
async function udpProbe(host, port) {
  return new Promise(r => {
    const s = dgram.createSocket('udp4');
    const done = ok => { s.close(); r(ok); };
    s.on('message', () => done(true));
    s.on('error', () => done(false));
    try { s.send(Buffer.from([0]), port, host, err => err && done(false)); }
    catch { done(false); }
    setTimeout(() => done(false), 1200);
  });
}
async function probeEndpoint(host, port, log) {
  if (!await tcpReachable(host, port)) { log.push(`TCP closed ${host}:${port}`); return false; }
  log.push(`TCP open ${host}:${port}`);
  if (await tlsHandshake(host, port)) { log.push(`TLS OK ${host}:${port}`); return true; }
  if (await udpProbe(host, port)) { log.push(`UDP OK ${host}:${port}`); return true; }
  return false;
}
// === ОСНОВНАЯ ЛОГИКА ===
async function parseSources(sources, { concurrency = 50 } = {}) {
  const results = [], seen = new Set(), log = [], limit = pLimit(concurrency);
  for (const src of sources) {
    if (!src) continue;
    log.push(`Fetching ${src}`);
    let text;
    try { text = await (await fetch(src)).text(); } catch (e) { log.push(`Fetch error: ${e.message}`); continue; }
    const lines = text ? text.split(/\r?\n/) : [];
    let i = 0, tasks = [];
    while (i < lines.length) {
      let line = lines[i++];
      if (!line) continue;
      line = line.trim();
      if (!line) continue;
      const m = line.match(PROTOCOL_RE);
      if (!m) continue;
      const protocol = m[1] ? m[1].toLowerCase() : '';
      let rest = m[2];
      
      // Проверка на undefined для protocol
      if (!protocol) continue;
      
      // Многострочный JSON
      if (rest && ((rest.includes('{') && !rest.includes('}')) || (rest.trim().startsWith('{') && !rest.trim().endsWith('}')))) {
        let depth = 0, block = rest;
        for (const c of block) if (c === '{') depth++; else if (c === '}') depth--;
        while (depth > 0 && i < lines.length) {
          const next = lines[i++];
          if (!next) continue;
          block += '\n' + next;
          for (const c of next) if (c === '{') depth++; else if (c === '}') depth--;
        }
        rest = block;
      }
      
      // Проверка на undefined для rest
      if (!rest) {
        log.push(`Skipping line due to undefined rest: ${line}`);
        continue;
      }
      
      const suffix = extractCommentSuffix(rest);
      const payload = suffix ? rest.slice(0, rest.indexOf(suffix)).trim() : rest.trim();
      const decodedPayload = decodeURIComponent(payload);
      
      // Проверка на undefined для decodedPayload
      if (decodedPayload === undefined) {
        log.push(`Skipping line due to undefined decodedPayload: ${line}`);
        continue;
      }
      
      // НОРМАЛИЗАЦИЯ
      const normalized = normalizeLine(protocol, decodedPayload, suffix);
      
      // Проверка на undefined для normalized
      if (!normalized) {
        log.push(`Skipping line due to undefined normalized: ${line}`);
        continue;
      }
      
      // JSON
      let jsonObj = null;
      const jsonStart = normalized.indexOf('{');
      if (jsonStart > 0) {
        try { jsonObj = JSON.parse(normalized.slice(jsonStart)); } catch {}
      }
      
      // ФИЛЬТРЫ
      if (checkInsecureFlags(normalized, jsonObj)) { log.push(`Excluded (insecure) -> ${normalized}`); continue; }
      if (securityForbidden(normalized, jsonObj)) { log.push(`Excluded (none/auto) -> ${normalized}`); continue; }
      if (!hasRequiredParam(normalized, jsonObj)) { log.push(`Excluded (no crypto) -> ${normalized}`); continue; }
      if (!portIs443(normalized, jsonObj)) { log.push(`Excluded (port ≠ 443) -> ${normalized}`); continue; }
      const hp = parseHostPortFromNormalized(normalized);
      if (!hp?.host || !hp?.port) { log.push(`Excluded (no host/port) -> ${normalized}`); continue; }
      tasks.push(limit(async () => {
        log.push(`Probing ${hp.host}:${hp.port}`);
        if (await probeEndpoint(hp.host, hp.port, log)) {
          const final = normalized.trim();
          if (!seen.has(final)) {
            seen.add(final);
            results.push(final);
            log.push(`Included -> ${final}`);
          } else {
            log.push(`Duplicate -> ${final}`);
          }
        } else {
          log.push(`Unreachable -> ${normalized}`);
        }
      }));
    }
    await Promise.all(tasks);
    log.push(`Done ${src}`);
  }
  return { results, log };
}
module.exports = { parseSources };
