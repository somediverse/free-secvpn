/**
 * Parser module with concurrency, TCP reachability, TLS handshake and UDP probe (QUIC-ish) checks.
 * - Uses a concurrency limit (default 50) to run connection probes in parallel.
 * - Performs TCP connect to host:port.
 * - Performs a TLS handshake (tls.connect) when port reachable to verify TLS server is responding.
 * - Performs a UDP probe: send an empty packet and wait for any response (best-effort for UDP/QUIC).
 *
 * NOTE: UDP/QUIC detection is best-effort — QUIC may not respond to an empty UDP packet. This step
 * improves detection for many UDP-capable VPN servers but cannot guarantee 100% for all QUIC servers.
 * upd. Parser module with concurrency, TCP reachability, TLS handshake and UDP probe.
 */

const fetch = require('node-fetch');
const net = require('net');
const tls = require('tls');
const dgram = require('dgram');
const pLimit = require('p-limit');

const PROTOCOL_RE = /^([a-zA-Z0-9+\-.]+):\/\/.*$/s;

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
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
      if (decoded.includes('{') || decoded.includes('://') || decoded.includes('add') || decoded.includes('port')) {
        return decoded;
      }
    } catch (e) {}
  }
  return s;
}

function flattenJsonToUrl(protocol, obj, suffix) {
  const host = obj.add || obj.address || obj.host || obj.ip || obj.server || '';
  const port = obj.port || obj.p || obj.sport || '';
  let userinfo = '';
  if (obj.id || obj.uuid || obj.user) userinfo = obj.id || obj.uuid || obj.user;
  else if (obj.method && obj.password) userinfo = obj.password;
  else if (obj.auth) userinfo = obj.auth;
  let authority = userinfo ? `${userinfo}@` : '';
  authority += host;
  if (port) authority += `:${port}`;
  const q = [];
  const skip = new Set(['add','address','host','ip','server','port','p','id','uuid','user','password','pass','auth','ps']);
  for (const k of Object.keys(obj)) {
    if (skip.has(k)) continue;
    const v = obj[k];
    if (v === null || v === undefined || v === '') continue;
    q.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  const query = q.length ? `?${q.join('&')}` : '';
  const comment = suffix ? ` ${suffix}` : '';
  return `${protocol}://${authority}${query}${comment}`.trim();
}

function checkInsecureFlags(lineLower, jsonObj) {
  if (!lineLower) return false;
  const patterns = ['insecure=1','insecure: 1','allowinsecure=1','skip-cert-verify=true','skip-cert-verify: true','insecure: true','insecure:true'];
  return patterns.some(p => lineLower.includes(p)) ||
         (jsonObj && ['insecure','allowInsecure','skip-cert-verify'].some(k =>
           Object.hasOwn(jsonObj, k) && [true, '1', 1, 'true'].includes(jsonObj[k])
         ));
}

function securityForbidden(lineLower, jsonObj) {
  if (!lineLower) return false;
  const forbidden = ['none', 'auto'];
  const re = /(security|scy|sc)\s*[=:]?\s*([^\s;,&}]+)/i;
  const m = lineLower.match(re);
  if (m && forbidden.includes(m[2].toLowerCase())) return true;
  return jsonObj?.security && forbidden.includes(String(jsonObj.security).toLowerCase());
}

function hasRequiredParam(lineLower, jsonObj) {
  if (!lineLower) return false;
  const ok = v => v && (String(v).toLowerCase().includes('tls') || String(v).toLowerCase().includes('reality') || /-(gcm|poly1305)$/.test(String(v).toLowerCase()));
  const re = /(security|method|cipher|scy|sc|crypt)\s*[=:\"]?\s*([^\s;,&}]+)/i;
  const m = lineLower.match(re);
  if (m && ok(m[2])) return true;
  return ['security','scy','method','cipher'].some(k => jsonObj?.[k] && ok(jsonObj[k]));
}

function portIs443(lineLower, jsonObj) {
  if (!lineLower) return false;
  const m = lineLower.match(/port\s*[=:]?\s*(\d+)/i);
  if (m && m[1] === '443') return true;
  return jsonObj?.port === 443 || jsonObj?.port === '443';
}

function parseHostPortFromNormalized(normalized) {
  try {
    const u = new URL(normalized.replace(/^[a-z]+:\/\//i, 'http://'));
    return { host: u.hostname, port: u.port || '443' };
  } catch {
    return null;
  }
}

function extractCommentSuffix(raw) {
  const i1 = raw.indexOf(' # ');
  if (i1 >= 0) return raw.slice(i1);
  const i2 = raw.lastIndexOf('#');
  return i2 >= 0 && i2 > raw.length - 60 ? raw.slice(i2) : '';
}

// === ФИНАЛЬНАЯ normalizeLine (ИСПРАВЛЕНА) ===
function normalizeLine(protocol, payload, suffix, log) {
  const decoded = decodeBase64IfNeeded(payload) || payload;
  let finalLine = `${protocol}://${decoded}${suffix || ''}`.trim();

  // Попытка JSON
  const jsonStr = decoded.trim();
  if (jsonStr.startsWith('{') && jsonStr.endsWith('}')) {
    const jsonObj = safeJsonParse(jsonStr);
    if (jsonObj) {
      finalLine = flattenJsonToUrl(protocol, jsonObj, suffix);
    }
  }

  return finalLine; // ← ГАРАНТИРОВАННО СТРОКА
}

// === Пробники ===
async function tcpReachable(host, port, timeout = 2000) {
  return new Promise(r => {
    const s = net.createConnection({ host, port }, () => { s.destroy(); r(true); });
    s.setTimeout(timeout, () => { s.destroy(); r(false); });
    s.on('error', () => r(false));
  });
}

async function tlsHandshake(host, port, timeout = 2500) {
  return new Promise(r => {
    const s = tls.connect({ host, port, rejectUnauthorized: false }, () => { s.end(); r(true); });
    s.setTimeout(timeout, () => { s.destroy(); r(false); });
    s.on('error', () => r(false));
  });
}

async function udpProbe(host, port, timeout = 1200) {
  return new Promise(r => {
    const s = dgram.createSocket('udp4');
    const done = ok => { s.close(); r(ok); };
    s.on('message', () => done(true));
    s.on('error', () => done(false));
    try { s.send(Buffer.from([0]), 0, 1, port, host, err => err && done(false)); }
    catch { done(false); }
    setTimeout(() => done(false), timeout);
  });
}

async function probeEndpoint(host, port, log) {
  if (!await tcpReachable(host, port)) { log.push(`TCP closed ${host}:${port}`); return false; }
  log.push(`TCP open ${host}:${port}`);
  if (await tlsHandshake(host, port)) { log.push(`TLS OK ${host}:${port}`); return true; }
  log.push(`TLS failed ${host}:${port}`);
  if (await udpProbe(host, port)) { log.push(`UDP OK ${host}:${port}`); return true; }
  log.push(`UDP failed ${host}:${port}`);
  return false;
}

async function parseSources(sources, { concurrency = 50 } = {}) {
  const results = [], seen = new Set(), log = [], limit = pLimit(concurrency);

  for (const src of sources) {
    log.push(`Fetching ${src}`);
    let text;
    try { text = (await fetch(src)).text(); } catch (e) { log.push(`Fetch error: ${e.message}`); continue; }
    await text;

    const lines = text.split(/\r?\n/);
    let i = 0, tasks = [];

    while (i < lines.length) {
      let line = lines[i++].trim();
      if (!line) continue;
      const m = line.match(PROTOCOL_RE);
      if (!m) continue;

      const protocol = m[1].toLowerCase();
      let rest = m[2];

      // Многострочный JSON
      if ((rest.includes('{') && !rest.includes('}')) || (rest.startsWith('{') && !rest.endsWith('}'))) {
        let depth = 0, block = rest;
        for (const c of block) if (c === '{') depth++; else if (c === '}') depth--;
        while (depth > 0 && i < lines.length) {
          const next = lines[i++];
          block += '\n' + next;
          for (const c of next) if (c === '{') depth++; else if (c === '}') depth--;
        }
        rest = block;
      }

      const suffix = extractCommentSuffix(rest);
      const payload = suffix ? rest.slice(0, rest.indexOf(suffix)).trim() : rest.trim();
      const decodedPayload = decodeURIComponent(payload);

      const normalized = normalizeLine(protocol, decodedPayload, suffix, log);
      const lower = normalized.toLowerCase();

      let jsonObj = null;
      const jsonStart = normalized.indexOf('{');
      if (jsonStart > 0) {
        try { jsonObj = JSON.parse(normalized.slice(jsonStart)); } catch {}
      }

      if (checkInsecureFlags(lower, jsonObj)) { log.push(`Excluded (insecure) -> ${normalized}`); continue; }
      if (securityForbidden(lower, jsonObj)) { log.push(`Excluded (none/auto) -> ${normalized}`); continue; }
      if (!hasRequiredParam(lower, jsonObj)) { log.push(`Excluded (no crypto) -> ${normalized}`); continue; }
      if (!portIs443(lower, jsonObj)) { log.push(`Excluded (port ≠ 443) -> ${normalized}`); continue; }

      const hp = parseHostPortFromNormalized(normalized);
      if (!hp?.host || !hp?.port) { log.push(`Excluded (no host/port) -> ${normalized}`); continue; }

      tasks.push(limit(async () => {
        log.push(`Probing ${hp.host}:${hp.port}`);
        if (await probeEndpoint(hp.host, hp.port, log)) {
          const final = normalized.trim();
          if (!seen.has(final)) { seen.add(final); results.push(final); log.push(`Included -> ${final}`); }
          else log.push(`Duplicate -> ${final}`);
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
