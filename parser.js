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
  const maybe = str.split('?')[0].split('#')[0];
  const cleaned = maybe.replace(/[\r\n\s]/g, '');
  return /^[A-Za-z0-9+/=]+$/.test(cleaned) && cleaned.length % 4 === 0;
}

function decodeBase64IfNeeded(s) {
  if (!s) return s;
  if (isBase64(s)) {
    try {
      const buf = Buffer.from(s, 'base64');
      const decoded = buf.toString('utf8');
      if (decoded.includes('{') || decoded.includes('://') || decoded.includes('add') || decoded.includes('port')) {
        return decoded;
      }
    } catch (e) {}
  }
  return s;
}

function flattenJsonToUrl(protocol, obj, originalSuffix) {
  const host = obj.add || obj.address || obj.host || obj.ip || obj.server || '';
  const port = obj.port || obj.p || obj.sport || '';
  let userinfo = '';
  if (obj.id || obj.uuid || obj.user) userinfo = obj.id || obj.uuid || obj.user;
  else if (obj.method && obj.password) userinfo = obj.password;
  else if (obj.auth) userinfo = obj.auth;
  let authority = '';
  if (userinfo) authority = `${userinfo}@`;
  authority += host || '';
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
  const comment = originalSuffix ? ` ${originalSuffix}` : '';
  return `${protocol}://${authority}${query}${comment}`.trim();
}

function checkInsecureFlags(lineLower, jsonObj) {
  if (!lineLower) return false;
  const insecurePatterns = ['insecure=1','insecure: 1','allowinsecure=1','skip-cert-verify=true','skip-cert-verify: true','insecure: true','insecure:true'];
  for (const p of insecurePatterns) if (lineLower.includes(p)) return true;
  if (jsonObj) {
    const bad = ['insecure','allowInsecure','skip-cert-verify'];
    for (const k of bad) {
      if (Object.prototype.hasOwnProperty.call(jsonObj, k)) {
        const v = jsonObj[k];
        if (v === true || v === '1' || v === 1 || String(v) === 'true') return true;
      }
    }
  }
  return false;
}

function securityForbidden(lineLower, jsonObj) {
  if (!lineLower) return false;
  const forbidden = ['none', 'auto'];
  const patterns = ['security', 'scy', 'sc'];
  for (const p of patterns) {
    const re = new RegExp(`${p}\\s*[=:]\\s*([^\\s;,&}]+)`, 'i');
    const m = lineLower.match(re);
    if (m && forbidden.includes(m[1].toLowerCase())) return true;
  }
  if (jsonObj && jsonObj.security && forbidden.includes(String(jsonObj.security).toLowerCase())) return true;
  return false;
}

function hasRequiredParam(lineLower, jsonObj) {
  if (!lineLower) return false;
  const checkValue = (val) => {
    if (!val) return false;
    const s = String(val).toLowerCase();
    return s.includes('tls') || s.includes('reality') || s.endsWith('-gcm') || s.endsWith('-poly1305');
  };
  const paramPatterns = ['security','method','cipher','scy','sc','crypt'];
  for (const p of paramPatterns) {
    const re = new RegExp(`${p}\\s*[=:\"]\\s*([^\\s;,&}]+)`, 'i');
    const m = lineLower.match(re);
    if (m && checkValue(m[1])) return true;
  }
  if (jsonObj) {
    const keys = ['security','scy','method','cipher'];
    for (const k of keys) if (jsonObj[k] && checkValue(jsonObj[k])) return true;
  }
  return false;
}

function portIs443(lineLower, jsonObj) {
  if (!lineLower) return false;
  const portMatch = lineLower.match(/port\s*[=:]?\s*(\d+)/i);
  if (portMatch && portMatch[1] === '443') return true;
  if (jsonObj && jsonObj.port === 443) return true;
  return false;
}

function parseHostPortFromNormalized(normalized) {
  try {
    const u = new URL(normalized.replace(/^[a-z]+:\/\//i, 'http://'));
    return { host: u.hostname, port: u.port || '443' };
  } catch (e) {
    return null;
  }
}

function extractCommentSuffix(raw) {
  const hashIdx = raw.indexOf(' # ');
  if (hashIdx >= 0) return raw.slice(hashIdx);
  const hashIdx2 = raw.lastIndexOf('#');
  if (hashIdx2 >= 0 && hashIdx2 > raw.length - 60) return raw.slice(hashIdx2);
  return '';
}

// === ДОБАВЛЕНА ФУНКЦИЯ normalizeLine ===
function normalizeLine(protocol, payload, suffix, log) {
  let decoded = decodeBase64IfNeeded(payload);
  let jsonObj = null;
  let finalLine = `${protocol}://${decoded}${suffix || ''}`.trim();

  const jsonMatch = decoded.match(/^\{[\s\S]*\}$/);
  if (jsonMatch) {
    jsonObj = safeJsonParse(jsonMatch[0]);
    if (jsonObj) {
      finalLine = flattenJsonToUrl(protocol, jsonObj, suffix);
    }
  }

  return finalLine;
}

// === Пробники ===
async function tcpReachable(host, port, timeout = 2000) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host, port }, () => {
      sock.destroy();
      resolve(true);
    });
    sock.setTimeout(timeout);
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.on('error', () => resolve(false));
  });
}

async function tlsHandshake(host, port, timeout = 2500) {
  return new Promise(resolve => {
    const sock = tls.connect({ host, port, rejectUnauthorized: false }, () => {
      sock.end();
      resolve(true);
    });
    sock.setTimeout(timeout);
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.on('error', () => resolve(false));
  });
}

async function udpProbe(host, port, timeout = 1200) {
  return new Promise(resolve => {
    const s = dgram.createSocket('udp4');
    const onDone = (ok) => { s.close(); resolve(ok); };
    s.on('message', () => onDone(true));
    s.on('error', () => onDone(false));
    const msg = Buffer.from([0]);
    try { s.send(msg, 0, msg.length, port, host, (err) => { if (err) onDone(false); }); }
    catch (e) { onDone(false); }
    setTimeout(() => onDone(false), timeout);
  });
}

async function probeEndpoint(host, port, log) {
  const tcp = await tcpReachable(host, port, 2000);
  if (!tcp) { log.push(`TCP closed ${host}:${port}`); return false; }
  log.push(`TCP open ${host}:${port}`);

  const tlsOk = await tlsHandshake(host, port, 2500);
  if (tlsOk) { log.push(`TLS handshake succeeded ${host}:${port}`); return true; }
  log.push(`TLS handshake failed ${host}:${port}`);

  const udpOk = await udpProbe(host, port, 1200);
  if (udpOk) { log.push(`UDP probe responded ${host}:${port}`); return true; }
  log.push(`UDP probe failed ${host}:${port}`);
  return false;
}

async function parseSources(sources, options = { concurrency: 50 }) {
  const results = [];
  const seen = new Set();
  const log = [];
  const limit = pLimit(options.concurrency || 50);

  for (const src of sources) {
    log.push(`Fetching ${src} ...`);
    let text = '';
    try {
      const res = await fetch(src);
      text = await res.text();
    } catch (err) {
      log.push(`ERROR fetching ${src}: ${err.message}`);
      continue;
    }

    const lines = text.split(/\r?\n/);
    let i = 0;
    const tasks = [];

    while (i < lines.length) {
      let line = lines[i].trim();
      i++;
      if (!line) continue;

      const protoMatch = line.match(PROTOCOL_RE);
      if (!protoMatch) continue;

      const protocol = protoMatch[1].toLowerCase();
      let rest = protoMatch[2];

      if ((rest.includes('{') && !rest.includes('}')) || (rest.trim().startsWith('{') && !rest.trim().endsWith('}'))) {
        let block = rest;
        let depth = 0;
        for (const ch of block) if (ch === '{') depth++; else if (ch === '}') depth--;
        while (depth > 0 && i < lines.length) {
          const next = lines[i];
          i++;
          block += '\n' + next;
          for (const ch of next) {
            if (ch === '{') depth++;
            if (ch === '}') depth--;
          }
        }
        rest = block;
      }

      const suffix = extractCommentSuffix(rest);
      const payloadNoSuffix = suffix ? rest.replace(suffix, '').trim() : rest.trim();
      let payloadDecoded = decodeURIComponent(payloadNoSuffix);

      const normalized = normalizeLine(protocol, payloadDecoded, suffix, log);
      const lower = normalized.toLowerCase();

      let jsonObj = null;
      const jIdx = normalized.indexOf('://');
      if (jIdx >= 0) {
        const after = normalized.slice(jIdx + 3);
        const maybeJsonStart = after.indexOf('{');
        if (maybeJsonStart >= 0) {
          const jstr = after.slice(maybeJsonStart);
          jsonObj = safeJsonParse(jstr);
        }
      }

      if (checkInsecureFlags(lower, jsonObj)) { log.push(`Excluded (insecure) -> ${normalized}`); continue; }
      if (securityForbidden(lower, jsonObj)) { log.push(`Excluded (none/auto) -> ${normalized}`); continue; }
      if (!hasRequiredParam(lower, jsonObj)) { log.push(`Excluded (no crypto) -> ${normalized}`); continue; }
      if (!portIs443(lower, jsonObj)) { log.push(`Excluded (port ≠ 443) -> ${normalized}`); continue; }

      const hp = parseHostPortFromNormalized(normalized);
      if (!hp || !hp.host || !hp.port) { log.push(`Excluded (no host/port) -> ${normalized}`); continue; }

      const task = limit(async () => {
        log.push(`Probing ${hp.host}:${hp.port} ...`);
        try {
          const ok = await probeEndpoint(hp.host, hp.port, log);
          if (!ok) { log.push(`Excluded (unreachable) -> ${normalized}`); return; }
          const finalLine = normalized.replace(/\s+$/, '');
          if (!seen.has(finalLine)) {
            seen.add(finalLine);
            results.push(finalLine);
            log.push(`Included -> ${finalLine}`);
          } else {
            log.push(`Skipped duplicate -> ${finalLine}`);
          }
        } catch (e) {
          log.push(`Probe error ${hp.host}:${hp.port} -> ${e.message}`);
        }
      });
      tasks.push(task);
    }

    await Promise.all(tasks);
    log.push(`Finished parsing ${src}`);
  }

  return { results, log };
}

module.exports = { parseSources };
