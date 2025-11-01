/**
 * Parser module.
 * - Fetches each URL
 * - Splits by lines, preserves lines that look like one-server-per-line.
 * - Decodes base64 payloads after protocol:// if present
 * - Parses inline JSON/YAML and converts into single-line "protocol://..." representation
 * - Applies filtering rules:
 *    * Must contain at least one of: security/method/cipher
 *    * The value must include tls OR reality OR end with -gcm OR end with -poly1305
 *    * Port must be 443
 *    * Exclude entries containing insecure flags or security values like none/auto or missing security field
 * - Performs a TCP reachability check (connect to host:port with timeout) before including entry.
 * - Returns results (array of strings) and a log (array of lines)
 */

const fetch = require('node-fetch');
const yaml = require('js-yaml');
const net = require('net');

const PROTOCOL_RE = /^([a-zA-Z0-9+\-.]+):\/\/.*$/s;

function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch (e) {
    return null;
  }
}

function isBase64(str) {
  if (!str || typeof str !== 'string') return false;
  const maybe = str.split('?')[0].split('#')[0];
  const cleaned = maybe.replace(/[
\n\s]/g, '');
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
  if (obj.id || obj.uuid || obj.user) {
    userinfo = obj.id || obj.uuid || obj.user;
  } else if (obj.method && obj.password) {
    userinfo = obj.password;
  } else if (obj.auth) {
    userinfo = obj.auth;
  }
  let authority = '';
  if (userinfo) authority = `${userinfo}@`;
  authority += host || '';
  if (port) authority += `:${port}`;
  const q = [];
  const skip = new Set(['add', 'address', 'host', 'ip', 'server', 'port', 'p', 'id', 'uuid', 'user', 'password', 'pass', 'auth', 'ps']);
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
  const insecurePatterns = [
    'insecure=1', 'insecure: 1', 'allowinsecure=1', 'skip-cert-verify=true',
    'skip-cert-verify: true', 'insecure: true', 'insecure:true'
  ];
  for (const p of insecurePatterns) {
    if (lineLower.includes(p)) return true;
  }
  if (jsonObj) {
    const bad = ['insecure', 'allowInsecure', 'skip-cert-verify'];
    for (const k of bad) {
      if (Object.prototype.hasOwnProperty.call(jsonObj, k)) {
        const v = jsonObj[k];
        if (v === true || v === '1' || v === 1 || String(v) === 'true') return true;
      }
    }
  }
  return false;
}

function extractCommentSuffix(raw) {
  const hashIdx = raw.indexOf(' # ');
  if (hashIdx >= 0) return raw.slice(hashIdx);
  const hashIdx2 = raw.lastIndexOf('#');
  if (hashIdx2 >= 0 && hashIdx2 > raw.length - 60) {
    return raw.slice(hashIdx2);
  }
  return '';
}

function hasRequiredParam(lineLower, jsonObj) {
  const checkValue = (val) => {
    if (!val) return false;
    const s = String(val).toLowerCase();
    if (s.includes('tls')) return true;
    if (s.includes('reality')) return true;
    if (s.endsWith('-gcm')) return true;
    if (s.endsWith('-poly1305')) return true;
    if (/-gcm\b/.test(s)) return true;
    if (/-poly1305\b/.test(s)) return true;
    return false;
  };
  const paramPatterns = ['security', 'method', 'cipher', 'scy', 'sc', 'crypt'];
  for (const p of paramPatterns) {
    const re = new RegExp(`${p}\s*[=:\"]\s*([^\s;,&]+)`, 'i');
    const m = lineLower.match(re);
    if (m && checkValue(m[1])) return true;
  }
  if (jsonObj) {
    const keys = ['security', 'method', 'cipher', 'scy', 'crypt'];
    for (const k of keys) {
      if (Object.prototype.hasOwnProperty.call(jsonObj, k)) {
        if (checkValue(jsonObj[k])) return true;
      }
    }
  }
  return false;
}

function portIs443(lineLower, jsonObj) {
  if (/:443\b/.test(lineLower)) return true;
  if (/port["']?\s*[:=]\s*["']?443\b/.test(lineLower)) return true;
  if (jsonObj && (String(jsonObj.port) === '443' || Number(jsonObj.port) === 443)) return true;
  return false;
}

function securityForbidden(lineLower, jsonObj) {
  const re = /security\s*[=:\"]\s*([a-zA-Z0-9_-]+)/i;
  const m = lineLower.match(re);
  if (m) {
    const v = m[1].toLowerCase();
    if (v === 'none' || v === 'auto') return true;
  }
  if (jsonObj && Object.prototype.hasOwnProperty.call(jsonObj, 'security')) {
    const v = String(jsonObj.security).toLowerCase();
    if (v === 'none' || v === 'auto' || v === '') return true;
  }
  return false;
}

function normalizeLine(protocol, payload, suffix, log) {
  const orig = `${protocol}://${payload}${suffix ? ' ' + suffix : ''}`;
  const dec = decodeBase64IfNeeded(payload);
  if (dec !== payload) {
    log.push(`Decoded base64 payload for ${protocol}://...`);
    const m2 = dec.match(PROTOCOL_RE);
    if (m2) {
      return normalizeLine(m2[1], m2[2], suffix, log);
    }
    const j = safeJsonParse(dec);
    if (j) return flattenJsonToUrl(protocol, j, suffix);
    try {
      const y = yaml.load(dec);
      if (y && typeof y === 'object') return flattenJsonToUrl(protocol, y, suffix);
    } catch (e) {}
    return `${protocol}://${dec}${suffix ? ' ' + suffix : ''}`;
  }
  const pTrim = payload.trim();
  if (pTrim.startsWith('{') || pTrim.startsWith('[')) {
    const j = safeJsonParse(pTrim);
    if (j && typeof j === 'object') {
      return flattenJsonToUrl(protocol, j, suffix);
    } else {
      try {
        const y = yaml.load(pTrim);
        if (y && typeof y === 'object') return flattenJsonToUrl(protocol, y, suffix);
      } catch (e) {}
      return orig;
    }
  }
  const idx = payload.indexOf('{');
  if (idx >= 0) {
    const jstr = payload.slice(idx);
    const j = safeJsonParse(jstr);
    if (j) {
      return flattenJsonToUrl(protocol, j, suffix);
    }
  }
  return orig;
}

async function fetchText(url) {
  const res = await fetch(url, { timeout: 30000 });
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
  return await res.text();
}

function parseHostPortFromNormalized(normalized) {
  // normalized like protocol://[userinfo@]host:port?...
  try {
    const m = normalized.match(PROTOCOL_RE);
    if (!m) return null;
    let after = m[2];
    // remove comment suffix
    const commentIdx = after.indexOf(' #');
    if (commentIdx >= 0) after = after.slice(0, commentIdx);
    // strip query
    const qIdx = after.indexOf('?');
    if (qIdx >= 0) after = after.slice(0, qIdx);
    // remove userinfo
    const atIdx = after.lastIndexOf('@');
    if (atIdx >= 0) after = after.slice(atIdx + 1);
    // host:port or hostname (with :port)
    const hpMatch = after.match(/^(.+?)(?::(\d+))?/);
    if (!hpMatch) return null;
    const host = hpMatch[1];
    const port = hpMatch[2] ? Number(hpMatch[2]) : null;
    return { host, port };
  } catch (e) {
    return null;
  }
}

function tcpReachable(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    if (!host || !port) return resolve(false);
    const socket = new net.Socket();
    let finished = false;
    const onDone = (up) => {
      if (finished) return;
      finished = true;
      try { socket.destroy(); } catch (e) {}
      resolve(up);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => onDone(true));
    socket.once('timeout', () => onDone(false));
    socket.once('error', () => onDone(false));
    socket.connect(port, host);
  });
}

async function parseSources(sources) {
  const results = [];
  const seen = new Set();
  const log = [];
  for (const src of sources) {
    log.push(`Fetching ${src} ...`);
    let text = '';
    try {
      text = await fetchText(src);
    } catch (err) {
      log.push(`ERROR fetching ${src}: ${err.message}`);
      continue;
    }
    const lines = text.split(/\r?\n/);
    let i = 0;
    while (i < lines.length) {
      let line = lines[i].trim();
      i++;
      if (!line) continue;
      const protoMatch = line.match(PROTOCOL_RE);
      if (!protoMatch) continue;
      const protocol = protoMatch[1];
      let rest = protoMatch[2];
      if ((rest.includes('{') && !rest.includes('}')) || rest.trim().startsWith('{') && !rest.trim().endsWith('}')) {
        let block = rest;
        let depth = 0;
        if (block.includes('{')) {
          for (const ch of block) if (ch === '{') depth++;
          for (const ch of block) if (ch === '}') depth--;
        }
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
      if (checkInsecureFlags(lower, jsonObj)) {
        log.push(`Excluded (insecure flags) -> ${normalized}`);
        continue;
      }
      if (securityForbidden(lower, jsonObj)) {
        log.push(`Excluded (security forbidden none/auto) -> ${normalized}`);
        continue;
      }
      if (!hasRequiredParam(lower, jsonObj)) {
        log.push(`Excluded (missing required parameter with allowed value) -> ${normalized}`);
        continue;
      }
      if (!portIs443(lower, jsonObj)) {
        log.push(`Excluded (port != 443) -> ${normalized}`);
        continue;
      }
      // New: check TCP reachability (fast check suitable for most VPN protocols on port 443)
      const hp = parseHostPortFromNormalized(normalized);
      if (!hp || !hp.host || !hp.port) {
        log.push(`Excluded (cannot parse host/port) -> ${normalized}`);
        continue;
      }
      log.push(`Pinging ${hp.host}:${hp.port} ...`);
      const up = await tcpReachable(hp.host, hp.port, 3000);
      if (!up) {
        log.push(`Excluded (unreachable) -> ${normalized}`);
        continue;
      }
      const finalLine = normalized.replace(/\s+$/,'');
      if (!seen.has(finalLine)) {
        seen.add(finalLine);
        results.push(finalLine);
        log.push(`Included -> ${finalLine}`);
      } else {
        log.push(`Skipped duplicate -> ${finalLine}`);
      }
    }
    log.push(`Finished parsing ${src}`);
  }
  return { results, log };
}

module.exports = { parseSources };
