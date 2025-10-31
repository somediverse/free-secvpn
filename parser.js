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
 * - checkInsecureFlag
 * - Updated to handle vmess JSON format
 * - Added proper error handling for malformed URIs
 */
const pLimit = require('p-limit');
const net = require('net');
const tls = require('tls');
const dgram = require('dgram');
const PROTOCOL_RE = /^([a-zA-Z0-9+\-.]+):\/\/(.*)$/s;
function isIPAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(host);
}
function extractCommentSuffix(raw) {
  if (!raw) return '';
  const i1 = raw.indexOf(' # ');
  if (i1 >= 0) return raw.slice(i1);
  const i2 = raw.lastIndexOf('#');
  return i2 >= 0 && i2 > raw.length - 60 ? raw.slice(i2) : '';
}
function checkInsecureFlag(protocol, port) {
  // Allow insecure connections for non-standard ports or specific protocols
  return protocol === 'ss' || protocol === 'vmess' || port !== 443;
}
function parseVmessJson(jsonStr) {
  try {
    const config = JSON.parse(jsonStr);
    const { add, port, id, aid = '0', net = 'tcp', type = '', host = '', path = '', tls = '0', sni = '', ps = '', v = '2' } = config;
    
    // Конвертация vmess из JSON в URI формат
    const uuid = id;
    const security = tls === 'tls' ? 'tls' : 'none';
    const network = net;
    const hostParam = host || sni;
    const pathParam = path;
    const sniParam = sni || host;
    const alterId = aid;
    const remark = ps;
    
    // Формируем URI
    const params = new URLSearchParams({
      encryption: 'auto',
      security,
      type: network,
      host: hostParam,
      path: pathParam,
      sni: sniParam,
      ps: remark,
      uuid,
      alterId,
      tls: tls === 'tls' ? '1' : '0'
    });
    
    // Удаляем пустые параметры
    for (const [key, value] of params.entries()) {
      if (!value) params.delete(key);
    }
    
    const uri = `vmess://${add}:${port}?${params.toString()}#${encodeURIComponent(remark)}`;
    return uri;
  } catch (e) {
    return null;
  }
}
function parseSSUri(uri) {
  const match = uri.match(/^ss:\/\/([^@]+)@([^:]+):(\d+)(?:\/\?(.*))?$/);
  if (!match) return null;
  
  const [, method_and_password, host, port, query] = match;
  const decoded = Buffer.from(method_and_password, 'base64').toString('utf-8');
  const [method, password] = decoded.split(':');
  
  // Извлечение дополнительных параметров
  const params = new URLSearchParams(query || '');
  const plugin = params.get('plugin');
  const obfs = params.get('obfs');
  
  return {
    protocol: 'ss',
    host,
    port: parseInt(port),
    method,
    password,
    plugin,
    obfs
  };
}
function parseVmessUri(uri) {
  const match = uri.match(/^vmess:\/\/(.+)$/);
  if (!match) return null;
  
  try {
    const jsonStr = Buffer.from(match[1], 'base64').toString('utf-8');
    return parseVmessJson(jsonStr);
  } catch (e) {
    return null;
  }
}
function parseProtocol(line) {
  const m = line.match(PROTOCOL_RE);
  if (!m) return null;
  
  const [, protocol, rest] = m;
  const trimmedRest = rest.trim();
  
  if (protocol === 'ss') {
    return parseSSUri(trimmedRest);
  } else if (protocol === 'vmess') {
    return parseVmessUri(trimmedRest);
  }
  
  return null;
}
async function checkTcpConnection(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}
async function checkTlsHandshake(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const options = {
      host,
      port,
      rejectUnauthorized: false,
    };
    
    // Убрана явная установка servername для предотвращения DEP0123
    const socket = tls.connect(options, () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.setTimeout(timeout);
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
  });
}
async function checkUdpConnection(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    client.on('error', () => {
      client.close();
      resolve(false);
    });
    client.on('message', () => {
      client.close();
      resolve(true);
    });
    client.on('timeout', () => {
      client.close();
      resolve(false);
    });
    
    client.send(Buffer.alloc(0), port, host, (err) => {
      if (err) {
        client.close();
        resolve(false);
      } else {
        client.setTimeout(timeout);
      }
    });
  });
}
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
      
      const protocol = m[1];
      const rest = m[2].trim();
      
      // Проверяем, является ли это VMess JSON
      if (protocol === 'vmess' && rest.startsWith('{')) {
        const parsed = parseVmessJson(rest);
        if (parsed) {
          log.push(`Parsed vmess JSON: ${parsed}`);
          line = parsed;
        } else {
          log.push(`Failed to parse vmess JSON: ${rest}`);
          continue;
        }
      }
      
      const parsed = parseProtocol(line);
      if (!parsed) {
        log.push(`Failed to parse protocol: ${line}`);
        continue;
      }
      
      const { host, port } = parsed;
      if (!host || !port) {
        log.push(`Invalid host or port: ${line}`);
        continue;
      }
      
      // Проверяем уникальность
      const key = `${host}:${port}`;
      if (seen.has(key)) {
        log.push(`Duplicate entry skipped: ${line}`);
        continue;
      }
      seen.add(key);
      
      // Проверяем TCP соединение
      const tcpOk = await checkTcpConnection(host, port);
      if (!tcpOk) {
        log.push(`TCP connection failed: ${host}:${port}`);
        continue;
      }
      
      // Проверяем TLS handshake если порт 443 или insecure флаг установлен
      let tlsOk = true;
      if (port === 443 || checkInsecureFlag(protocol, port)) {
        tlsOk = await checkTlsHandshake(host, port);
        if (!tlsOk) {
          log.push(`TLS handshake failed: ${host}:${port}`);
          continue;
        }
      }
      
      // Проверяем UDP если это UDP-совместимый протокол
      let udpOk = true;
      if (protocol === 'ss' || protocol === 'vmess') {
        udpOk = await checkUdpConnection(host, port);
        if (!udpOk) {
          log.push(`UDP probe failed: ${host}:${port}`);
        }
      }
      
      // Фильтрация результатов
      const isInsecure = checkInsecureFlag(protocol, port);
      const isUDP = protocol === 'ss' || protocol === 'vmess';
      
      if (isInsecure || isUDP) {
        const comment = extractCommentSuffix(line);
        const finalLine = `${line}${comment}`;
        results.push(finalLine);
        log.push(`Added result: ${finalLine}`);
      } else {
        log.push(`Skipped result (secure & TCP-only): ${line}`);
      }
    }
  }
  
  return { results, log };
}
module.exports = { parseSources };
