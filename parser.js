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
    const { add, port, id, aid = '0', net = 'tcp', type = '', host = '', path = '', tls = '0', sni = '', ps = '' } = config;
    
    if (!add || !port || !id) return null;
    
    const result = {
      protocol: 'vmess',
      host: add,
      port: parseInt(port),
      uuid: id,
      alterId: parseInt(aid),
      security: net === 'ws' ? 'tls' : 'auto',
      type: type || 'none',
      host: host || '',
      path: path || '',
      tls: tls === 'tls' ? 1 : 0,
      sni: sni || '',
      ps: ps || ''
    };
    
    return result;
  } catch (e) {
    return null;
  }
}
async function checkTcpConnection(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout }, () => {
      socket.end();
      resolve(true);
    });
    
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}
async function checkTlsConnection(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const options = { host, port, timeout };
    if (!isIPAddress(host)) {
      options.servername = host;
    }
    const socket = tls.connect(options, () => {
      socket.end();
      resolve(true);
    });
    
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}
async function checkUdpConnection(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    const message = Buffer.alloc(0); // Empty packet for QUIC probe
    
    const timeoutId = setTimeout(() => {
      client.close();
      resolve(false);
    }, timeout);
    
    client.on('message', () => {
      clearTimeout(timeoutId);
      client.close();
      resolve(true);
    });
    
    client.on('error', () => {
      clearTimeout(timeoutId);
      resolve(false);
    });
    
    client.send(message, 0, message.length, port, host);
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
      
      const protocol = m[1].toLowerCase();
      let rest = m[2];
      
      // Handle vmess JSON format
      if (protocol === 'vmess' && rest.startsWith('{')) {
        const vmessConfig = parseVmessJson(rest);
        if (!vmessConfig) continue;
        
        const key = `${vmessConfig.protocol}://${vmessConfig.host}:${vmessConfig.port}`;
        if (seen.has(key)) continue;
        seen.add(key);
        
        const insecure = checkInsecureFlag(protocol, vmessConfig.port);
        
        tasks.push(limit(async () => {
          const tcpOk = await checkTcpConnection(vmessConfig.host, vmessConfig.port);
          const tlsOk = vmessConfig.tls ? await checkTlsConnection(vmessConfig.host, vmessConfig.port) : false;
          const udpOk = await checkUdpConnection(vmessConfig.host, vmessConfig.port);
          
          if (tcpOk || tlsOk || udpOk) {
            results.push({
              ...vmessConfig,
              insecure,
              tcp: tcpOk,
              tls: tlsOk,
              udp: udpOk
            });
          }
        }));
        continue;
      }
      
      // Handle SS protocol with base64 decoding
      if (protocol === 'ss') {
        const suffix = extractCommentSuffix(rest);
        const payload = suffix ? rest.slice(0, rest.indexOf(suffix)).trim() : rest.trim();
        
        try {
          const decoded = decodeURIComponent(payload);
          const parts = decoded.split('@');
          if (parts.length !== 2) continue;
          
          const [methodPass, hostPort] = parts;
          const [host, portStr] = hostPort.split(':');
          const port = parseInt(portStr);
          
          if (!host || !port || isNaN(port)) continue;
          
          const key = `${protocol}://${host}:${port}`;
          if (seen.has(key)) continue;
          seen.add(key);
          
          const insecure = checkInsecureFlag(protocol, port);
          
          tasks.push(limit(async () => {
            const tcpOk = await checkTcpConnection(host, port);
            const tlsOk = port === 443 ? await checkTlsConnection(host, port) : false;
            const udpOk = await checkUdpConnection(host, port);
            
            if (tcpOk || tlsOk || udpOk) {
              results.push({
                protocol,
                host,
                port,
                method: methodPass.split(':')[0],
                password: methodPass.split(':')[1],
                insecure,
                tcp: tcpOk,
                tls: tlsOk,
                udp: udpOk
              });
            }
          }));
        } catch (e) {
          log.push(`Failed to decode SS URI: ${e.message}`);
          continue;
        }
        continue;
      }
      
      // Skip unknown protocols
      log.push(`Skipping unknown protocol: ${protocol}`);
    }
    
    await Promise.all(tasks);
  }
  
  return { results, log };
}
module.exports = { parseSources };
