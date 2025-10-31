/**
 * Parser module with concurrency, TCP reachability, TLS handshake and UDP probe (QUIC-ish) checks.
 * - Uses a concurrency limit (default 50) to run connection probes in parallel.
 * - Performs TCP connect to host:port.
 * - Performs a TLS handshake (tls.connect) when port reachable to verify TLS server is responding.
 * - Performs a UDP probe: send an empty packet and wait for any response (best-effort for UDP/QUIC).
 *
 * NOTE: UDP/QUIC detection is best-effort — QUIC may not respond to an empty UDP packet. This step
 * improves detection for many UDP-capable VPN servers but cannot guarantee 100% for all QUIC servers.
 */

const fetch = require('node-fetch');
const yaml = require('js-yaml');
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
    if (skip.has(k)) continue; const v = obj[k]; if (v===null||v===undefined||v==='') continue; q.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  const query = q.length ? `?${q.join('&')}` : '';
  const comment = originalSuffix ? ` ${originalSuffix}` : '';
  return `${protocol}://${authority}${query}${comment}`.trim();
}

function checkInsecureFlags(lineLower, jsonObj) {
  const insecurePatterns = ['insecure=1','insecure: 1','allowinsecure=1','skip-cert-verify=true','skip-cert-verify: true','insecure: true','insecure:true'];
  for (const p of insecurePatterns) if (lineLower.includes(p)) return true;
  if (jsonObj) {
    const bad = ['insecure','allowInsecure','skip-cert-verify'];
    for (const k of bad) if (Object.prototype.hasOwnProperty.call(jsonObj,k)) { const v=jsonObj[k]; if (v===true||v==='1'||v===1||String(v)==='true') return true; }
  }
  return false;
}

function extractCommentSuffix(raw) {
  const hashIdx = raw.indexOf(' # '); if (hashIdx>=0) return raw.slice(hashIdx); const hashIdx2 = raw.lastIndexOf('#'); if (hashIdx2>=0 && hashIdx2>raw.length-60) return raw.slice(hashIdx2); return ''; }

function hasRequiredParam(lineLower, jsonObj) { const checkValue=(val)=>{ if(!val) return false; const s=String(val).toLowerCase(); if(s.includes('tls')) return true; if(s.includes('reality')) return true; if(s.endsWith('-gcm')) return true; if(s.endsWith('-poly1305')) return true; if(/-gcm\b/.test(s)) return true; if(/-poly1305\b/.test(s)) return true; return false; };
  const paramPatterns=['security','method','cipher','scy','sc','crypt'];
  for(const p of paramPatterns){ const re=new RegExp(`${p}\s*[=:\"]\s*([^\s;,&]+)`,'i'); const m=lineLower.match(re); if(m && checkValue(m[1])) return true; }
  if(jsonObj){ const keys=['security','method','cipher','scy','crypt']; for(const k of keys) if(Object.prototype.hasOwnProperty.call(jsonObj,k)) if(checkValue(jsonObj[k])) return true; }
  return false; }

function portIs443(lineLower, jsonObj){ if(/:443\b/.test(lineLower)) return true; if(/port["']?\s*[:=]\s*["']?443\b/.test(lineLower)) return true; if(jsonObj && (String(jsonObj.port)==='443' || Number(jsonObj.port)===443)) return true; return false; }

function securityForbidden(lineLower,jsonObj){ const re=/security\s*[=:\"]\s*([a-zA-Z0-9_-]+)/i; const m=lineLower.match(re); if(m){ const v=m[1].toLowerCase(); if(v==='none'||v==='auto') return true;} if(jsonObj && Object.prototype.hasOwnProperty.call(jsonObj,'security')){ const v=String(jsonObj.security).toLowerCase(); if(v==='none'||v==='auto'||v==='') return true;} return false; }
function normalizeLine(protocol, payload, suffix, log) {
  const orig = `${protocol}://${payload}${suffix ? ' ' + suffix : ''}`;
  // Проверка payload на undefined или null
  if (!payload) {
    return orig;
  }
  const dec = decodeBase64IfNeeded(payload);
  if (dec !== payload) {
    log.push(`Decoded base64 payload for ${protocol}://...`);
    const m2 = dec.match(PROTOCOL_RE);
    if (m2) return normalizeLine(m2[1], m2[2], suffix, log);
    const j = safeJsonParse(dec);
    if (j) return flattenJsonToUrl(protocol, j, suffix);
    try {
      const y = yaml.load(dec);
      if (y && typeof y === 'object') return flattenJsonToUrl(protocol, y, suffix);
    } catch (e) {
      // Пропускаем ошибки парсинга
    }
    return `${protocol}://${dec}${suffix ? ' ' + suffix : ''}`;
  }
  const pTrim = payload.trim();
  if (pTrim.startsWith('{') || pTrim.startsWith('[')) {
    const j = safeJsonParse(pTrim);
    if (j && typeof j === 'object') return flattenJsonToUrl(protocol, j, suffix);
    else {
      try {
        const y = yaml.load(pTrim);
        if (y && typeof y === 'object') return flattenJsonToUrl(protocol, y, suffix);
      } catch (e) {
        // Пропускаем ошибки парсинга
      }
      return orig;
    }
  }
  const idx = payload.indexOf('{');
  if (idx >= 0) {
    const jstr = payload.slice(idx);
    const j = safeJsonParse(jstr);
    if (j) return flattenJsonToUrl(protocol, j, suffix);
  }
  return orig;
}

async function fetchText(url){ const res=await fetch(url,{ timeout:30000}); if(!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`); return await res.text(); }

function parseHostPortFromNormalized(normalized){ try{ const m=normalized.match(PROTOCOL_RE); if(!m) return null; let after=m[2]; const commentIdx=after.indexOf(' #'); if(commentIdx>=0) after=after.slice(0,commentIdx); const qIdx=after.indexOf('?'); if(qIdx>=0) after=after.slice(0,qIdx); const atIdx=after.lastIndexOf('@'); if(atIdx>=0) after=after.slice(atIdx+1); const hpMatch=after.match(/^(.+?)(?::(\d+))?/); if(!hpMatch) return null; const host=hpMatch[1]; const port=hpMatch[2]? Number(hpMatch[2]) : null; return {host,port}; }catch(e){ return null; } }

function tcpReachable(host,port,timeout=2000){ return new Promise((resolve)=>{ if(!host||!port) return resolve(false); const socket=new net.Socket(); let finished=false; const onDone=(up)=>{ if(finished) return; finished=true; try{ socket.destroy(); }catch(e){} resolve(up); }; socket.setTimeout(timeout); socket.once('connect',()=>onDone(true)); socket.once('timeout',()=>onDone(false)); socket.once('error',()=>onDone(false)); socket.connect(port,host); }); }

function tlsHandshake(host,port,timeout=3000){ return new Promise((resolve)=>{ let finished=false; const opts={host,port,servername:host,rejectUnauthorized:false}; const sock=tls.connect(opts,()=>{ if(finished) return; finished=true; try{ sock.end(); }catch(e){} resolve(true); }); sock.setTimeout(timeout,()=>{ if(finished) return; finished=true; try{ sock.destroy(); }catch(e){} resolve(false); }); sock.once('error',()=>{ if(finished) return; finished=true; try{ sock.destroy(); }catch(e){} resolve(false); }); }); }

function udpProbe(host,port,timeout=1500){ return new Promise((resolve)=>{ if(!host||!port) return resolve(false); const s=dgram.createSocket('udp4'); let done=false; const onDone=(ok)=>{ if(done) return; done=true; try{ s.close(); }catch(e){} resolve(ok); }; s.once('error',()=>onDone(false)); s.on('message',()=>onDone(true)); const msg=Buffer.from([0]); try{ s.send(msg,0,msg.length,port,host,(err)=>{ if(err) return onDone(false); // wait for response
 }); }catch(e){ return onDone(false); } setTimeout(()=>onDone(false),timeout); }); }

async function probeEndpoint(host,port,log){ // perform TCP, then TLS, and UDP probe in parallel but with overall timeout
  const tcp = await tcpReachable(host,port,2000);
  if(!tcp){ log.push(`TCP closed ${host}:${port}`); return false; }
  log.push(`TCP open ${host}:${port}`);
  // TLS handshake (most VPN servers using 443 for TLS will respond)
  const tlsOk = await tlsHandshake(host,port,2500);
  if(tlsOk){ log.push(`TLS handshake succeeded ${host}:${port}`); return true; }
  log.push(`TLS handshake failed ${host}:${port}`);
  // UDP probe as fallback (for UDP/QUIC oriented servers)
  const udpOk = await udpProbe(host,port,1200);
  if(udpOk){ log.push(`UDP probe responded ${host}:${port}`); return true; }
  log.push(`UDP probe failed ${host}:${port}`);
  return false; }

async function parseSources(sources, options={concurrency:50}){
  const results=[]; const seen=new Set(); const log=[]; const limit=pLimit(options.concurrency||50);
  for(const src of sources){ log.push(`Fetching ${src} ...`); let text=''; try{ text=await fetchText(src); }catch(err){ log.push(`ERROR fetching ${src}: ${err.message}`); continue; } const lines=text.split(/\r?\n/); let i=0; const tasks=[]; while(i<lines.length){ let line=lines[i].trim(); i++; if(!line) continue; const protoMatch=line.match(PROTOCOL_RE); if(!protoMatch) continue; const protocol=protoMatch[1]; let rest=protoMatch[2]; if((rest.includes('{') && !rest.includes('}')) || rest.trim().startsWith('{') && !rest.trim().endsWith('}')){ let block=rest; let depth=0; if(block.includes('{')){ for(const ch of block) if(ch==='{' ) depth++; for(const ch of block) if(ch==='}') depth--; } while(depth>0 && i<lines.length){ const next=lines[i]; i++; block+='\n'+next; for(const ch of next){ if(ch==='{') depth++; if(ch==='}') depth--; } } rest=block; }
    const suffix=extractCommentSuffix(rest);
    const payloadNoSuffix=suffix? rest.replace(suffix,'').trim() : rest.trim();
    let payloadDecoded=decodeURIComponent(payloadNoSuffix);
    const normalized=normalizeLine(protocol,payloadDecoded,suffix,log);
    const lower=normalized.toLowerCase();
    let jsonObj=null; const jIdx=normalized.indexOf('://'); if(jIdx>=0){ const after=normalized.slice(jIdx+3); const maybeJsonStart=after.indexOf('{'); if(maybeJsonStart>=0){ const jstr=after.slice(maybeJsonStart); jsonObj=safeJsonParse(jstr); } }
    if(checkInsecureFlags(lower,jsonObj)){ log.push(`Excluded (insecure flags) -> ${normalized}`); continue; }
    if(securityForbidden(lower,jsonObj)){ log.push(`Excluded (security forbidden none/auto) -> ${normalized}`); continue; }
    if(!hasRequiredParam(lower,jsonObj)){ log.push(`Excluded (missing required parameter with allowed value) -> ${normalized}`); continue; }
    if(!portIs443(lower,jsonObj)){ log.push(`Excluded (port != 443) -> ${normalized}`); continue; }
    const hp=parseHostPortFromNormalized(normalized);
    if(!hp||!hp.host||!hp.port){ log.push(`Excluded (cannot parse host/port) -> ${normalized}`); continue; }
    // schedule probe task with concurrency limit
    const task = limit(async ()=>{
      log.push(`Probing ${hp.host}:${hp.port} ...`);
      try{
        const ok = await probeEndpoint(hp.host,hp.port,log);
        if(!ok){ log.push(`Excluded (unreachable) -> ${normalized}`); return; }
        const finalLine=normalized.replace(/\s+$/,''); if(!seen.has(finalLine)){ seen.add(finalLine); results.push(finalLine); log.push(`Included -> ${finalLine}`); } else { log.push(`Skipped duplicate -> ${finalLine}`); }
      }catch(e){ log.push(`Probe error ${hp.host}:${hp.port} -> ${e.message}`); }
    });
    tasks.push(task);
  }
  // await all probe tasks for this source
  await Promise.all(tasks);
  log.push(`Finished parsing ${src}`);
  }
  return {results,log}; }

module.exports = { parseSources };
