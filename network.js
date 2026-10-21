import http from 'node:http';
import https from 'node:https';
import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import ipaddr from 'ipaddr.js';

export function publicIP(value) {
  try {
    let ip = ipaddr.parse(value);
    if (ip.kind() === 'ipv6') {
      if (ip.isIPv4MappedAddress()) return false;
      // Only globally routed IPv6; reject transition, documentation and special ranges.
      if (!ip.match(ipaddr.parse('2000::'), 3)) return false;
    }
    return ip.range() === 'unicast';
  } catch { return false; }
}
export function parseTarget(input) {
  if (typeof input !== 'string' || input.length > 2048) throw new Error('URL inválida.');
  let u;
  try { u = new URL(input); } catch { throw new Error('Ingresa una URL completa con https:// o http://.'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.port) throw new Error('Solo HTTP/HTTPS, sin credenciales ni puertos personalizados.');
  const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!host || /(^|\.)(localhost|local|internal|test|invalid|onion)$/.test(host) || (!host.includes('.') && !isIP(host)) || (isIP(host) && !publicIP(host))) throw new Error('Destino local, privado o reservado bloqueado.');
  u.hash = '';
  return u;
}
export async function resolvePublic(host, resolver = lookup) {
  host = host.replace(/^\[|\]$/g, '');
  let timer;
  const records = isIP(host) ? [{address:host, family:isIP(host)}] : await Promise.race([
    resolver(host, {all:true, verbatim:true}),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Tiempo de DNS agotado.')), 3000); })
  ]).finally(() => clearTimeout(timer));
  if (!records.length || records.some(r => !publicIP(r.address))) throw new Error('DNS apunta a una dirección privada o reservada.');
  return records[0];
}
// Pin the validated address into lookup; keep the original hostname for Host and TLS verification.
export async function requestTarget(input, {limit=262144, signal, redirects=3, method='GET'} = {}) {
  const u = parseTarget(String(input));
  const pinned = await resolvePublic(u.hostname);
  signal?.throwIfAborted();
  const result = await new Promise((resolve, reject) => {
    let timer, done=false;
    const finish = (err, value) => { if (done) return; done=true; clearTimeout(timer); err ? reject(err) : resolve(value); };
    const req = (u.protocol === 'https:' ? https : http).request(u, {
      method, agent:false, signal, maxHeaderSize:16384, rejectUnauthorized:true,
      lookup:(_host, options, cb) => options?.all ? cb(null,[pinned]) : cb(null,pinned.address,pinned.family),
      headers:{'User-Agent':'VulScan/1.0 (authorized low-impact security review)',Accept:'text/html,text/plain,*/*;q=0.1','Accept-Encoding':'identity',Range:`bytes=0-${limit-1}`}
    }, res => {
      const cert = u.protocol === 'https:' ? res.socket.getPeerCertificate() : null;
      const tls = cert ? {valid:true, issuer:cert.issuer?.O || '', expires:cert.valid_to, protocol:res.socket.getProtocol()} : null;
      const chunks=[]; let size=0;
      const complete = truncated => finish(null,{url:u.href,status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks),tls,truncated});
      res.on('data',chunk=>{const remaining=limit-size; chunks.push(chunk.subarray(0,remaining)); size+=Math.min(chunk.length,remaining); if(size>=limit){complete(true);res.destroy();}});
      res.on('end',()=>complete(false));
      res.on('error',e=>finish(e));
    });
    timer=setTimeout(()=>req.destroy(new Error('Tiempo de conexión agotado.')),6500);
    req.on('error',e=>finish(e)); req.end();
  });
  if ([301,302,303,307,308].includes(result.status) && result.headers.location) {
    if (!redirects) throw new Error('Demasiadas redirecciones.');
    const next=parseTarget(new URL(result.headers.location,u).href);
    if (u.protocol==='https:' && next.protocol==='http:') throw new Error('Redirección a HTTP inseguro bloqueada.');
    return requestTarget(next,{limit,signal,redirects:redirects-1,method});
  }
  return result;
}
