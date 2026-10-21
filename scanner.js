import {parseTarget,requestTarget} from './network.js';
export const weights = {'Crítica':35,'Alta':20,'Media':8,'Baja':3,'Informativa':0};
export function inspectHeaders(headers, secure) {
  const f=[];
  const add=(severity,title,description,recommendation)=>f.push({severity,title,description,recommendation});
  const csp=String(headers['content-security-policy'] || '');
  if(!csp) add('Media','Falta Content-Security-Policy','La respuesta no declara una política de contenido.','Define una CSP restrictiva, con nonces o hashes para scripts.');
  else if(/'unsafe-inline'|'unsafe-eval'/.test(csp)) add('Baja','CSP permite ejecución insegura','Se observaron unsafe-inline o unsafe-eval; su efecto depende del resto de la política.','Revisa la política y sustituye permisos amplios por nonces o hashes.');
  if(!/frame-ancestors\s/i.test(csp) && !/^(DENY|SAMEORIGIN)$/i.test(headers['x-frame-options']||'')) add('Media','Protección contra framing ausente','No se observó una directiva válida para limitar el embebido.','Configura frame-ancestors en CSP.');
  if(String(headers['x-content-type-options']).toLowerCase()!=='nosniff') add('Baja','Falta X-Content-Type-Options','El navegador podría inferir tipos de contenido.','Configura X-Content-Type-Options: nosniff.');
  if(secure && !/max-age\s*=\s*[1-9]\d*/i.test(headers['strict-transport-security']||'')) add('Media','HSTS ausente o desactivado','No se anuncia una duración positiva para forzar HTTPS.','Configura Strict-Transport-Security tras validar HTTPS en todo el dominio.');
  if(!headers['referrer-policy']) add('Baja','Falta Referrer-Policy','No se declara una política explícita del referente.','Configura strict-origin-when-cross-origin o una política más restrictiva.');
  if(!headers['permissions-policy']) add('Informativa','Falta Permissions-Policy','No se restringen explícitamente capacidades del navegador.','Deshabilita cámara, micrófono y geolocalización si no se usan.');
  for(const [i,cookie] of (headers['set-cookie'] || []).entries()) {
    const flags=cookie.split(';').slice(1).map(s=>s.trim().toLowerCase());
    const missing=[];
    if(!flags.includes('secure'))missing.push('Secure');
    if(!flags.includes('httponly'))missing.push('HttpOnly');
    if(!flags.some(x=>/^samesite=(strict|lax|none)$/.test(x)))missing.push('SameSite');
    if(missing.length)add('Media',`Cookie ${i+1}: atributos ausentes`, `Faltan ${missing.join(', ')}. Los valores de cookies no se guardan ni se muestran.`, 'Usa Secure y SameSite; aplica HttpOnly a cookies que no necesiten JavaScript. Revisa según su función.');
    if(flags.includes('samesite=none')&&!flags.includes('secure'))add('Baja',`Cookie ${i+1}: SameSite=None sin Secure`,'Los navegadores pueden rechazar esta cookie.','Añade Secure.');
  }
  return f;
}
export function exposed(kind, body, headers={}) {
  const text=body.toString('utf8');
  if(/<(!doctype|html|head|body)\b/i.test(text))return false;
  if(kind==='env')return /^(?:export\s+)?[A-Z_][A-Z0-9_]{2,}\s*=\s*[^\r\n]+/m.test(text);
  if(kind==='git')return /^ref: refs\/heads\/[\w./-]+\s*$/.test(text)||/^[a-f0-9]{40}\s*$/.test(text);
  if(kind==='zip')return body.subarray(0,4).equals(Buffer.from([80,75,3,4]));
  if(kind==='sql')return /(?:CREATE TABLE|INSERT INTO|-- MySQL dump|-- PostgreSQL database dump)/i.test(text);
  if(kind==='robots')return /^(User-agent|Disallow|Allow|Sitemap):/im.test(text);
  return false;
}
export function technologies(html, headers) {
  const list=[];
  for(const [name,re] of [['jquery',/jquery(?:[-./]|%40)(\d+\.\d+\.\d+)/ig],['bootstrap',/bootstrap(?:[-/@]|%40)(\d+\.\d+\.\d+)/ig],['lodash',/lodash(?:[-/@]|%40)(\d+\.\d+\.\d+)/ig]]) {
    const match=re.exec(html); if(match)list.push({name,version:match[1],ecosystem:'npm'});
  }
  return {packages:list,banners:[headers.server,headers['x-powered-by']].filter(Boolean).map(s=>s.slice(0,120))};
}
export async function scan(input, {exposure=false, signal, request=requestTarget, osvFetch=fetch}={}) {
  const u=parseTarget(input), findings=[], checks=[], warnings=[];
  const add=(severity,title,description,recommendation)=>findings.push({severity,title,description,recommendation});
  if(u.protocol==='http:')add('Alta','URL inicial sin HTTPS','La primera conexión no está cifrada.','Utiliza HTTPS y redirige todo el tráfico HTTP a HTTPS.');
  let response;
  try { response=await request(u,{signal}); }
  catch(error) {
    const tlsError=/CERT_|CERTIFICATE|SELF_SIGNED|TLS|SSL|UNABLE_TO_VERIFY/.test(error.code||'');
    if(tlsError)add('Alta','No se pudo validar TLS','El servidor no superó la validación TLS del cliente. Puede haber un certificado inválido o incompatibilidad.','Revisa vigencia, nombre del dominio, cadena completa y configuración TLS.');
    else throw error;
    return {url:u.origin,score:null,findings,checks:[{name:'TLS',status:'Falló la validación'}],warnings:['Informe incompleto: no se leyó el sitio.'],technologies:[],at:new Date().toISOString()};
  }
  const final=new URL(response.url);
  if(response.status<200 || response.status>=300) warnings.push(`HTTP ${response.status}: se analiza una respuesta de error o acceso restringido, no necesariamente la aplicación.`);
  if(response.truncated)warnings.push('HTML limitado a 256 KiB; detección de tecnologías parcial.');
  findings.push(...inspectHeaders(response.headers,final.protocol==='https:'));
  checks.push({name:'Cabeceras y cookies',status:`HTTP ${response.status}`});
  if(response.tls) {
    const days=Math.floor((Date.parse(response.tls.expires)-Date.now())/86400000);
    if(days<30)add('Baja','Certificado próximo a vencer',`Vence en ${days} días.`,'Renueva el certificado y automatiza su renovación.');
    checks.push({name:'SSL / TLS',status:`Certificado válido · ${response.tls.protocol} · vence ${response.tls.expires}`});
  } else checks.push({name:'SSL / TLS',status:'No evaluado: respuesta HTTP'});
  if(exposure) {
    for(const [path,kind] of [['/.env','env'],['/.git/HEAD','git'],['/backup.zip','zip'],['/backup.sql','sql'],['/robots.txt','robots']]) {
      signal?.throwIfAborted();
      try {
        const r=await request(new URL(path,final.origin),{signal,limit:4096,redirects:0});
        if([200,206].includes(r.status)&&exposed(kind,r.body,r.headers)) {
          if(kind==='robots')add('Informativa','robots.txt público','Se detectaron directivas de rastreo. Este archivo es público por diseño.','No lo uses como control de acceso ni publiques rutas confidenciales.');
          else add(kind==='env'?'Crítica':'Alta',`Archivo expuesto: ${path}`,'La respuesta contiene una firma compatible. No se muestran ni persisten sus contenidos; confirma manualmente el alcance.','Retira el archivo del directorio público, bloquea su acceso y rota secretos si se confirma su exposición.');
          checks.push({name:path,status:'Firma detectada'});
        } else checks.push({name:path,status:`Sin evidencia en la muestra · HTTP ${r.status}`});
      }catch{checks.push({name:path,status:'No verificado'});warnings.push(`No se pudo verificar ${path}.`);}
    }
  }else checks.push({name:'Archivos expuestos',status:'Omitido: modo pasivo'});
  const tech=technologies(response.body.toString('utf8'),response.headers);
  for(const pkg of tech.packages) {
    signal?.throwIfAborted();
    const osvController=new AbortController();
    const abort=()=>osvController.abort();
    signal?.addEventListener('abort',abort,{once:true});
    const timer=setTimeout(abort,5000);
    try {
      const r=await osvFetch('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:{name:pkg.name,ecosystem:pkg.ecosystem},version:pkg.version}),signal:osvController.signal});
      if(!r.ok)throw new Error('OSV no disponible');
      let size=0;const chunks=[];
      for await(const chunk of r.body){size+=chunk.length;if(size>1048576){osvController.abort();throw new Error('Respuesta OSV demasiado grande');}chunks.push(Buffer.from(chunk));}
      const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      for(const v of (data.vulns||[]).filter(v=>!v.withdrawn).slice(0,15))add('Media',`${pkg.name} ${pkg.version}: ${String(v.id).slice(0,80)}`,`Posible coincidencia OSV por versión inferida de una URL. ${String(v.summary||'Vulnerabilidad conocida.').slice(0,350)} No confirma explotabilidad; severidad provisional.`, 'Confirma paquete y versión con tu inventario; revisa el aviso en OSV y actualiza a una versión corregida.');
      checks.push({name:`OSV · ${pkg.name}`,status:data.next_page_token?'Coincidencias parciales':`${(data.vulns||[]).length} avisos encontrados`});
      if(data.next_page_token)warnings.push('OSV devolvió más páginas: resultados parciales.');
    } catch {warnings.push(`OSV no disponible para ${pkg.name}: vulnerabilidades no verificadas.`);}
    finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  if(!tech.packages.length)warnings.push('No se identificaron versiones de paquetes compatibles con OSV. Esto no implica ausencia de vulnerabilidades.');
  findings.sort((a,b)=>weights[b.severity]-weights[a.severity]);
  const complete=response.status>=200&&response.status<300;
  return {url:final.origin+final.pathname,score:complete?Math.max(0,100-findings.reduce((n,f)=>n+weights[f.severity],0)):null,findings,checks,warnings,technologies:[...tech.banners,...tech.packages.map(p=>`${p.name} ${p.version} (inferido)`)],at:new Date().toISOString()};
}
