import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {scan} from './scanner.js';
import {parseTarget} from './network.js';

export class RateGate {
  constructor(){this.windows=new Map();this.active=0;}
  take(key,now=Date.now()) {
    for(const [k,v] of this.windows)if(v.until<=now)this.windows.delete(k);
    const v=this.windows.get(key)||{count:0,until:now+600000};
    if(this.active>=3 || this.windows.size>=10000 || v.count>=5)return false;
    v.count++;this.windows.set(key,v);this.active++;return true;
  }
  release(){this.active=Math.max(0,this.active-1);}
}
const security={
  'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security':'max-age=31536000','Cache-Control':'no-store'
};
export function createApp({scanner=scan,gate=new RateGate()}={}) {
  const server=http.createServer(async(req,res)=>{
    for(const [k,v] of Object.entries(security))res.setHeader(k,v);
    const json=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
    if(req.method==='GET'&&req.url==='/health')return json(200,{ok:true});
    if(req.method==='POST'&&req.url==='/api/scan') {
      // No trust in X-Forwarded-For. Behind proxies this deliberately shares the quota.
      if(req.headers['sec-fetch-site']==='cross-site')return json(403,{error:'Origen no permitido.'});
      if(req.headers.origin){try{if(new URL(req.headers.origin).host!==req.headers.host)return json(403,{error:'Origen no permitido.'});}catch{return json(403,{error:'Origen inválido.'});}}
      if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']||''))return json(415,{error:'Se requiere JSON.'});
      const key=req.socket.remoteAddress||'unknown';
      if(!gate.take(key)){res.setHeader('Retry-After','600');return json(429,{error:'Límite alcanzado: 5 análisis cada 10 minutos o servidor ocupado. Intenta más tarde.'});}
      const controller=new AbortController();
      const deadline=setTimeout(()=>controller.abort(),50000);
      const disconnected=()=>{if(!res.writableEnded)controller.abort();};
      res.on('close',disconnected);
      try{
        let size=0, chunks=[];
        await new Promise((resolve,reject)=>{
          const timer=setTimeout(()=>{reject(new Error('Solicitud incompleta.'));},5000);
          req.on('data',chunk=>{size+=chunk.length;if(size>4096){clearTimeout(timer);reject(new Error('Solicitud demasiado grande.'));req.resume();}else chunks.push(chunk);});
          req.on('end',()=>{clearTimeout(timer);resolve();});
          req.on('error',e=>{clearTimeout(timer);reject(e);});
        });
        let body;try{body=JSON.parse(Buffer.concat(chunks).toString());}catch{throw new Error('JSON inválido.');}
        if(!body||body.authorized!==true)throw new Error('Confirma que tienes autorización para analizar este sitio.');
        parseTarget(body.url);
        const report=await scanner(body.url,{exposure:body.exposure===true,signal:controller.signal});
        if(!res.destroyed)json(200,report);
      }catch(error){
        const known=/URL|HTTP|puerto|credenciales|Destino|DNS apunta|JSON|Solicitud|Confirma|Ingresa|Redirección|Demasiadas|Tiempo/.test(error.message);
        if(!res.destroyed)json(400,{error:known?error.message:'No se pudo completar el análisis. Verifica la URL y vuelve a intentar.'});
      }finally{clearTimeout(deadline);gate.release();res.off('close',disconnected);}
      return;
    }
    const assets={'/':['index.html','text/html'],'/app.js':['app.js','text/javascript'],'/style.css':['style.css','text/css']};
    if(req.method==='GET'&&Object.hasOwn(assets,req.url)){
      const [name,type]=assets[req.url];
      try{const content=await readFile(new URL(`./public/${name}`,import.meta.url));res.writeHead(200,{'Content-Type':`${type}; charset=utf-8`});res.end(content);}catch{json(500,{error:'Archivo no disponible.'});}
    }else json(404,{error:'No encontrado.'});
  });
  server.requestTimeout=10000;server.headersTimeout=10000;server.maxHeadersCount=40;
  return server;
}
if(process.argv[1]===fileURLToPath(import.meta.url))createApp().listen(Number(process.env.PORT)||3000,'0.0.0.0',()=>console.log('VulScan listo'));
