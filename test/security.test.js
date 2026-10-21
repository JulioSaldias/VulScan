import test from 'node:test';
import assert from 'node:assert/strict';
import {parseTarget,publicIP,resolvePublic} from '../network.js';
import {inspectHeaders,exposed,scan,technologies} from '../scanner.js';
import {createApp,RateGate} from '../server.js';

test('SSRF: loopback, private, metadata, reserved and disguised IPs are blocked',()=>{
  for(const ip of ['127.0.0.1','0.0.0.0','10.1.2.3','172.16.1.1','192.168.1.1','169.254.169.254','100.64.0.1','192.0.2.1','198.18.0.1','224.0.0.1','240.0.0.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','2002:7f00:1::'])assert.equal(publicIP(ip),false,ip);
  for(const u of ['file:///etc/passwd','ftp://example.com','http://localhost','http://local','http://foo.internal','http://2130706433','http://0x7f000001','http://0177.0.0.1','http://[::1]','https://user:pass@example.com','https://example.com:8080'])assert.throws(()=>parseTarget(u),undefined,u);
  assert.equal(publicIP('8.8.8.8'),true);assert.equal(publicIP('2606:4700:4700::1111'),true);
});
test('Mixed public/private DNS responses fail closed',async()=>{
  await assert.rejects(resolvePublic('example.com',async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]));
  assert.deepEqual(await resolvePublic('example.com',async()=>[{address:'8.8.8.8',family:4}]),{address:'8.8.8.8',family:4});
});
test('Sensitive file signatures reject HTML fallback and do not require secret values in report',()=>{
  assert.equal(exposed('env',Buffer.from('<html>APP_KEY=foo</html>')),false);
  assert.equal(exposed('env',Buffer.from('APP_KEY=secret')),true);
  assert.equal(exposed('git',Buffer.from('ref: refs/heads/main\n')),true);
  assert.equal(exposed('zip',Buffer.from([80,75,3,4,0])),true);
  assert.equal(exposed('robots',Buffer.from('User-agent: *\nDisallow: /admin')),true);
});
test('Cookie attributes parsed independently of secret cookie value',()=>{
  const f=inspectHeaders({'set-cookie':['s=Secure; SameSite=None']},true);
  assert.ok(f.some(x=>x.description.includes('Secure, HttpOnly')));
  assert.ok(!JSON.stringify(f).includes('s=Secure'));
});
test('Fingerprint detects explicit versions only',()=>{
  assert.equal(technologies('<script src="jquery.js"></script>',{}).packages.length,0);
  assert.equal(technologies('<script src="jquery-3.4.1.min.js"></script>',{}).packages[0].version,'3.4.1');
});
test('Passive scan requests one page, optional exposure is bounded and secrets are redacted',async()=>{
  const calls=[];const request=async u=>{calls.push(String(u));return {url:String(u),status:200,headers:{},body:Buffer.from(String(u).endsWith('/.env')?'APP_KEY=never-expose-this':'<html>Hello</html>'),tls:null};};
  const passive=await scan('https://example.com',{request});assert.equal(calls.length,1);assert.ok(passive.score>=0&&passive.score<=100);
  calls.length=0;const active=await scan('https://example.com',{request,exposure:true});assert.equal(calls.length,6);assert.ok(active.findings.some(x=>x.severity==='Crítica'));assert.ok(!JSON.stringify(active).includes('never-expose-this'));
});
test('OSV failures and HTTP errors do not imply a clean scan',async()=>{
  const request=async()=>({url:'https://example.com/',status:403,headers:{},body:Buffer.from('jquery-3.4.1.min.js'),tls:null});
  const r=await scan('https://example.com',{request,osvFetch:async()=>{throw new Error('offline');}});assert.equal(r.score,null);assert.ok(r.warnings.some(w=>w.includes('OSV no disponible')));
});
test('Rate gate enforces quota and concurrency',()=>{
  const g=new RateGate();assert.equal(g.take('a',0),true);assert.equal(g.take('b',0),true);assert.equal(g.take('c',0),true);assert.equal(g.take('d',0),false);g.release();assert.equal(g.take('d',0),true);
  const q=new RateGate();for(let i=0;i<5;i++){assert.equal(q.take('a',0),true);q.release();}assert.equal(q.take('a',1),false);assert.equal(q.take('a',600001),true);
});
test('OSV matches are provisional and withdrawn advisories are ignored',async()=>{
  const request=async()=>({url:'https://example.com/',status:200,headers:{},body:Buffer.from('jquery-3.4.1.min.js'),tls:{expires:'Jan 01 2030 00:00:00 GMT',protocol:'TLSv1.3'}});
  const osvFetch=async(_url,options)=>{
    assert.deepEqual(JSON.parse(options.body),{package:{name:'jquery',ecosystem:'npm'},version:'3.4.1'});
    return new Response(JSON.stringify({vulns:[{id:'TEST-001',summary:'Fixture advisory'},{id:'TEST-002',withdrawn:'2025-01-01'}]}));
  };
  const r=await scan('https://example.com',{request,osvFetch});
  assert.ok(r.findings.some(f=>f.title.includes('TEST-001')&&f.description.includes('No confirma explotabilidad')));
  assert.ok(!r.findings.some(f=>f.title.includes('TEST-002')));
});
test('OSV oversized responses are bounded and reported as unavailable',async()=>{
  const request=async()=>({url:'https://example.com/',status:200,headers:{},body:Buffer.from('jquery-3.4.1.min.js'),tls:null});
  const r=await scan('https://example.com',{request,osvFetch:async()=>new Response('x'.repeat(1048577))});
  assert.ok(r.warnings.some(w=>w.includes('OSV no disponible')));
});
test('HTTP API: validation, authorization, CSP, rate and no forwarded-IP spoofing',async t=>{
  const app=createApp({scanner:async()=>({score:100,findings:[]})});await new Promise(r=>app.listen(0,'127.0.0.1',r));t.after(()=>{app.closeAllConnections();app.close();});
  const base=`http://127.0.0.1:${app.address().port}`;
  const page=await fetch(base);assert.equal(page.status,200);assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  const send=body=>fetch(base+'/api/scan',{method:'POST',headers:{'Content-Type':'application/json','X-Forwarded-For':Math.random().toString()},body:JSON.stringify(body)});
  assert.equal((await send({url:'https://example.com'})).status,400);
  assert.equal((await send({url:'http://127.0.0.1',authorized:true})).status,400);
  for(let i=0;i<3;i++)assert.equal((await send({url:'https://example.com',authorized:true})).status,200);
  assert.equal((await send({url:'https://example.com',authorized:true})).status,429);
  const cross=await fetch(base+'/api/scan',{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://evil.example'},body:'{}'});assert.equal(cross.status,403);
  assert.equal((await fetch(base+'/.env')).status,404);
});
