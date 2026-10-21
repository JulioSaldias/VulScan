const $=id=>document.getElementById(id);
const severities=['Crítica','Alta','Media','Baja','Informativa'];
const classes=['critical','high','medium','low','info'];
let report;
function el(tag,text,cls){const n=document.createElement(tag);n.textContent=text;if(cls)n.className=cls;return n;}
function renderFindings(){
  $('findings').replaceChildren();
  const list=report.findings.filter(f=>$('filter').value==='all'||f.severity===$('filter').value);
  if(!list.length)$('findings').append(el('p','No hay hallazgos en esta selección. Revisa la cobertura antes de interpretar el resultado.'));
  for(const f of list){const card=el('article','', 'finding');card.append(el('span',f.severity,`badge ${classes[severities.indexOf(f.severity)]}`),el('h3',f.title),el('p',f.description),el('p',`Recomendación: ${f.recommendation}`,'recommendation'));$('findings').append(card);}
}
$('filter').addEventListener('change',renderFindings);
$('scan-form').addEventListener('submit',async e=>{
  e.preventDefault();$('error').hidden=true;$('results').hidden=true;$('loading').hidden=false;$('analyze').disabled=true;$('scan-form').setAttribute('aria-busy','true');
  try{
    const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('url').value,authorized:$('authorized').checked,exposure:$('exposure').checked}),signal:AbortSignal.timeout(55000)});
    const data=await response.json();if(!response.ok)throw new Error(data.error||'No se pudo analizar el sitio.');report=data;
    $('score').textContent=report.score??'—';$('target').textContent=report.url;$('date').textContent=new Date(report.at).toLocaleString('es');
    $('counts').replaceChildren();severities.forEach((s,i)=>{const n=el('div','',`count ${classes[i]}`);n.append(el('span',s),el('strong',String(report.findings.filter(f=>f.severity===s).length)));$('counts').append(n);});
    $('filter').value='all';renderFindings();$('checks').replaceChildren(...report.checks.map(c=>el('li',`${c.name}: ${c.status}`)));$('warnings').replaceChildren(...report.warnings.map(w=>el('li',w)));$('technologies').textContent=`Tecnologías / banners: ${report.technologies.join(', ')||'no identificados'}`;
    $('results').hidden=false;$('results').focus();
  }catch(error){$('error').textContent=error.name==='TimeoutError'?'El análisis agotó el tiempo disponible. Intenta de nuevo más tarde.':error.message;$('error').hidden=false;}
  finally{$('loading').hidden=true;$('analyze').disabled=false;$('scan-form').removeAttribute('aria-busy');}
});
$('download').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='vulscan-informe.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
