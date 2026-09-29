(() => {
"use strict";
const $=id=>document.getElementById(id),node=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};
const samples={support:"Contact demo.person@example.test at +1-202-555-0182 about ticket PG-42.",finance:"Email finance@example.test about test card 4111 1111 1111 1111 and the $1,284.50 invoice.",security:"A fictional log contains sk-example00000000000000000000. Notify security@example.test.",unicode:"こんにちは、連絡先は demo.person@example.test です。"};
let presets=null,last=null,benchmark=null,key=null,epoch=0,busy=false;
function resetOutput(){last=null;key=null;$('lab-protected').textContent='Your transform will appear here.';$('lab-restored').textContent='Irreversible actions stay transformed.';$('lab-trace').replaceChildren();$('lab-restore').disabled=true;$('lab-export').disabled=true;}
function choose(){resetOutput();$('lab-source').value=samples[$('lab-case').value];$('lab-status').textContent='Fictional sample loaded. Transform when ready.';}
function traceTable(trace){
 const root=$('lab-trace');root.replaceChildren();if(!trace){root.append(node('p','This gateway did not return a policy trace.'));return;}
 root.append(node('h3','Follow each policy decision'),node('p','Configured detectors: '+trace.detectors.join(', ')+' · UTF-8 byte offsets'));
 const wrap=node('div');wrap.className='trace-wrap';const table=node('table');table.className='trace-table';const head=node('tr');['Entity / detector','Byte span','Confidence / threshold','Action','Outcome'].forEach(v=>head.append(node('th',v)));table.append(head);
 trace.decisions.forEach(d=>{const tr=node('tr');[d.entity+' / '+d.detector,d.start+'–'+d.end,d.confidence_ppm+' / '+d.minimum_confidence_ppm,d.action,d.outcome.replaceAll('_',' ')].forEach(v=>tr.append(node('td',v)));table.append(tr);});wrap.append(table);root.append(wrap);
 if(!trace.decisions.length)root.append(node('p',trace.state==='blocked'?'Transform stopped before decisions completed.':'No candidate was selected. This does not prove that the input is free of sensitive data.'));
 if(trace.gate)root.append(node('p','Blocking gate: '+trace.gate));
 const details=node('details'),pre=node('pre');pre.textContent=JSON.stringify({rules:trace.rules,precedence:trace.precedence,limitations:trace.limitations},null,2);details.append(node('summary','Inspect rules, precedence and limits'),pre);root.append(details);
}
function download(name,value){const u=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'})),a=node('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);}
async function json(url,body){const res=await fetch(url,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),data=await res.json();if(!res.ok)throw Error(typeof data.detail==='string'?data.detail:'Gateway returned HTTP '+res.status);return data;}
$('lab-form').addEventListener('submit',async event=>{
 event.preventDefault();if(!presets||busy||!$('lab-form').reportValidity())return;
 busy=true;const owner=++epoch;resetOutput();$('lab-run').disabled=true;$('lab-status').textContent='Running the local privacy engine…';
 try{
  const policy=structuredClone(presets[$('lab-preset').value]);policy.mapping_retention_seconds=60;policy.audit_retention_seconds=60;
  const email=policy.rules.find(r=>r.entity==='EMAIL_ADDRESS');email.action=$('lab-email').value;email.reversible=email.action==='tokenize';email.minimum_confidence_ppm=Number($('lab-confidence').value);email.scopes=$('lab-scope').checked?['json:/contact']:['*'];email.required_detectors=$('lab-required').checked?['presidio-v1']:[];
  policy.allow_terms=$('lab-allow').value.trim()?[$('lab-allow').value.trim()]:[];
  if($('lab-key').checked){const bytes=crypto.getRandomValues(new Uint8Array(32));key=btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');}
  const doc=await json('/v1/transform',{text:$('lab-source').value,policy,restore_key:key,include_policy_trace:true});
  // A copied capsule is independent of the server session; keep recovery only in memory.
  let cleanup='Temporary gateway session deleted.';
  try{const removed=await fetch('/v1/sessions/'+encodeURIComponent(doc.session_id),{method:'DELETE'});if(!removed.ok)throw Error();}catch{cleanup='Session cleanup failed; server retention still applies.';}
  if(owner!==epoch)return;last=doc;$('lab-protected').textContent=doc.text??'BLOCKED · No output to forward.';traceTable(doc.policy_trace);$('lab-export').disabled=!doc.policy_trace;$('lab-restore').disabled=!(doc.capsule&&key);
  $('lab-status').textContent=(doc.state==='blocked'?'Blocked: '+doc.reason:doc.detections.length+' transformation(s) applied. No upstream API called.')+' '+cleanup;
 }catch(err){if(owner===epoch)$('lab-status').textContent='Walkthrough failed: '+err.message;}
 finally{busy=false;$('lab-run').disabled=!presets;}
});
$('lab-restore').addEventListener('click',async()=>{
 const snapshot=last,recovery=key,owner=epoch;if(!snapshot?.capsule||!recovery)return;
 try{const doc=await json('/v1/restore/capsule',{text:snapshot.text,session_id:snapshot.session_id,capsule:snapshot.capsule,restore_key:recovery});if(owner!==epoch)return;$('lab-restored').textContent=doc.text;$('lab-status').textContent='Approved values restored from the sealed capsule. Irreversible replacements remain.';}catch(err){if(owner===epoch)$('lab-status').textContent='Restoration failed: '+err.message;}
});
$('lab-export').addEventListener('click',()=>{if(last?.policy_trace)download('privacy-policy-trace.json',last.policy_trace);});
$('lab-clear').addEventListener('click',()=>{++epoch;resetOutput();$('lab-source').value='';$('lab-allow').value='';$('lab-status').textContent='Source, capsule and recovery key cleared from this page.';});
$('lab-case').addEventListener('change',()=>{++epoch;choose();});
$('lab-form').addEventListener('input',()=>{++epoch;resetOutput();$('lab-status').textContent='Inputs changed. Transform again to inspect the new policy.';});
$('benchmark-run').addEventListener('click',async()=>{
 const button=$('benchmark-run');button.disabled=true;benchmark=null;$('benchmark-export').disabled=true;$('benchmark-status').textContent='Measuring the configured engine on invented labeled cases…';$('benchmark-result').replaceChildren();
 try{benchmark=await json('/v1/benchmark/demo',{});const root=$('benchmark-result'),m=benchmark.accuracy,stats=node('div');stats.className='trace-stats';[['Exact true positives',m.true_positives],['False positives',m.false_positives],['Missed spans',m.false_negatives],['Median transform (ms)',benchmark.timing.median_ms.toFixed(2)]].forEach(([label,value])=>{const tile=node('div');tile.append(node('strong',String(value)),node('span',label));stats.append(tile);});root.append(stats,node('p','Detector set: '+benchmark.provenance.detectors.join(', ')));const details=node('details');details.append(node('summary','Inspect every case and reproducibility record'),node('pre',JSON.stringify(benchmark,null,2)));root.append(details);$('benchmark-export').disabled=false;$('benchmark-status').textContent='Benchmark complete. Small fixture corpus; observed coverage is not a production guarantee.';}catch(err){$('benchmark-status').textContent='Benchmark failed: '+err.message;}finally{button.disabled=false;}
});
$('benchmark-export').addEventListener('click',()=>{if(benchmark)download('privacy-benchmark.json',benchmark);});
choose();json('/v1/presets').then(value=>{presets=value;$('lab-run').disabled=false;$('lab-status').textContent='Gateway ready. Fictional samples run only when you click Transform.';}).catch(()=>{$('lab-status').textContent='Live gateway unavailable. Start privacy-gateway serve and open /walkthrough to run the actual engine.';});
})();
