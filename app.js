const findings = [
  {host:"cdn.polyfill.io",url:"https://cdn.polyfill.io/v3/polyfill.min.js",file:"src/templates/base.html",line:18,type:"Browser script",status:"Does not resolve",statusKind:"offline",severity:"Critical",score:91,explanation:"This URL is loaded as a browser script, so a hostile replacement could run in every visitor's page. DNS currently returns no address. That is a dangling reference, but DNS alone does not prove that the domain is available to register.",fix:"Remove the script reference. Replace it with a maintained dependency pinned to a version, or self-host the asset.",evidence:"DNS: no answer · RDAP: no current record · checked just now",uncertainty:"A failed DNS lookup can be temporary. Verify registration status with the registrar before taking action."},
  {host:"assets.northstar-builds.s3.amazonaws.com",url:"https://assets.northstar-builds.s3.amazonaws.com/agent/latest",file:".github/workflows/deploy.yml",line:42,type:"Cloud storage",status:"NoSuchBucket response",statusKind:"warn",severity:"High",score:73,explanation:"A deployment workflow downloads an agent binary from this S3 bucket. The endpoint returned NoSuchBucket, a strong signal that the name may be unclaimed. If this workflow still runs, a re-registered bucket could supply a malicious build artifact.",fix:"Remove the stale download or move the artifact to a bucket in an account you control. Pin the artifact by version and checksum.",evidence:"S3 probe: NoSuchBucket · location: deploy workflow · checked just now",uncertainty:"Confirm the bucket region and deployment activity before concluding the name is claimable."},
  {host:"api.legacy-metrics.dev",url:"https://api.legacy-metrics.dev/v1/events",file:"src/lib/telemetry.ts",line:7,type:"API endpoint",status:"Expires in 21 days",statusKind:"warn",severity:"High",score:62,explanation:"This endpoint is called by the application at runtime. RDAP lists a registration expiry in 21 days. An expiry is not evidence of a handoff, but an unattended renewal could put the telemetry endpoint at risk.",fix:"Confirm the domain owner and renewal process. If this vendor is no longer in use, remove the endpoint and its client code.",evidence:"DNS: resolves · RDAP: expiry in 21 days · checked just now",uncertainty:"RDAP dates can change after renewal and do not establish the domain owner's intent."},
  {host:"fonts.googleapis.com",url:"https://fonts.googleapis.com/css2?family=Inter",file:"src/styles/theme.css",line:3,type:"Browser asset",status:"Resolves",statusKind:"ok",severity:"Low",score:18,file2:"src/styles/theme.css"},
  {host:"api.stripe.com",url:"https://api.stripe.com/v1",file:"src/billing/client.ts",line:12,type:"API endpoint",status:"Resolves",statusKind:"ok",severity:"Low",score:14},
  {host:"hooks.slack.com",url:"https://hooks.slack.com/services/…",file:"ops/notify.py",line:31,type:"Webhook",status:"Resolves",statusKind:"ok",severity:"Medium",score:34},
  {host:"registry.npmjs.org",url:"https://registry.npmjs.org/",file:"Dockerfile",line:16,type:"Build / deploy",status:"Resolves",statusKind:"ok",severity:"Low",score:12},
  {host:"images.unsplash.com",url:"https://images.unsplash.com/photo…",file:"src/pages/about.html",line:26,type:"Browser asset",status:"Resolves",statusKind:"ok",severity:"Low",score:9},
  {host:"api.mapbox.com",url:"https://api.mapbox.com/styles/v1/…",file:"src/maps/map.ts",line:8,type:"API endpoint",status:"Resolves",statusKind:"ok",severity:"Low",score:16},
  {host:"hooks.zapier.com",url:"https://hooks.zapier.com/hooks/catch/…",file:"config/automation.yml",line:15,type:"Webhook",status:"Resolves",statusKind:"ok",severity:"Medium",score:29},
  {host:"storage.googleapis.com",url:"https://storage.googleapis.com/northstar-assets/…",file:"scripts/release.sh",line:22,type:"Cloud storage",status:"Resolves",statusKind:"ok",severity:"Medium",score:32},
  {host:"cdn.jsdelivr.net",url:"https://cdn.jsdelivr.net/npm/lodash@…",file:"src/pages/legacy.html",line:39,type:"Browser script",status:"Resolves",statusKind:"ok",severity:"Medium",score:30}
];
let activeFilter="All", showAll=false, descending=true;
const body=document.querySelector("#findingsBody"), empty=document.querySelector("#emptyState");
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function render(){
  const q=document.querySelector("#searchInput").value.trim().toLowerCase();
  let rows=findings.filter(x=>(activeFilter==="All"||x.severity===activeFilter)&&(!q||`${x.host} ${x.file} ${x.type} ${x.status}`.toLowerCase().includes(q)));
  rows.sort((a,b)=>descending?b.score-a.score:a.score-b.score);
  const visible=showAll?rows:rows.slice(0,3);
  body.innerHTML=visible.map((x,i)=>`<tr data-index="${findings.indexOf(x)}"><td><div class="domain-cell"><span class="domain-icon">${x.type.includes("Cloud")?"◈":x.type.includes("Browser")?"◌":x.type.includes("Webhook")?"↗":"⌁"}</span><span class="domain-text"><b>${esc(x.host)}</b><small>${esc(x.url)}</small></span></div></td><td class="file-path">${esc(x.file.split("/").slice(0,-1).join("/")||"/")}<span> / </span>${esc(x.file.split("/").slice(-1)[0])}<span> :${x.line}</span></td><td><span class="type-pill ${x.type.includes("script")?"script":x.type.includes("Cloud")?"storage":x.type.includes("API")?"api":x.type.includes("Documentation")?"doc":""}">${esc(x.type)}</span></td><td><span class="status ${x.statusKind}"><i class="status-dot"></i>${esc(x.status)}</span></td><td><span class="priority ${x.severity.toLowerCase()}"><i></i>${esc(x.severity)}</span></td><td><button class="row-more" aria-label="Show details" title="Show details">···</button></td></tr>`).join("");
  empty.hidden=visible.length>0;
  document.querySelector("#showingText").innerHTML=`Showing <b>${visible.length}</b> of ${rows.length} references`;
  document.querySelector(".heading-count").textContent=String(findings.filter(x=>["Critical","High"].includes(x.severity)).length).padStart(2,"0");
  document.querySelector("#attentionMetric").textContent=String(findings.filter(x=>["Critical","High"].includes(x.severity)).length).padStart(2,"0");
  document.querySelector("#totalMetric").textContent=String(findings.length).padStart(2,"0");
}
body.addEventListener("click",e=>{const tr=e.target.closest("tr");if(!tr)return;const item=findings[Number(tr.dataset.index)];let next=tr.nextElementSibling;if(next?.classList.contains("detail-row")){next.remove();return}document.querySelectorAll(".detail-row").forEach(n=>n.remove());const detail=document.createElement("tr");detail.className="detail-row";detail.innerHTML=`<td colspan="6"><div class="finding-detail"><div><span class="detail-label">WHY IT MATTERS</span><p>${esc(item.explanation||"This reference is part of the external dependency inventory. No immediate warning was confirmed.")}</p></div><div><span class="detail-label">RECOMMENDED ACTION</span><p>${esc(item.fix||"Confirm that this dependency is still needed, and document its owner and renewal path.")}</p></div><div class="detail-evidence">${esc(item.evidence||"DNS: resolves · RDAP: record found · checked just now")}<br><span>Assessment includes uncertainty; verify before remediation.</span></div></div></td>`;tr.after(detail)});
document.querySelectorAll(".filter").forEach(el=>el.addEventListener("click",()=>{document.querySelectorAll(".filter").forEach(f=>f.classList.remove("active"));el.classList.add("active");activeFilter=el.dataset.filter;showAll=activeFilter==="All"?showAll:true;render()}));
document.querySelector("#searchInput").addEventListener("input",render);
document.querySelector("#sortButton").addEventListener("click",()=>{descending=!descending;document.querySelector("#sortButton").innerHTML=`${descending?"Priority ↓":"Priority ↑"} <span>⌄</span>`;render()});
document.querySelector("#viewAll").addEventListener("click",()=>{showAll=true;render();document.querySelector("#findings").scrollIntoView({behavior:"smooth",block:"start"})});
document.querySelectorAll(".nav-item").forEach(el=>el.addEventListener("click",()=>{document.querySelectorAll(".nav-item").forEach(n=>n.classList.remove("active"));el.classList.add("active");if(el.dataset.view!=="overview"){showAll=true;if(el.dataset.view==="alerts")activeFilter="High";else activeFilter="All";document.querySelectorAll(".filter").forEach(f=>f.classList.toggle("active",f.dataset.filter===activeFilter));render();document.querySelector("#findings").scrollIntoView({behavior:"smooth",block:"start"})}}));
const siteDialog=document.querySelector("#siteCheckDialog"),siteForm=document.querySelector("#siteCheckForm"),siteStatus=document.querySelector("#siteCheckStatus"),siteResults=document.querySelector("#siteCheckResults"),siteSubmit=document.querySelector("#siteCheckSubmit");
document.querySelector("#scanButton").addEventListener("click",()=>{siteDialog.showModal();document.querySelector("#siteUrl").focus()});
document.querySelector("#closeSiteCheck").addEventListener("click",()=>siteDialog.close());
siteDialog.addEventListener("click",e=>{if(e.target===siteDialog)siteDialog.close()});
function siteResult(title,detail,state="ok"){
  const row=document.createElement("article");row.className=`site-result ${state}`;
  const mark=document.createElement("span");mark.className="site-result-mark";mark.textContent=state==="ok"?"✓":state==="warn"?"!":"·";
  const copy=document.createElement("div");const name=document.createElement("b");name.textContent=title;const info=document.createElement("small");info.textContent=detail;copy.append(name,info);row.append(mark,copy);return row;
}
async function timedFetch(url,options={},ms=9000){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),ms);
  try{return await fetch(url,{...options,signal:controller.signal})}finally{clearTimeout(timer)}
}
function dnsValue(data){return data.Answer?.filter(x=>x.type!==5).map(x=>x.data.replace(/\.$/,"")).slice(0,3).join(", ")||"No records returned"}
async function checkWebsite(raw){
  let parsed;try{parsed=new URL(/^https?:\/\//i.test(raw.trim())?raw.trim():`https://${raw.trim()}`)}catch{throw new Error("Enter a valid website address, such as example.com.")}
  const host=parsed.hostname.toLowerCase().replace(/^www\./,"");
  if(!host.includes(".")||host.length>253||/[^a-z0-9.-]/.test(host)||host.startsWith(".")||host.endsWith("."))throw new Error("Enter a public domain name, such as example.com.");
  document.querySelector("#siteResultDomain").textContent=host;
  document.querySelector("#siteResultSummary").textContent="Checking public signals…";
  const list=document.querySelector("#siteResultList");list.replaceChildren();siteResults.hidden=false;
  const checks=[
    (async()=>{const [a,aaaa]=await Promise.all(["A","AAAA"].map(async type=>{const r=await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`,{headers:{accept:"application/dns-json"}});if(!r.ok)throw new Error("DNS lookup unavailable");return r.json()}));const answers=[...new Set([...(a.Answer||[]),...(aaaa.Answer||[])].filter(x=>x.type===1||x.type===28).map(x=>x.data))];return siteResult("Web address (DNS)",answers.length?answers.join(" · "):"No IPv4 or IPv6 address was returned.",answers.length?"ok":"warn")})(),
    (async()=>{const r=await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=CAA`,{headers:{accept:"application/dns-json"}});if(!r.ok)throw new Error("CAA lookup unavailable");const d=await r.json();return siteResult("Certificate issuer policy (CAA)",d.Answer?.length?dnsValue(d):"No CAA policy found; any certificate authority may be able to issue a certificate.",d.Answer?.length?"ok":"warn")})(),
    (async()=>{const r=await timedFetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(host)}&type=TXT`,{headers:{accept:"application/dns-json"}});if(!r.ok)throw new Error("DMARC lookup unavailable");const d=await r.json(),record=d.Answer?.find(x=>x.data.toLowerCase().includes("v=dmarc1"));return siteResult("Email spoofing policy (DMARC)",record?record.data.replaceAll('" "',"").replaceAll('"',""):"No DMARC record found for this domain.",record?"ok":"warn")})(),
    (async()=>{const r=await timedFetch(`https://rdap.org/domain/${encodeURIComponent(host)}`,{headers:{accept:"application/rdap+json, application/json"}});if(r.status===404)return siteResult("Domain registration","No public registration record was returned. Check that you entered the registered domain, not a subdomain.","warn");if(!r.ok)throw new Error("The registry did not return registration data.");const d=await r.json(),expires=d.events?.find(x=>x.eventAction==="expiration")?.eventDate,registrar=d.entities?.find(x=>x.roles?.includes("registrar"))?.vcardArray?.[1]?.find(x=>x[0]==="fn")?.[3];return siteResult("Domain registration",[registrar?`Registrar: ${registrar}`:null,expires?`Expiry: ${new Date(expires).toLocaleDateString()}`:"Registration record found"].filter(Boolean).join(" · "),"ok")})(),
    (async()=>{const r=await timedFetch(`https://crt.sh/?q=${encodeURIComponent(`%.${host}`)}&output=json`);if(!r.ok)throw new Error("Certificate records unavailable");const d=await r.json(),names=new Set((Array.isArray(d)?d:[]).flatMap(x=>String(x.name_value||"").split("\n").map(n=>n.trim().replace(/^\*\./,""))).filter(Boolean));return siteResult("Public certificates",names.size?`${names.size} name${names.size===1?"":"s"} found in certificate transparency logs. ${[...names].slice(0,4).join(" · ")}`:"No certificate names were returned.",names.size?"ok":"warn")})(),
    (async()=>{try{const r=await timedFetch(`https://${host}/`,{mode:"no-cors",method:"HEAD"},7000);return siteResult("HTTPS connection",r.type==="opaque"?"The browser connected over HTTPS. Cross-origin rules hide the website's response details.":`HTTPS responded with status ${r.status}.`,"ok")}catch{return siteResult("HTTPS connection","The browser could not complete an HTTPS connection. Check that HTTPS is enabled and the host is reachable.","bad")}})()
  ];
  const results=await Promise.all(checks.map(async p=>{try{return await p}catch(e){return siteResult("Lookup unavailable",e.name==="AbortError"?"This public service took too long to respond.":e.message||"A public lookup could not be completed.","warn")}}));
  list.replaceChildren(...results);
  const good=results.filter(x=>x.classList.contains("ok")).length;
  document.querySelector("#siteResultSummary").textContent=`${good} of ${results.length} checks returned useful results · ${new Date().toLocaleTimeString([], {hour:"numeric",minute:"2-digit"})}`;
}
siteForm.addEventListener("submit",async e=>{
  e.preventDefault();siteSubmit.disabled=true;siteResults.hidden=true;siteStatus.hidden=false;siteStatus.textContent="Checking public DNS, registration, certificates, and HTTPS…";
  try{await checkWebsite(document.querySelector("#siteUrl").value);siteStatus.hidden=true}
  catch(error){siteResults.hidden=true;siteStatus.textContent=error.message}
  finally{siteSubmit.disabled=false}
});
render();
