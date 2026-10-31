const ALLOWED_KINDS = new Set(["Browser script", "Browser asset", "Cloud storage", "Webhook", "Build / deploy", "Documentation", "API / external service"]);
const severities = ["Critical", "High", "Medium", "Low"];
const cors = origin => ({ "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin" });

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = env.ALLOWED_ORIGIN || "https://matthewl687.github.io";
    if (origin !== allowed) return new Response("Origin not allowed", { status: 403 });
    if (request.method === "OPTIONS") return new Response(null, { headers: cors(origin) });
    if (request.method !== "POST" || new URL(request.url).pathname !== "/scan") return new Response("Not found", { status: 404, headers: cors(origin) });
    try {
      const body = await request.json();
      const owner = String(body.owner || "").slice(0, 100), repo = String(body.repo || "").slice(0, 100);
      if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo) || !Array.isArray(body.references) || body.references.length > 500) return new Response("Invalid scan request", { status: 400, headers: cors(origin) });
      const refs = body.references.filter(x => x && typeof x.host === "string" && /^[a-z0-9.-]{1,253}$/i.test(x.host) && typeof x.file === "string" && x.file.length < 500).slice(0, 250).map(x => ({ ...x, kind: ALLOWED_KINDS.has(x.kind) ? x.kind : "API / external service", context: redact(String(x.context || "").slice(0, 500)) }));
      const evidence = [];
      const byHost = new Map();
      const findings = await mapLimit(refs, 8, async ref => {
        if (!byHost.has(ref.host)) byHost.set(ref.host, investigate(ref));
        const facts = await byHost.get(ref.host);
        evidence.push({ host: ref.host, label: facts.label, detail: facts.detail });
        return rank(ref, facts);
      });
      let reasoningMode = "Deterministic contextual ranking";
      if (env.META_MODEL_API_KEY && findings.length) {
        try { await reviewWithModel(findings, env.META_MODEL_API_KEY, env.TRUSTLINE_MODEL || "muse-spark-1.3"); reasoningMode = "Muse Spark reviewed · facts remain deterministic"; }
        catch { /* Model is optional; retain evidence-based ranking. */ }
      }
      findings.sort((a,b) => severities.indexOf(a.severity) - severities.indexOf(b.severity) || b.score-a.score);
      return Response.json({ findings, evidence, reasoningMode, checkedAt: new Date().toISOString() }, { headers: { ...cors(origin), "Cache-Control": "no-store" } });
    } catch (error) {
      return new Response(JSON.stringify({ error: "The public evidence scan could not be completed." }), { status: 500, headers: { ...cors(origin), "Content-Type": "application/json" } });
    }
  }
};

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length); let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (next < items.length) { const i = next++; try { out[i] = await fn(items[i]); } catch { out[i] = rank(items[i], { dns: "lookup failed", detail: "Public evidence lookup failed or timed out." }); } } }));
  return out;
}
async function getJson(url, timeout = 9000, headers = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeout);
  try { const r = await fetch(url, { signal: controller.signal, headers }); const body = await r.text(); let data = null; try { data = JSON.parse(body); } catch {} return { status: r.status, data, body: body.slice(0, 20000) }; }
  finally { clearTimeout(timer); }
}
function rootDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  const two = new Set(["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.nz","co.jp","com.br","com.cn","com.sg","com.mx","co.in"]);
  return labels.length > 2 ? labels.slice(two.has(labels.slice(-2).join(".")) ? -3 : -2).join(".") : host;
}
async function investigate(ref) {
  const host = ref.host.toLowerCase(), root = rootDomain(host), facts = { host, dns: "unknown", expiry: null, bucket: null, ct: null, archive: null };
  try {
    const dns = await getJson(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, 6000, { accept: "application/dns-json" });
    const ips = (dns.data?.Answer || []).filter(a => a.type === 1 || a.type === 28).map(a => a.data);
    facts.dns = ips.length ? "resolves" : dns.data?.Status === 3 ? "NXDOMAIN" : "no address returned";
    facts.addresses = ips.slice(0, 4);
  } catch { facts.dns = "DNS lookup failed"; }
  try {
    const r = await getJson(`https://rdap.org/domain/${encodeURIComponent(root)}`, 7000, { accept: "application/rdap+json, application/json" });
    const ev = r.data?.events || [];
    facts.expiry = ev.find(x => ["expiration", "expiry"].includes(String(x.eventAction).toLowerCase()))?.eventDate || null;
    const registrar = (r.data?.entities || []).find(x => (x.roles || []).includes("registrar"));
    facts.registrar = registrar?.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3] || null;
    facts.rdap = r.status === 404 ? "No registration record returned" : facts.expiry ? `Registration record found; expiry ${facts.expiry}` : r.status < 400 ? "Registration record found; expiry date unavailable" : `RDAP HTTP ${r.status}`;
  } catch { facts.rdap = "RDAP lookup unavailable"; }
  if (/s3[.-]|\.s3\.amazonaws\.com$|storage\.googleapis\.com$/.test(host)) {
    try {
      const u = new URL(ref.url); const candidate = /^(?:https?):$/.test(u.protocol) && (u.hostname === host);
      if (candidate && (/amazonaws\.com$/.test(host) || host === "storage.googleapis.com")) {
        const r = await fetch(u.href, { method: "GET", headers: { Range: "bytes=0-0" }, signal: AbortSignal.timeout(6000) });
        let body = "";
        if (r.body) { const reader = r.body.getReader(); while (body.length < 3000) { const { value, done } = await reader.read(); if (done) break; body += new TextDecoder().decode(value); } await reader.cancel(); }
        facts.bucket = /NoSuchBucket/i.test(body) ? "NoSuchBucket response" : `HTTP ${r.status}; bucket ownership not established`;
      }
    } catch { facts.bucket = "Storage probe failed; claimability unknown"; }
  }
  try {
    const ct = await getJson(`https://crt.sh/?q=%25.${encodeURIComponent(root)}&output=json`, 9000, { accept: "application/json" });
    if (Array.isArray(ct.data)) facts.ct = `${ct.data.length} certificate entries; latest ${ct.data.map(x => x.not_before).filter(Boolean).sort().at(-1) || "date unavailable"}`;
    else facts.ct = `Certificate log returned HTTP ${ct.status}`;
  } catch { facts.ct = "Certificate transparency lookup unavailable"; }
  try {
    const q = encodeURIComponent(`*.${root}/*`);
    const wb = await getJson(`https://web.archive.org/cdx/search/cdx?url=${q}&output=json&filter=statuscode:200&fl=timestamp,original&collapse=urlkey&limit=20`, 9000);
    facts.archive = Array.isArray(wb.data) ? `${Math.max(0,wb.data.length-1)} archived URL snapshots returned` : `Archive lookup returned HTTP ${wb.status}`;
  } catch { facts.archive = "Archive lookup unavailable"; }
  facts.label = "DNS · RDAP · CT · Archive";
  facts.detail = `DNS: ${facts.dns}; RDAP: ${facts.rdap}; CT: ${facts.ct}; Wayback: ${facts.archive}${facts.bucket ? `; storage: ${facts.bucket}` : ""}`;
  return facts;
}
function rank(ref, facts) {
  let score = ["Browser script", "Browser asset", "Cloud storage", "Webhook", "Build / deploy"].includes(ref.kind) ? 25 : ref.kind === "Documentation" ? 5 : 12;
  const reasons = [];
  if (["NXDOMAIN", "no address returned"].includes(facts.dns)) { score += 42; reasons.push(`The hostname currently has ${facts.dns === "NXDOMAIN" ? "an NXDOMAIN response" : "no address answer"}, which can indicate a stale or dangling reference.`); }
  if (facts.bucket === "NoSuchBucket response") { score += 55; reasons.push("The provider returned NoSuchBucket. This is a strong warning, but is not conclusive proof that the name is claimable."); }
  else if (facts.bucket) reasons.push("The storage probe did not confirm whether the resource name can be claimed.");
  if (facts.expiry) {
    const days = Math.ceil((Date.parse(facts.expiry) - Date.now()) / 86400000);
    if (days <= 30) { score += 32; reasons.push(`RDAP lists a registration expiry in ${Math.max(days,0)} days.`); }
  }
  if (["Browser script", "Cloud storage", "Build / deploy"].includes(ref.kind)) { score += 12; reasons.push(`A replacement in this ${ref.kind.toLowerCase()} context could affect a broad or sensitive part of the system.`); }
  if (!reasons.length) reasons.push("No immediate ownership warning was confirmed in available public checks. Keep this dependency in the inventory.");
  score = Math.min(score, 100);
  const severity = score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 35 ? "Medium" : "Low";
  const recommendation = ["NXDOMAIN", "no address returned"].includes(facts.dns) ? "Remove or replace the dangling reference. For required assets, use a domain or account your team controls." : facts.bucket === "NoSuchBucket response" ? "Verify the bucket name with its owner; recreate only in the intended account, or remove the abandoned reference." : ["Browser script", "Browser asset"].includes(ref.kind) ? "Pin the dependency and, where practical, self-host it or serve it from infrastructure your team controls." : "Confirm the current owner and business need, then remove or replace references that are no longer used.";
  return { ...ref, score, severity, explanation: reasons.join(" "), recommendation, uncertainty: `Point-in-time signals: DNS ${facts.dns}; ${facts.rdap}. Public records do not prove ownership intent or takeoverability.`, evidence: facts };
}
function redact(text) { return text.replace(/(api[_-]?key|token|secret|password)(\s*[:=]\s*)["']?[^\s,;"']+/gi, "$1$2[REDACTED]"); }
async function reviewWithModel(findings, key, model) {
  const prompt = `Review these external code references and deterministic evidence. Return JSON with a findings array, one per input, keys host, kind, severity (Critical/High/Medium/Low), explanation, recommendation, uncertainty. Only refine classification, priority and wording; do not alter or invent evidence or dates. Weigh execution context and blast radius.\n${JSON.stringify(findings.map(({host,kind,file,line,context,evidence,severity,score}) => ({host,kind,file,line,context,evidence,severity,score})))}`;
  const response = await fetch("https://api.meta.ai/v1/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify({ model, messages: [{ role: "user", content: prompt }], response_format: { type: "json_object" } }) });
  if (!response.ok) throw new Error("Model review unavailable");
  const data = await response.json(), parsed = JSON.parse(data.choices[0].message.content), suggestions = parsed.findings || [];
  const byHost = new Map(suggestions.filter(x => x && typeof x.host === "string").map(x => [x.host, x]));
  for (const item of findings) {
    const s = byHost.get(item.host); if (!s) continue;
    if (ALLOWED_KINDS.has(s.kind)) item.kind = s.kind;
    if (severities.includes(s.severity)) item.severity = s.severity;
    for (const field of ["explanation", "recommendation", "uncertainty"]) if (typeof s[field] === "string") item[field] = s[field].slice(0, 1200);
  }
}
