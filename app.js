// Set this to the deployed Worker URL to enable RDAP, DNS, bucket, CT,
// Wayback, and optional Muse Spark analysis. Repository inventory works without it.
const API_URL = window.TRUSTLINE_API_URL || "";
const form = document.querySelector("#scanForm");
const landing = document.querySelector("#landing");
const report = document.querySelector("#report");
const input = document.querySelector("#repoUrl");
const submit = form.querySelector("button[type=submit]");
const formError = document.querySelector("#formError");
const MAX_FILES = 220;
const MAX_BYTES = 1_200_000;
const SKIP = new Set([".git", "node_modules", "vendor", "dist", "build", ".next", "coverage", "target"]);
const PUBLIC_TLDS = new Set(("com org net edu gov mil int io ai dev app tech xyz info biz me co us uk ca au nz jp de fr es it nl se no fi ch at ru cn in br za tv cloud online site store blog museum aero name pro mobi travel jobs cat asia tel xxx post zip mov music live world design software digital company agency network systems security services solutions academy exchange finance consulting photography media email website today space fun club life news group center studio codes tools support ly gg fm cc ws ac") .split(" "));
const PUBLIC_SUFFIXES = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "com.cn", "com.sg", "com.mx", "co.in"]);
const URL_RE = /\b(?:https?:\/\/|s3:\/\/|gs:\/\/)[^\s"'<>`\])}]+/gi;
const HOST_RE = /(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s"'<>`]*)?/gi;

function parseRepo(raw) {
  let url;
  try { url = new URL(raw.trim()); } catch { throw new Error("Paste a public GitHub repository link, such as https://github.com/owner/repository."); }
  const parts = url.pathname.split("/").filter(Boolean);
  if (url.hostname.toLowerCase() !== "github.com" || parts.length < 2 || !/^[\w.-]+$/.test(parts[0]) || !/^[\w.-]+$/.test(parts[1]))
    throw new Error("Enter a public GitHub repository link in the form github.com/owner/repository.");
  return { owner: parts[0], repo: parts[1].replace(/\.git$/i, "") };
}
async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (!response.ok) throw new Error(response.status === 404 ? "Repository not found or not public." : `GitHub returned ${response.status}. Public API rate limits may apply.`);
  return response.json();
}
function classify(path, context, url) {
  const text = `${path} ${context} ${url}`.toLowerCase();
  let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch {}
  if (/^(?:s3|gs):\/\//i.test(url) || host === "storage.googleapis.com" || /(?:^|\.)s3[.-]|\.s3\.amazonaws\.com$/.test(host) || /\b(?:s3_bucket|bucket_name|storage_bucket)\b/i.test(context)) return "Cloud storage";
  if (/<script\b|script[_-]?src/i.test(context) || (/\bsrc\s*=/i.test(context) && /\.js(?:[?#]|$)/i.test(url))) return "Browser script";
  if (/<(?:link|img|source)\b|\b(?:href|src)\s*=/i.test(context) || /fonts\./i.test(host) || (/\.css(?:[?#]|$)/i.test(url) && /stylesheet/i.test(context))) return "Browser asset";
  if (/webhook|callback|notify_url/.test(text)) return "Webhook";
  if (/dockerfile|workflow|deploy|terraform|ansible|\.ya?ml/.test(text)) return "Build / deploy";
  if (/readme|docs\/|documentation|changelog|\.md\b/.test(text)) return "Documentation";
  return "API / external service";
}
function refsFromFiles(files) {
  const found = new Map();
  for (const file of files) {
    const spans = [];
    const text = file.text;
    for (const pattern of [URL_RE, HOST_RE]) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text))) {
        const startAt = match.index, endAt = match.index + match[0].length;
        if (spans.some(([start, end]) => startAt < end && endAt > start)) continue;
        spans.push([startAt, endAt]);
        let raw = match[0].replace(/[.,;:!?)\]}]+$/, "");
        if (raw.startsWith("//")) continue;
        let normalized = raw.includes("://") ? raw : `https://${raw}`;
        if (/^s3:\/\//i.test(raw)) {
          const storage = raw.slice(5).split("/");
          normalized = `https://${storage[0]}.s3.amazonaws.com/${storage.slice(1).join("/")}`;
        } else if (/^gs:\/\//i.test(raw)) {
          const storage = raw.slice(5).split("/");
          normalized = `https://storage.googleapis.com/${storage.join("/")}`;
        }
        let parsed;
        try { parsed = new URL(normalized); } catch { continue; }
        const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
        if (!host.includes(".") || ["example.com", "example.org", "example.net", "localhost"].includes(host) || host.split(".").includes("example") || PUBLIC_SUFFIXES.has(host) || /\.(png|jpg|jpeg|gif|svg|webp|woff2?)$/i.test(host)) continue;
        if (!raw.includes("://") && !PUBLIC_TLDS.has(host.split(".").at(-1))) continue;
        if (!raw.includes("://") && /[(_$a-z0-9]/i.test(text[endAt] || "")) continue;
        const line = text.slice(0, startAt).split("\n").length;
        const key = `${host}\n${file.path}`;
        const before = text.slice(Math.max(0, startAt - 180), startAt);
        const after = text.slice(startAt, Math.min(text.length, endAt + 240));
        if (!found.has(key)) found.set(key, { host, url: normalized, file: file.path, line, context: `${before}${after}`.replace(/\s+/g, " ").slice(0, 480), references: 0 });
        found.get(key).references++;
      }
    }
  }
  return [...found.values()].map(x => ({ ...x, kind: classify(x.file, x.context, x.url) }));
}
async function fetchRepoFiles({ owner, repo }) {
  const meta = await fetchJson(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
  const branch = meta.default_branch || "main";
  const tree = await fetchJson(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  if (tree.truncated) throw new Error("This repository is too large for a complete public scan. Try a smaller repository or configure the Trustline Worker.");
  const eligible = tree.tree.filter(x => x.type === "blob" && x.size <= 160_000 && !x.path.split("/").some(part => SKIP.has(part)) && !/\.(png|jpe?g|gif|webp|ico|pdf|zip|woff2?|ttf|mp[34]|lock)$/i.test(x.path)).slice(0, MAX_FILES);
  const files = [];
  let bytes = 0;
  for (let i = 0; i < eligible.length && files.length < MAX_FILES && bytes < MAX_BYTES; i += 8) {
    const batch = await Promise.all(eligible.slice(i, i + 8).map(async item => {
      try {
        const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${item.path.split("/").map(encodeURIComponent).join("/")}`;
        const response = await fetch(rawUrl);
        if (!response.ok) return null;
        const text = await response.text();
        return { path: item.path, text, size: text.length };
      } catch { return null; }
    }));
    for (const file of batch) if (file && bytes + file.size <= MAX_BYTES) { files.push(file); bytes += file.size; }
  }
  return { meta, branch, files, truncated: eligible.length > files.length };
}
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" })[c]); }
function signalCard(title, value, detail, state = "good") {
  return `<article class="signal-card ${state}"><div class="signal-card-top"><span class="signal-label">${escapeHtml(title.toUpperCase())}</span><span class="signal-value">${state === "good" ? "✓" : state === "review" ? "!" : "·"}</span></div><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></article>`;
}
function fallbackAdvice(ref) {
  const context = `${ref.file} ${ref.context || ""} ${ref.url || ""}`.toLowerCase();
  if (ref.kind === "Browser script") return "Pin this script to a reviewed version, add Subresource Integrity when the host supports it, and self-host it if you need stable control over what runs in visitors’ browsers.";
  if (ref.kind === "Browser asset") return "Confirm this asset is still used by the page. Pin or self-host fonts, stylesheets, and other browser-loaded files where practical, and remove stale includes.";
  if (ref.kind === "Cloud storage") return "Verify the bucket name and owning cloud account. Remove abandoned bucket URLs; for active buckets, restrict write access and serve only the objects this code needs.";
  if (ref.kind === "Webhook") return "Verify the receiver is still controlled by the intended team, authenticate webhook requests, and rotate any signing secret if the endpoint or owner changed.";
  if (ref.kind === "Build / deploy") return "Check that this endpoint is still part of the release path. Pin referenced actions, images, and downloads to immutable versions or digests, and remove unused workflow targets.";
  if (ref.kind === "Documentation") return "Check whether this link is still relevant and points to the intended publisher. Update or remove stale links; avoid relying on documentation links as production dependencies.";
  if (/webhook|callback|notify/.test(context)) return "Confirm the endpoint is still operated by the expected service, authenticate requests, and rotate any associated credential if ownership changed.";
  if (/api[_-]?key|token|secret|authorization/.test(context)) return "Confirm this is the intended API host and keep credentials in a secret store. Restrict credentials to the required service and rotate them if the endpoint owner is uncertain.";
  return "Confirm this hostname is an intentional runtime dependency and is controlled by the expected provider. Remove stale references; for critical services, document an owner and a replacement plan.";
}
function renderReport(repoInfo, files, refs, remoteReport = null) {
  const name = `${repoInfo.owner}/${repoInfo.repo}`;
  document.querySelector("#reportDomain").textContent = name;
  const link = document.querySelector("#reportUrl"); link.href = `https://github.com/${name}`; link.textContent = link.href;
  document.querySelector("#checkedAt").textContent = new Date().toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  const inv = document.querySelector("#signalGrid");
  inv.innerHTML = [signalCard("Files reviewed", files.length, "Text files from the default branch"), signalCard("External references", refs.length, "Unique hostname and file pairs"), signalCard("File inventory", remoteReport ? "Server checks" : "Browser mode", remoteReport ? "Current public ownership evidence" : "Some cross-origin checks need the secure service", remoteReport ? "good" : "review")].join("");
  const ordered = remoteReport?.findings || refs.map(ref => ({ ...ref, severity: "Unranked", score: null, explanation: `Found in ${ref.file}:${ref.line} and classified as ${ref.kind.toLowerCase()} from its nearby source context. Current ownership and availability evidence is not connected in this report.`, recommendation: fallbackAdvice(ref), uncertainty: "This is source context only; no current DNS, registration, storage, certificate-history, or archive evidence was collected, so no takeoverability conclusion is possible." }));
  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Unranked: 4 };
  ordered.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4) || (b.score || 0) - (a.score || 0));
  const list = document.querySelector("#findingList"); list.replaceChildren();
  document.querySelector("#findingCount").textContent = String(ordered.length).padStart(2, "0");
  if (!ordered.length) list.innerHTML = '<div class="empty-findings">No external hostnames were found in the files reviewed. This does not prove the repository has no runtime dependencies.</div>';
  for (const item of ordered) {
    const level = item.severity === "Critical" || item.severity === "High" ? "high" : item.severity === "Medium" ? "medium" : "info";
    const card = document.createElement("article"); card.className = `finding-card ${level}`;
    card.innerHTML = `<i class="finding-bar"></i><div class="finding-main"><h3>${escapeHtml(item.host)} <span class="finding-kind">· ${escapeHtml(item.kind)}</span></h3><p>${escapeHtml(item.explanation)}</p><p class="finding-source"><a target="_blank" rel="noreferrer" href="https://github.com/${encodeURIComponent(repoInfo.owner)}/${encodeURIComponent(repoInfo.repo)}/blob/${encodeURIComponent(repoInfo.branch)}/${item.file.split("/").map(encodeURIComponent).join("/")}#L${item.line}">${escapeHtml(item.file)}:${item.line}</a> · ${item.references || 1} reference(s)</p><p class="recommendation">Suggested fix: ${escapeHtml(item.recommendation || "Review whether this reference is still needed.")}</p><p class="finding-uncertainty">Uncertainty: ${escapeHtml(item.uncertainty || "Evidence is point-in-time and does not prove takeoverability.")}</p></div><span class="finding-meta">${escapeHtml(item.severity || "UNRANKED")}${item.score != null ? ` · ${item.score}/100` : ""}</span>`;
    list.append(card);
  }
  document.querySelector("#overviewTitle").textContent = remoteReport ? `${ordered.length} external references investigated` : `${refs.length} external references inventoried`;
  document.querySelector("#overviewText").textContent = remoteReport ? "Findings combine deterministic public evidence with contextual risk ranking. Review the evidence and uncertainty before acting." : "This is a source inventory only. Add the Trustline Worker to investigate RDAP, DNS, storage, certificate history, archives, and optional agentic reasoning.";
  document.querySelector("#overviewBanner").className = `overview-banner ${remoteReport && ordered.some(x => ["Critical", "High"].includes(x.severity)) ? "warn" : ""}`;
  document.querySelector("#overviewIcon").textContent = remoteReport ? "◎" : "i";
  document.querySelector("#scopeText").textContent = `${files.length} text files scanned from ${repoInfo.branch}. ${refs.length} unique host/file references were extracted. ${remoteReport ? "External evidence is point-in-time; a missing DNS response or storage error is not by itself proof of a takeover." : "The free static page can inventory public repository code. To safely access RDAP, DNS, storage, certificate-transparency, archive, and optional Muse Spark APIs, deploy the included secure Worker."}`;
  const ev = document.querySelector("#evidenceGrid"); ev.replaceChildren();
  if (remoteReport?.evidence?.length) {
    for (const e of remoteReport.evidence) { const card = document.createElement("article"); card.className = "evidence-card"; card.innerHTML = `<span>${escapeHtml(e.host)}</span><b>${escapeHtml(e.label || "Public evidence")}</b><p>${escapeHtml(e.detail || "")}</p>`; ev.append(card); }
  } else {
    const card = document.createElement("article"); card.className = "evidence-card"; card.innerHTML = '<span>EXTERNAL LOOKUPS</span><b>Secure service not configured</b><p>The browser cannot safely perform all ownership and infrastructure checks. Deploy the included Worker and set its URL in site-config.js.</p>'; ev.append(card);
  }
}
form.addEventListener("submit", async event => {
  event.preventDefault(); formError.hidden = true;
  let repoInfo;
  try { repoInfo = parseRepo(input.value); } catch (error) { formError.textContent = error.message; formError.hidden = false; return; }
  landing.hidden = true; report.hidden = false; submit.disabled = true; submit.querySelector("span").textContent = "Scanning…";
  document.querySelector("#findingList").innerHTML = '<div class="loading-line"><i></i><span>Reading public repository files and extracting references…</span></div>';
  document.querySelector("#findingCount").textContent = "…";
  try {
    const scan = await fetchRepoFiles(repoInfo);
    const refs = refsFromFiles(scan.files);
    const model = { ...repoInfo, branch: scan.branch };
    let remoteReport = null;
    if (API_URL) {
      const response = await fetch(API_URL.replace(/\/$/, "") + "/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ owner: repoInfo.owner, repo: repoInfo.repo, references: refs }) });
      if (response.ok) remoteReport = await response.json();
      else throw new Error(`Trustline evidence service returned ${response.status}.`);
    }
    renderReport(model, scan.files, refs, remoteReport);
    if (scan.truncated) document.querySelector("#scopeText").textContent += ` Scan capped at ${scan.files.length} files / ${MAX_BYTES.toLocaleString()} text characters; the report may be incomplete.`;
  } catch (error) {
    report.hidden = true; landing.hidden = false; formError.textContent = error.message || "The public repository could not be scanned."; formError.hidden = false;
  } finally { submit.disabled = false; submit.querySelector("span").textContent = "Audit repository"; }
  window.scrollTo({ top: 0, behavior: "smooth" });
});
document.querySelector("#backButton").addEventListener("click", () => { report.hidden = true; landing.hidden = false; formError.hidden = true; window.scrollTo({ top: 0, behavior: "smooth" }); input.focus(); });
