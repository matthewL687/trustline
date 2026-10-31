const form = document.querySelector("#scanForm");
const landing = document.querySelector("#landing");
const report = document.querySelector("#report");
const input = document.querySelector("#websiteUrl");
const submit = form.querySelector("button[type=submit]");
const formError = document.querySelector("#formError");
function rootDomain(host) {
  const parts = host.split(".");
  const doubleSuffixes = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "com.cn", "com.sg", "com.mx", "co.in"]);
  const tenantSuffixes = ["github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app", "workers.dev", "herokuapp.com", "appspot.com", "azurewebsites.net"];
  const tenantSuffix = tenantSuffixes.find(suffix => host.endsWith(`.${suffix}`));
  if (tenantSuffix) return host;
  if (parts.length < 3) return host;
  const suffix = parts.slice(-2).join(".");
  return doubleSuffixes.has(suffix) ? parts.slice(-3).join(".") : suffix;
}

function parseWebsite(raw) {
  const value = raw.trim();
  let url;
  try { url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`); }
  catch { throw new Error("Enter a valid public website link, such as https://example.com."); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("Use a public website link that starts with http:// or https://.");
  }
  const host = url.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  if (!host.includes(".") || host.length > 253 || /[^a-z0-9.-]/.test(host) || host.startsWith(".") || host.endsWith(".")) {
    throw new Error("Enter a public domain name, such as example.com.");
  }
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) {
    throw new Error("Enter a public domain name, not a local network address.");
  }
  url.hash = "";
  return { url, host, root: rootDomain(host) };
}

async function fetchWithTimeout(url, options = {}, timeout = 9000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}

function dnsQuery(name, type) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  return fetchWithTimeout(url, { headers: { accept: "application/dns-json" } }).then(async response => {
    if (!response.ok) throw new Error(`DNS lookup returned HTTP ${response.status}.`);
    return response.json();
  });
}

function signalCard(title, value, detail, status = "good") {
  const card = document.createElement("article");
  card.className = `signal-card ${status}`;
  const top = document.createElement("div");
  top.className = "signal-card-top";
  const label = document.createElement("span");
  label.className = "signal-label";
  label.textContent = title.toUpperCase();
  const mark = document.createElement("span");
  mark.className = "signal-value";
  mark.textContent = status === "good" ? "✓" : status === "review" ? "!" : status === "error" ? "×" : "·";
  top.append(label, mark);
  const strong = document.createElement("strong");
  strong.textContent = value;
  const small = document.createElement("small");
  small.textContent = detail;
  card.append(top, strong, small);
  return card;
}

function evidenceCard(title, value, detail, url, linkLabel) {
  const card = document.createElement("article");
  card.className = "evidence-card";
  const label = document.createElement("span");
  label.textContent = title.toUpperCase();
  const heading = document.createElement("b");
  heading.textContent = value;
  const description = document.createElement("p");
  description.textContent = detail;
  card.append(label, heading, description);
  if (url) {
    const link = document.createElement("a");
    link.href = url;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.textContent = linkLabel || "Open public record ↗";
    card.append(link);
  }
  return card;
}

function findingCard(item) {
  const card = document.createElement("article");
  card.className = `finding-card ${item.level}`;
  const bar = document.createElement("i");
  bar.className = "finding-bar";
  const main = document.createElement("div");
  main.className = "finding-main";
  const title = document.createElement("h3");
  title.textContent = item.title;
  const explanation = document.createElement("p");
  explanation.textContent = item.explanation;
  main.append(title, explanation);
  if (item.recommendation) {
    const recommendation = document.createElement("p");
    recommendation.className = "recommendation";
    recommendation.textContent = `Suggested next step: ${item.recommendation}`;
    main.append(recommendation);
  }
  const meta = document.createElement("span");
  meta.className = "finding-meta";
  meta.textContent = item.label;
  card.append(bar, main, meta);
  return card;
}

function setOverview(kind, title, text, icon) {
  const banner = document.querySelector("#overviewBanner");
  banner.className = `overview-banner ${kind}`;
  document.querySelector("#overviewIcon").textContent = icon;
  document.querySelector("#overviewTitle").textContent = title;
  document.querySelector("#overviewText").textContent = text;
}

function makeFindingList(results) {
  const findings = [];
  const dns = results.get("DNS");
  const caa = results.get("CAA");
  const dmarc = results.get("DMARC");
  const registration = results.get("Registration");
  const https = results.get("HTTPS");

  if (dns?.state === "review") findings.push({ level: "high", label: "HIGH · WEBSITE REACHABILITY", title: "No web address returned by DNS", explanation: "The public DNS lookup did not return an IPv4 or IPv6 address for this domain. That can make the site unreachable, though DNS changes and temporary lookup failures are possible.", recommendation: "Confirm the domain's A/AAAA records and authoritative DNS settings." });
  else if (dns?.state === "error") findings.push({ level: "info", label: "LOOKUP UNAVAILABLE", title: "DNS evidence could not be collected", explanation: dns.detail, recommendation: "Retry the check later or review DNS with your provider." });

  if (registration?.expiryDays !== undefined && registration.expiryDays <= 45) findings.push({ level: registration.expiryDays <= 21 ? "high" : "medium", label: `${registration.expiryDays <= 21 ? "HIGH" : "REVIEW"} · DOMAIN RENEWAL`, title: registration.expiryDays < 0 ? "The registration expiry date has passed" : `Domain registration expires in ${registration.expiryDays} days`, explanation: "The public registration record lists an upcoming expiry date. An expiry date does not prove the domain will be lost, but an unattended renewal could interrupt the website or put its name at risk.", recommendation: "Confirm auto-renewal and the billing contact with the registrar." });
  else if (registration?.state === "error") findings.push({ level: "info", label: "LOOKUP UNAVAILABLE", title: "Registration details could not be confirmed", explanation: registration.detail, recommendation: "Check the registered domain in your registrar account." });

  if (caa?.state === "review") findings.push({ level: "medium", label: "REVIEW · CERTIFICATE POLICY", title: "No CAA certificate policy found", explanation: "Without a CAA record, certificate authorities are not restricted by this DNS policy from issuing a certificate for the domain. This is a configuration choice, not proof that a certificate was issued improperly.", recommendation: "If you want to limit issuance, add CAA records for the certificate authorities you use." });
  else if (caa?.state === "error") findings.push({ level: "info", label: "LOOKUP UNAVAILABLE", title: "Certificate policy could not be checked", explanation: caa.detail, recommendation: "Retry the public DNS lookup later." });

  if (dmarc?.state === "review") findings.push({ level: "medium", label: "REVIEW · EMAIL SPOOFING", title: dmarc.policy === "none" ? "DMARC is monitoring only" : "No DMARC policy found", explanation: dmarc.policy === "none" ? "The domain has a DMARC record, but its policy is p=none, which requests monitoring rather than quarantine or rejection of unauthenticated mail." : "No DMARC record was returned for the domain. Mail providers may have less guidance for handling messages that claim to come from it.", recommendation: "Review SPF and DKIM alignment, then consider a staged move to quarantine or reject." });
  else if (dmarc?.state === "error") findings.push({ level: "info", label: "LOOKUP UNAVAILABLE", title: "Email policy could not be checked", explanation: dmarc.detail, recommendation: "Retry the public DNS lookup later." });

  if (https?.state === "review") findings.push({ level: "high", label: "HIGH · HTTPS CONNECTION", title: "A secure connection could not be confirmed", explanation: "The browser could not complete the HTTPS connection to the host. A network failure can be temporary or caused by blocking, so it is not by itself proof of a certificate problem.", recommendation: "Open the site in a browser and verify its HTTPS certificate and hosting status." });
  else if (https?.state === "error") findings.push({ level: "info", label: "LOOKUP UNAVAILABLE", title: "HTTPS connection details are limited", explanation: https.detail, recommendation: "Check the website directly in a browser." });

  return findings.sort((a, b) => ({ high: 0, medium: 1, info: 2 }[a.level] - ({ high: 0, medium: 1, info: 2 }[b.level])));
}

async function checkSite(target) {
  const { url, host, root } = target;
  const resultMap = new Map();
  document.querySelector("#reportDomain").textContent = root;
  const reportUrl = document.querySelector("#reportUrl");
  reportUrl.href = url.href;
  reportUrl.textContent = url.href;
  document.querySelector("#checkedAt").textContent = new Date().toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  document.querySelector("#signalGrid").replaceChildren();
  document.querySelector("#evidenceGrid").replaceChildren();
  document.querySelector("#findingList").replaceChildren(Object.assign(document.createElement("div"), { className: "loading-line", innerHTML: "<i></i><span>Checking public records…</span>" }));
  setOverview("", "Checking public signals…", "Looking up DNS, domain registration, email policy, and HTTPS connection data.", "◎");

  const tasks = [
    ["DNS", async () => {
      const answers = await Promise.all(["A", "AAAA"].map(type => dnsQuery(host, type)));
      const ips = [...new Set(answers.flatMap(x => x.Answer || []).filter(x => x.type === 1 || x.type === 28).map(x => x.data))];
      if (!ips.length) return { state: "review", value: "No address", detail: "No A or AAAA records returned", evidence: answers.some(x => x.Status === 3) ? "DNS returned NXDOMAIN for the requested host." : "DNS returned no IPv4 or IPv6 address." };
      return { state: "good", value: `${ips.length} address${ips.length === 1 ? "" : "es"}`, detail: ips.slice(0, 3).join(" · "), evidence: `A/AAAA records: ${ips.join(", ")}` };
    }],
    ["CAA", async () => {
      const data = await dnsQuery(root, "CAA");
      const records = data.Answer?.filter(x => x.type === 257).map(x => x.data) || [];
      return records.length ? { state: "good", value: "Policy found", detail: records.slice(0, 2).join(" · "), evidence: records.join("; ") } : { state: "review", value: "No policy", detail: "No CAA records returned", evidence: "No CAA record was returned for the registered domain." };
    }],
    ["DMARC", async () => {
      const data = await dnsQuery(`_dmarc.${root}`, "TXT");
      const record = (data.Answer || []).find(x => x.type === 16 && x.data.toLowerCase().includes("v=dmarc1"));
      if (!record) return { state: "review", value: "No record", detail: "No DMARC record returned", evidence: "No DMARC TXT record was returned for _dmarc." };
      const value = record.data.replaceAll('" "', "").replaceAll('"', "");
      const policy = value.match(/(?:^|;)\s*p\s*=\s*([^;\s]+)/i)?.[1]?.toLowerCase() || "unknown";
      const relaxed = policy === "none";
      return { state: relaxed ? "review" : "good", value: relaxed ? "Monitoring only" : `Policy: ${policy}`, detail: value, evidence: value, policy };
    }],
    ["Registration", async () => {
      const response = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(root)}`, { headers: { accept: "application/rdap+json, application/json" } });
      if (response.status === 404) return { state: "review", value: "No record", detail: "No RDAP registration record returned", evidence: "RDAP returned HTTP 404 for the registered domain." };
      if (!response.ok) throw new Error(`RDAP returned HTTP ${response.status}.`);
      const data = await response.json();
      const events = data.events || [];
      const expiry = events.find(x => ["expiration", "expiry"].includes(String(x.eventAction).toLowerCase()))?.eventDate;
      const entity = (data.entities || []).find(x => (x.roles || []).includes("registrar"));
      const vcard = entity?.vcardArray?.[1] || [];
      const registrar = vcard.find(x => x[0] === "fn")?.[3];
      if (!expiry) return { state: "good", value: "Registered", detail: registrar ? `Registrar: ${registrar}` : "Public registration record found", evidence: registrar ? `Registrar: ${registrar}` : "RDAP registration record found." };
      const expiryDate = new Date(expiry);
      const expiryDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
      const state = expiryDays <= 45 ? "review" : "good";
      return { state, value: expiryDays < 0 ? "Expiry passed" : `${expiryDays} days left`, detail: `${registrar ? `Registrar: ${registrar} · ` : ""}Expires ${expiryDate.toLocaleDateString()}`, evidence: `RDAP expiration event: ${expiry}`, expiryDays };
    }],
    ["HTTPS", async () => {
      try {
        const response = await fetchWithTimeout(`https://${host}/`, { mode: "no-cors", method: "HEAD" }, 7000);
        return { state: "good", value: "Connected", detail: "Browser established an HTTPS connection", evidence: response.type === "opaque" ? "HTTPS connection established. Cross-origin rules hide the website response status." : `HTTPS responded with status ${response.status}.` };
      } catch (error) {
        if (error.name === "AbortError") throw new Error("HTTPS probe timed out.");
        throw new Error("The browser could not complete an HTTPS request to this host.");
      }
    }]
  ];

  const signalGrid = document.querySelector("#signalGrid");
  const evidenceGrid = document.querySelector("#evidenceGrid");
  const run = async ([name, lookup]) => {
    let item;
    try { item = await lookup(); }
    catch (error) { item = { state: "error", value: "Unavailable", detail: error.name === "AbortError" ? "The public lookup took too long." : error.message || "This public lookup could not be completed.", evidence: "No usable response was returned from the lookup." }; }
    resultMap.set(name, item);
    const card = signalCard(name, item.value, item.detail, item.state === "error" ? "error" : item.state);
    signalGrid.append(card);
    const evidence = evidenceCard(name, item.value, item.evidence);
    evidenceGrid.append(evidence);
  };
  await Promise.all(tasks.map(run));

  const ctUrl = new URL("https://crt.sh/");
  ctUrl.searchParams.set("q", `%.${root}`);
  const archiveUrl = new URL(`https://web.archive.org/web/*/${root}`);
  evidenceGrid.append(
    evidenceCard("Certificate transparency", "Public certificate log", `Open the public certificate log search for ${root}. The static site links to the log directly because the log does not allow browser access to its data API.`, ctUrl.href, "Open certificate log ↗"),
    evidenceCard("Archived snapshots", "Wayback history", `Open archived public captures for ${root} to compare how the website has changed over time.`, archiveUrl.href, "Open archived history ↗")
  );

  const findings = makeFindingList(resultMap);
  const list = document.querySelector("#findingList");
  list.replaceChildren();
  document.querySelector("#findingCount").textContent = String(findings.length).padStart(2, "0");
  const unavailable = [...resultMap.values()].filter(item => item.state === "error").length;
  if (!findings.length && unavailable === resultMap.size) {
    const empty = document.createElement("div");
    empty.className = "empty-findings";
    empty.textContent = "The public lookups did not return enough evidence to assess this domain. Retry the check later or use the links below to review its public records.";
    list.append(empty);
    setOverview("warn", "Public checks unavailable", "No risk conclusion is possible because none of the lookups completed.", "!");
  } else if (!findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty-findings";
    empty.textContent = "No review signals surfaced in the checks that completed. This is not a guarantee that the site is secure or that its code contains no risky references.";
    list.append(empty);
    setOverview("", "No review signals surfaced", "The available public checks did not identify a signal to flag. Keep ownership and renewal details current.", "✓");
  } else {
    list.append(...findings.map(findingCard));
    const serious = findings.filter(x => x.level === "high").length;
    setOverview(serious ? "bad" : "warn", `${findings.length} signal${findings.length === 1 ? "" : "s"} to review`, serious ? "At least one check could affect website reachability. Read the evidence and uncertainty before taking action." : "These are review prompts, not proof of a vulnerability. Read each signal and its recommended next step.", serious ? "!" : "◎");
  }
  document.querySelector("#checkedAt").textContent = new Date().toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  formError.hidden = true;
  let target;
  try { target = parseWebsite(input.value); }
  catch (error) { formError.textContent = error.message; formError.hidden = false; return; }
  landing.hidden = true;
  report.hidden = false;
  submit.disabled = true;
  submit.querySelector("span").textContent = "Checking…";
  try { await checkSite(target); }
  finally { submit.disabled = false; submit.querySelector("span").textContent = "Check website"; }
  window.scrollTo({ top: 0, behavior: "smooth" });
});

document.querySelector("#backButton").addEventListener("click", () => {
  report.hidden = true;
  landing.hidden = false;
  formError.hidden = true;
  window.scrollTo({ top: 0, behavior: "smooth" });
  input.focus();
});
