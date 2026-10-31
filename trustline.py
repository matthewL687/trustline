#!/usr/bin/env python3
"""Trustline: find and investigate third-party infrastructure referenced by a codebase."""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime as dt
import json
import os
import re
import socket
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".next"}
MAX_FILE = 2_000_000
URL_RE = re.compile(r"(?i)\b(?:https?://|s3://|gs://)[^\s\"'<>`)\]}]+")
HOST_RE = re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/[^\s\"'<>`]*)?")
SECRET_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]")


def clean_url(raw: str) -> str:
    return raw.rstrip(".,;:!?)\"]}")


def find_references(root: Path) -> list[dict]:
    found: dict[tuple[str, str], dict] = {}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            path = Path(base) / filename
            try:
                if path.stat().st_size > MAX_FILE:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeError):
                continue
            rel = path.relative_to(root).as_posix()
            for pattern in (URL_RE, HOST_RE):
                for match in pattern.finditer(text):
                    raw = clean_url(match.group(0))
                    if raw.lower().startswith(("localhost", "127.0.0.1", "0.0.0.0")):
                        continue
                    if "." not in raw or raw.lower().endswith((".png", ".jpg", ".svg", ".css", ".js")):
                        continue
                    value = raw if "://" in raw else "https://" + raw
                    parsed = urllib.parse.urlparse(value)
                    host = (parsed.hostname or "").lower().rstrip(".")
                    if not host or host in {"example.com", "example.org", "example.net", "localhost"}:
                        continue
                    start = max(0, match.start() - 180)
                    end = min(len(text), match.end() + 180)
                    context = text[start:end].replace("\n", " ")
                    line = text.count("\n", 0, match.start()) + 1
                    key = (host, rel)
                    if key not in found:
                        found[key] = {"host": host, "url": value, "file": rel, "line": line,
                                      "context": context[:500], "references": 0,
                                      "kind": classify_reference(rel, context, value)}
                    found[key]["references"] += 1
    return sorted(found.values(), key=lambda x: (x["host"], x["file"]))


def classify_reference(path: str, context: str, url: str) -> str:
    lower = (path + " " + context + " " + url).lower()
    if re.search(r"<script|\.js(?:\?|$)|script[_-]?src", lower):
        return "Browser script"
    if re.search(r"<link|\.css(?:\?|$)|stylesheet|font", lower):
        return "Browser asset"
    if re.search(r"s3://|storage\.googleapis|\.s3[.-]|bucket", lower):
        return "Cloud storage"
    if any(word in lower for word in ("webhook", "callback", "notify_url")):
        return "Webhook"
    if any(word in lower for word in ("dockerfile", "workflow", "deploy", "terraform", "ansible", ".yml", ".yaml")):
        return "Build / deploy"
    if any(word in lower for word in ("readme", "docs/", "documentation", "changelog", ".md ")):
        return "Documentation"
    return "API / external service"


def http_json(url: str, timeout: float = 7) -> tuple[int, object, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Trustline/0.1 (security research; contact: local-user)", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(500_000).decode("utf-8", "replace")
            try:
                return response.status, json.loads(body), body
            except json.JSONDecodeError:
                return response.status, None, body
    except urllib.error.HTTPError as error:
        body = error.read(20_000).decode("utf-8", "replace")
        return error.code, None, body
    except Exception as error:
        return 0, None, str(error)


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) < 3:
        return host
    common_second_level = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br", "com.cn", "com.sg", "com.mx"}
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in common_second_level else suffix


def investigate(ref: dict) -> dict:
    host = ref["host"]
    try:
        socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        dns = "resolves"
    except socket.gaierror as error:
        dns = "does not resolve" if getattr(error, "errno", None) == socket.EAI_NONAME else "DNS lookup failed"
    root_domain = registrable_domain(host)
    status, data, message = http_json("https://rdap.org/domain/" + urllib.parse.quote(root_domain, safe=""))
    expiry, registrar = None, None
    if isinstance(data, dict):
        registrar = next((e.get("vcardArray", [None, []])[1][0][3] for e in data.get("entities", [])
                          if e.get("roles") and "registrar" in e["roles"] and len(e.get("vcardArray", [])) > 1
                          and e["vcardArray"][1] and len(e["vcardArray"][1][0]) > 3), None)
        for event in data.get("events", []):
            if event.get("eventAction", "").lower() in {"expiration", "expiry"}:
                expiry = event.get("eventDate")
    bucket = None
    if "s3." in host or "storage.googleapis.com" in host or "s3.amazonaws.com" in host:
        code, _, body = http_json(ref["url"], timeout=5)
        if "NoSuchBucket" in body:
            bucket = "NoSuchBucket response"
        elif code == 404:
            bucket = "HTTP 404 (bucket state unclear)"
        elif code:
            bucket = f"HTTP {code}"
        else:
            bucket = "probe failed"
    ct_status, ct_data, _ = http_json("https://crt.sh/?q=%25." + urllib.parse.quote(root_domain, safe=".-") + "&output=json", timeout=10)
    cert_count = len(ct_data) if isinstance(ct_data, list) else None
    latest_cert = max((row.get("not_before", "") for row in ct_data if isinstance(row, dict)), default=None) if isinstance(ct_data, list) else None
    wayback_url = "https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote("*." + root_domain + "/*", safe="*./") + "&output=json&filter=statuscode:200&fl=timestamp,original&collapse=urlkey&limit=5"
    wayback_status, wayback_data, _ = http_json(wayback_url, timeout=10)
    snapshot_count = max(0, len(wayback_data) - 1) if isinstance(wayback_data, list) else None
    evidence = {"dns": dns, "rdap_status": status or None, "expiry": expiry, "registrar": registrar,
                "bucket": bucket, "certificate_count": cert_count, "latest_certificate": latest_cert,
                "wayback_snapshots": snapshot_count, "ct_status": ct_status or None,
                "wayback_status": wayback_status or None,
                "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    if status == 404:
        evidence["rdap"] = "No registration record returned"
    elif status and status >= 400:
        evidence["rdap"] = f"RDAP returned HTTP {status}"
    else:
        evidence["rdap"] = "Registration record found" if isinstance(data, dict) else "RDAP unavailable"
    return {**ref, "evidence": evidence}


def rank_and_explain(item: dict) -> dict:
    ev, kind = item["evidence"], item["kind"]
    is_live = kind in {"Browser script", "Browser asset", "Cloud storage", "Build / deploy", "Webhook"}
    score = 20 if is_live else 8
    reasons = []
    if ev["dns"] == "does not resolve":
        score += 42
        reasons.append("The hostname currently does not resolve, so this reference may be dangling.")
    if ev.get("bucket") == "NoSuchBucket response":
        score += 65
        reasons.append("The storage endpoint returned NoSuchBucket, a strong sign the bucket name is unclaimed.")
    elif ev.get("bucket"):
        reasons.append("The storage probe did not establish whether the name can be claimed.")
    if ev.get("expiry"):
        try:
            days = (dt.date.fromisoformat(ev["expiry"][:10]) - dt.date.today()).days
            if days <= 30:
                score += 35
                reasons.append(f"RDAP lists an expiry in {max(days, 0)} days.")
        except ValueError:
            pass
    if kind in {"Browser script", "Cloud storage", "Build / deploy"}:
        score += 12
        reasons.append(f"This appears in a {kind.lower()} position with meaningful replacement impact.")
    if not reasons:
        reasons.append("No immediate ownership or availability warning was confirmed; keep this dependency on the inventory.")
    score = min(score, 100)
    severity = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
    fix = ("Remove or replace the dangling reference. If it is a required asset, self-host it or point it to an account you control."
           if ev["dns"] == "does not resolve" else
           "Confirm the owner and renewal path. Pin or self-host browser-executed assets, and remove references that are no longer used.")
    return {**item, "score": score, "severity": severity, "explanation": " ".join(reasons), "recommendation": fix,
            "uncertainty": "DNS and registration data are point-in-time signals. They do not prove ownership intent or takeoverability."}


def model_review(items: list[dict]) -> None:
    key = os.environ.get("MODEL_API_KEY")
    if not key or not items:
        return
    # All facts stay deterministic; Muse Spark may refine classification, priority, and wording only.
    model_items = []
    for item in items:
        context = item.get("context", "")
        context = re.sub(r"(?i)(api[_-]?key|token|secret|password)(\s*[:=]\s*)[\"']?[^\s,;\"']+", r"\1\2[REDACTED]", context)
        model_items.append({**item, "context": context})
    prompt = "Review these external code references and deterministic evidence. Return JSON object with a findings array, one item per input, and keys: host, kind, severity (Critical/High/Medium/Low), explanation, recommendation, uncertainty. Do not invent or alter factual evidence or dates. Consider whether each reference executes at runtime and its blast radius.\n\n" + json.dumps(model_items, ensure_ascii=False)
    req = urllib.request.Request("https://api.meta.ai/v1/chat/completions", data=json.dumps({
        "model": os.environ.get("TRUSTLINE_MODEL", "muse-spark-1.3"),
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"}
    }).encode(), headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            result = json.loads(response.read().decode())
        content = result["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        suggestions = parsed if isinstance(parsed, list) else parsed.get("findings", [])
        by_host = {x.get("host"): x for x in suggestions if isinstance(x, dict)}
        valid_severity = {"Critical", "High", "Medium", "Low"}
        valid_kinds = {"Browser script", "Browser asset", "Cloud storage", "Webhook", "Build / deploy", "Documentation", "API / external service"}
        for item in items:
            suggestion = by_host.get(item["host"], {})
            for field in ("kind", "severity", "explanation", "recommendation", "uncertainty"):
                if field == "severity" and suggestion.get(field) not in valid_severity:
                    continue
                if field == "kind" and suggestion.get(field) not in valid_kinds:
                    continue
                if suggestion.get(field) and field in {"explanation", "recommendation", "uncertainty"}:
                    if not isinstance(suggestion[field], str):
                        continue
                if suggestion.get(field):
                    item[field] = str(suggestion[field])[:1000]
            item["reasoning_mode"] = "Muse Spark"
    except Exception as error:
        print(f"Model review unavailable; deterministic ranking retained ({error}).", file=sys.stderr)


def cache_results(db_path: Path, results: list[dict]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS evidence (host TEXT PRIMARY KEY, checked_at TEXT NOT NULL, payload TEXT NOT NULL)")
        for item in results:
            db.execute("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?)",
                       (item["host"], item["evidence"]["checked_at"], json.dumps(item["evidence"])))


def cached_evidence(db_path: Path, host: str, max_age_hours: int = 24) -> dict | None:
    if not db_path.exists():
        return None
    try:
        with sqlite3.connect(db_path) as db:
            row = db.execute("SELECT checked_at, payload FROM evidence WHERE host = ?", (host,)).fetchone()
        if not row:
            return None
        checked = dt.datetime.fromisoformat(row[0])
        if (dt.datetime.now(dt.timezone.utc) - checked).total_seconds() > max_age_hours * 3600:
            return None
        return json.loads(row[1])
    except (sqlite3.Error, ValueError, TypeError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Inventory and investigate external trust dependencies in a codebase.")
    parser.add_argument("path", nargs="?", default=".", help="Repository path (default: current directory)")
    parser.add_argument("--json", action="store_true", help="Write JSON findings to stdout")
    parser.add_argument("--no-network", action="store_true", help="Only extract references, skip external checks")
    parser.add_argument("--cache", default="~/.cache/trustline/evidence.sqlite3", help="SQLite evidence cache path")
    args = parser.parse_args()
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    refs = find_references(root)
    cache_path = Path(args.cache).expanduser()
    if args.no_network:
        findings = [rank_and_explain({**ref, "evidence": {"dns": "not checked", "rdap": "not checked", "checked_at": None}}) for ref in refs]
    else:
        investigated = []
        missing = []
        for ref in refs:
            cached = cached_evidence(cache_path, ref["host"])
            if cached:
                investigated.append({**ref, "evidence": cached})
            else:
                missing.append(ref)
        with futures.ThreadPoolExecutor(max_workers=12) as pool:
            investigated.extend(pool.map(investigate, missing))
        findings = [rank_and_explain(item) for item in investigated]
        model_review(findings)
        cache_results(cache_path, findings)
    findings.sort(key=lambda x: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4), -x["score"]))
    if args.json:
        print(json.dumps({"root": str(root), "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(), "findings": findings}, indent=2))
    else:
        counts = {s: sum(1 for item in findings if item["severity"] == s) for s in ("Critical", "High", "Medium", "Low")}
        print(f"\nTrustline scanned {root}\n{len(findings)} references  ·  " + "  ".join(f"{s} {n}" for s, n in counts.items()))
        print("─" * 92)
        for item in findings:
            print(f"\n[{item['severity'].upper():8}] {item['host']}  ·  {item['kind']}  ·  {item['file']}:{item['line']}")
            print(f"  {item['explanation']}\n  Fix: {item['recommendation']}")
        print("\nNote: ownership findings are evidence, not proof. Review uncertainty and verify high-impact items manually.\n")


if __name__ == "__main__":
    main()
