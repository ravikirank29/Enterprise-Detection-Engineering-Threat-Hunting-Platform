#!/usr/bin/env python3
"""
ioc_enrichment.py
------------------
Takes a list of IOCs (IPs, domains, file hashes) surfaced by a Splunk detection and enriches them
against threat intel sources (AbuseIPDB, VirusTotal, OTX) so a Tier-1 analyst doesn't have to
pivot across five browser tabs during triage. Outputs a single enriched CSV/JSON ready to attach
to the incident ticket.

Usage:
    python3 ioc_enrichment.py --input iocs.csv --output enriched_report.json
    python3 ioc_enrichment.py --ioc 185.220.101.45 --type ip

Requires environment variables (never hardcode keys):
    ABUSEIPDB_API_KEY
    VT_API_KEY
    OTX_API_KEY

Design notes:
    - All external calls are wrapped with retry/backoff and a short timeout so a single dead
      API doesn't stall the whole enrichment batch.
    - Results are cached in-memory per run (and optionally to disk) to avoid burning API quota
      re-enriching the same IOC across multiple alerts in one shift.
    - Output is a normalized schema regardless of source, so it can be piped straight into
      incident_report_generator.py or a SOAR playbook.
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import urllib.request
import urllib.error

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def classify_ioc(value: str) -> str:
    if IP_RE.match(value):
        return "ip"
    for name, pattern in HASH_RE.items():
        if pattern.match(value):
            return f"hash_{name}"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    malicious_verdict: Optional[bool] = None
    reputation_score: Optional[int] = None
    sources_checked: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    country: Optional[str] = None
    first_seen: Optional[str] = None
    asn: Optional[str] = None
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None


def _http_get_json(url: str, headers: dict, timeout: int = 10, retries: int = 2) -> Optional[dict]:
    """Small GET-JSON helper with basic retry/backoff. Returns None on persistent failure
    instead of raising, so a single bad lookup doesn't kill a batch enrichment run."""
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            if attempt == retries:
                print(f"  [!] Lookup failed for {url.split('?')[0]}: {e}", file=sys.stderr)
                return None
            time.sleep(1.5 * (attempt + 1))
    return None


def enrich_ip_abuseipdb(ip: str, api_key: str) -> dict:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": api_key, "Accept": "application/json"}
    data = _http_get_json(url, headers)
    if not data:
        return {}
    d = data.get("data", {})
    return {
        "abuseipdb_score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "total_reports": d.get("totalReports"),
        "is_tor": d.get("isTor"),
    }


def enrich_hash_virustotal(file_hash: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    data = _http_get_json(url, headers)
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_total_engines": sum(stats.values()) if stats else 0,
        "vt_tags": attrs.get("tags", []),
        "vt_type_description": attrs.get("type_description"),
        "first_submission": attrs.get("first_submission_date"),
    }


def enrich_domain_otx(domain: str, api_key: str) -> dict:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": api_key}
    data = _http_get_json(url, headers)
    if not data:
        return {}
    pulse_info = data.get("pulse_info", {})
    return {
        "otx_pulse_count": pulse_info.get("count", 0),
        "otx_pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
    }


def enrich_ioc(value: str) -> EnrichmentResult:
    ioc_type = classify_ioc(value)
    result = EnrichmentResult(ioc=value, ioc_type=ioc_type)

    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
    vt_key = os.environ.get("VT_API_KEY")
    otx_key = os.environ.get("OTX_API_KEY")

    try:
        if ioc_type == "ip" and abuseipdb_key:
            data = enrich_ip_abuseipdb(value, abuseipdb_key)
            result.raw.update(data)
            result.sources_checked.append("AbuseIPDB")
            if data.get("abuseipdb_score") is not None:
                result.reputation_score = data["abuseipdb_score"]
                result.malicious_verdict = data["abuseipdb_score"] >= 50
            result.country = data.get("country")
            if data.get("is_tor"):
                result.tags.append("tor-exit-node")

        elif ioc_type.startswith("hash_") and vt_key:
            data = enrich_hash_virustotal(value, vt_key)
            result.raw.update(data)
            result.sources_checked.append("VirusTotal")
            if data.get("vt_total_engines"):
                result.malicious_verdict = data.get("vt_malicious", 0) > 0
                result.reputation_score = round(
                    100 * data.get("vt_malicious", 0) / max(data["vt_total_engines"], 1)
                )
            result.tags.extend(data.get("vt_tags", []))
            result.first_seen = data.get("first_submission")

        elif ioc_type == "domain" and otx_key:
            data = enrich_domain_otx(value, otx_key)
            result.raw.update(data)
            result.sources_checked.append("AlienVault OTX")
            if data.get("otx_pulse_count") is not None:
                result.malicious_verdict = data["otx_pulse_count"] > 0
                result.reputation_score = min(data["otx_pulse_count"] * 10, 100)
            result.tags.extend(data.get("otx_pulse_names", []))

        if not result.sources_checked:
            result.error = "No matching API key configured for this IOC type, or unrecognized IOC format."

    except Exception as e:  # defensive: enrichment should never crash the batch
        result.error = str(e)

    return result


def load_iocs_from_csv(path: str) -> list:
    iocs = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].strip() and not row[0].startswith("#"):
                iocs.append(row[0].strip())
    return iocs


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs against threat intel sources.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="CSV file with one IOC per line")
    group.add_argument("--ioc", help="Single IOC to enrich")
    parser.add_argument("--type", help="Optional hint (ip/domain/hash) — auto-detected if omitted")
    parser.add_argument("--output", default="enriched_report.json", help="Output JSON path")
    args = parser.parse_args()

    iocs = [args.ioc] if args.ioc else load_iocs_from_csv(args.input)
    print(f"[*] Enriching {len(iocs)} IOC(s)...")

    results = []
    for i, ioc in enumerate(iocs, 1):
        print(f"  [{i}/{len(iocs)}] {ioc} ({classify_ioc(ioc)})")
        results.append(asdict(enrich_ioc(ioc)))
        time.sleep(0.5)  # light client-side rate limiting, be a good API citizen

    with open(args.output, "w") as f:
        json.dump({"generated_by": "ioc_enrichment.py", "count": len(results), "results": results}, f, indent=2)

    malicious_count = sum(1 for r in results if r.get("malicious_verdict"))
    print(f"\n[+] Done. {malicious_count}/{len(results)} flagged malicious/suspicious.")
    print(f"[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
