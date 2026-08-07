#!/usr/bin/env python3
"""
incident_report_generator.py
-----------------------------
Turns a raw Splunk detection hit (exported as JSON, e.g. via `| outputlookup` or the Splunk
REST API `/services/search/jobs/{sid}/results`) plus an optional IOC enrichment file (from
ioc_enrichment.py) into a formatted Markdown incident report ready to paste into a ticket or
hand to an on-call analyst.

Why this exists: analysts lose real time reformatting raw search results into something
readable under pressure. This standardizes that into one command.

Usage:
    python3 incident_report_generator.py \\
        --detection-hits splunk_export.json \\
        --detection-id DE-CA-001 \\
        --enrichment enriched_report.json \\
        --output incident_2026-08-06_lsass_access.md
"""

import argparse
import json
import sys
from datetime import datetime, timezone

# Lightweight local metadata for the detections in this repo — mirrors docs/mitre_attack_mapping.md.
# In a production deployment this would be pulled from the detection-as-code repo's manifest
# instead of duplicated here; kept inline for portfolio/demo portability.
DETECTION_CATALOG = {
    "DE-CA-001": {
        "title": "Suspicious LSASS Process Access (Credential Dumping)",
        "mitre": "T1003.001 - OS Credential Dumping: LSASS Memory",
        "severity": "Critical",
        "playbook": "playbooks/PB-002-credential-dumping-response.md",
    },
    "DE-DE-001": {
        "title": "Windows Event Log Cleared",
        "mitre": "T1070.001 - Indicator Removal: Clear Windows Event Logs",
        "severity": "Critical",
        "playbook": "playbooks/PB-003-log-tampering-response.md",
    },
    "DE-IM-001": {
        "title": "Mass File Modification Indicative of Ransomware Encryption",
        "mitre": "T1486 - Data Encrypted for Impact",
        "severity": "Critical",
        "playbook": "playbooks/PB-001-ransomware-containment.md",
    },
    "DE-CA-003": {
        "title": "Password Spray Against Multiple Accounts",
        "mitre": "T1110.003 - Brute Force: Password Spraying",
        "severity": "High",
        "playbook": "playbooks/PB-004-account-compromise-response.md",
    },
    "DE-C2-001": {
        "title": "Periodic Beaconing Pattern to External Host",
        "mitre": "T1071.001 - Application Layer Protocol: Web Protocols",
        "severity": "High",
        "playbook": "playbooks/PB-005-c2-beaconing-response.md",
    },
}

SEVERITY_SLA_MINUTES = {"Critical": 15, "High": 60, "Medium": 240, "Low": 1440}


def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_report(detection_id, hits, enrichment, incident_number):
    meta = DETECTION_CATALOG.get(detection_id, {
        "title": detection_id, "mitre": "Unmapped", "severity": "Medium", "playbook": "N/A"
    })
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sla = SEVERITY_SLA_MINUTES.get(meta["severity"], 240)

    affected_hosts = sorted({h.get("ComputerName") or h.get("dest") or "unknown" for h in hits})
    affected_users = sorted({h.get("User") or h.get("SubjectUserName") or "unknown" for h in hits})

    lines = []
    lines.append(f"# Incident Report: {incident_number}")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Detection:** {detection_id} — {meta['title']}  ")
    lines.append(f"**MITRE ATT&CK:** {meta['mitre']}  ")
    lines.append(f"**Severity:** {meta['severity']}  ")
    lines.append(f"**Response SLA:** {sla} minutes  ")
    lines.append(f"**Response Playbook:** `{meta['playbook']}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"{len(hits)} event(s) matched detection **{detection_id}**, affecting "
                  f"**{len(affected_hosts)}** host(s) and **{len(affected_users)}** account(s).")
    lines.append("")
    lines.append("## Affected Assets")
    lines.append("")
    lines.append("| Host | Account(s) Involved |")
    lines.append("|---|---|")
    host_user_map = {}
    for h in hits:
        host = h.get("ComputerName") or h.get("dest") or "unknown"
        user = h.get("User") or h.get("SubjectUserName") or "unknown"
        host_user_map.setdefault(host, set()).add(user)
    for host in affected_hosts:
        lines.append(f"| {host} | {', '.join(sorted(host_user_map.get(host, [])))} |")
    lines.append("")

    lines.append("## Raw Event Detail")
    lines.append("")
    lines.append("| Timestamp | Host | User | Detail |")
    lines.append("|---|---|---|---|")
    for h in hits[:25]:  # cap inline table; full data stays in the source JSON
        ts = h.get("first_seen") or h.get("_time") or "n/a"
        host = h.get("ComputerName") or h.get("dest") or "unknown"
        user = h.get("User") or h.get("SubjectUserName") or "unknown"
        detail = h.get("commands") or h.get("cmd") or h.get("access_rights") or ""
        detail = str(detail)[:120]
        lines.append(f"| {ts} | {host} | {user} | {detail} |")
    if len(hits) > 25:
        lines.append(f"| ... | ... | ... | *{len(hits) - 25} additional events omitted, see source export* |")
    lines.append("")

    if enrichment:
        lines.append("## IOC Enrichment")
        lines.append("")
        lines.append("| IOC | Type | Verdict | Score | Sources |")
        lines.append("|---|---|---|---|---|")
        for r in enrichment.get("results", []):
            verdict = "🔴 Malicious" if r.get("malicious_verdict") else (
                "🟢 Clean" if r.get("malicious_verdict") is False else "⚪ Unknown")
            lines.append(f"| {r['ioc']} | {r['ioc_type']} | {verdict} | "
                          f"{r.get('reputation_score', 'n/a')} | {', '.join(r.get('sources_checked', []))} |")
        lines.append("")

    lines.append("## Recommended Next Actions")
    lines.append("")
    lines.append(f"1. Follow `{meta['playbook']}` for the standardized {meta['severity'].lower()}-severity "
                  "response workflow.")
    lines.append("2. Validate affected host/account list above against asset inventory and privilege level.")
    lines.append("3. Preserve volatile evidence (memory, running process list) before any remediation action "
                  "that would disturb host state.")
    lines.append("4. Update this ticket with analyst findings and final disposition (True Positive / False "
                  "Positive / Benign Positive) to feed detection tuning feedback loop.")
    lines.append("")
    lines.append("---")
    lines.append("*Auto-generated by `scripts/incident_report_generator.py`. Analyst review required before "
                  "closure — this report accelerates triage, it does not replace it.*")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate a Markdown incident report from Splunk hits.")
    parser.add_argument("--detection-hits", required=True, help="JSON file of Splunk search results")
    parser.add_argument("--detection-id", required=True, help="Detection ID, e.g. DE-CA-001")
    parser.add_argument("--enrichment", help="Optional IOC enrichment JSON from ioc_enrichment.py")
    parser.add_argument("--output", required=True, help="Output Markdown file path")
    parser.add_argument("--incident-number", default=None, help="Ticket/incident number; auto-generated if omitted")
    args = parser.parse_args()

    hits = load_json(args.detection_hits)
    if isinstance(hits, dict) and "results" in hits:
        hits = hits["results"]
    enrichment = load_json(args.enrichment) if args.enrichment else None

    incident_number = args.incident_number or f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    report = build_report(args.detection_id, hits, enrichment, incident_number)

    with open(args.output, "w") as f:
        f.write(report)

    print(f"[+] Incident report written to {args.output} ({len(hits)} events processed)")


if __name__ == "__main__":
    main()
