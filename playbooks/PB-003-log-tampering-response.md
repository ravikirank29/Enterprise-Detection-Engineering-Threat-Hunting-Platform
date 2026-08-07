# Event Log Tampering / Anti-Forensics Response

**Playbook ID:** PB-003
**Severity:** Critical | **Response SLA:** 15 minutes
**Triggering Detection(s):** `DE-DE-001`
**Owner:** SOC Tier 2 / Incident Response

---

## Purpose

This playbook standardizes the response workflow when detection **DE-DE-001** fires, ensuring consistent,
auditable handling regardless of which analyst is on shift.

## Response Steps

### 1. Triage

Log clearing (1102/104) is almost never a false positive outside a documented maintenance window. Immediately cross-reference the acting account against the approved log-rotation service account allowlist; anything else proceeds directly to containment.

### 2. Assume Compromise

Treat this as confirmation of active attacker presence with likely elevated privileges (clearing the Security log requires local admin or equivalent). Isolate the host immediately.

### 3. Recover Lost Telemetry

Check for a centralized log forwarder (Splunk UF, Windows Event Forwarding) — logs already shipped off-host before the clear event survive in the SIEM even though the local log is gone. Pull the pre-clear window from the index to reconstruct what the attacker was hiding.

### 4. Widen the Hunt

Search for correlated activity in the hours before the clear event: credential access (DE-CA-*), persistence (DE-PE-*), and defense evasion (DE-DE-002) detections on the same host — log clearing is typically a closing action, not an opening one.

### 5. Preserve & Escalate

Image the host for forensic preservation before any remediation. Escalate to IR lead immediately given the near-certain confirmation of intrusion.

## Escalation Criteria

Escalate immediately to the IR Lead / on-call manager if:
- Evidence of lateral movement to 3+ hosts is confirmed
- A privileged/service account is confirmed compromised
- Customer data or regulated data (PII/PCI/PHI) exposure is suspected
- The affected system is classified as crown-jewel/Tier-0 infrastructure

## Related Artifacts

- Detection source: see `docs/mitre_attack_mapping.md` for the mapped detection file
- `scripts/incident_report_generator.py` — generates the standardized incident record from this response
- `scripts/ioc_enrichment.py` — enriches any IOCs surfaced during investigation
