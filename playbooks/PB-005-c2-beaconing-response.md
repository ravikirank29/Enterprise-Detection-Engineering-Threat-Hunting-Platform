# C2 Beaconing Response

**Playbook ID:** PB-005
**Severity:** High | **Response SLA:** 60 minutes
**Triggering Detection(s):** `DE-C2-001`
**Owner:** SOC Tier 2 / Incident Response

---

## Purpose

This playbook standardizes the response workflow when detection **DE-C2-001** fires, ensuring consistent,
auditable handling regardless of which analyst is on shift.

## Response Steps

### 1. Validate

Confirm the flagged destination isn't an allowlisted SaaS telemetry/health-check endpoint. Pivot to the source host's process tree via Sysmon to identify what's initiating the connections (network correlation by src_ip → EDR process/network module).

### 2. Contain

Isolate the source host at the network layer (EDR isolation preferred over firewall block, to preserve ongoing telemetry collection from the isolated host).

### 3. Identify the Implant

Identify the responsible process/binary from EDR telemetry. Extract and hash it, run through ioc_enrichment.py against VirusTotal. Check for persistence mechanisms installed by the same process (cross-reference DE-PE-001/002 on the same host).

### 4. Threat Intel Pivot

Enrich the C2 destination IP/domain via ioc_enrichment.py. Check for infrastructure overlap with known threat actor TTPs (JA3/JA3S fingerprints, SSL cert reuse, ASN patterns) if available in your threat intel platform.

### 5. Hunt for Additional Beacons

Search proxy/firewall logs org-wide for connections to the same destination or infrastructure cluster from other hosts — a single beacon is rarely isolated in a real intrusion.

### 6. Eradicate & Report

Remove the implant and any associated persistence. Generate the incident report with full IOC enrichment attached and update threat intel feeds/blocklists with the confirmed-malicious infrastructure.

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
