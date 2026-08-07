# Credential Dumping (LSASS Access) Response

**Playbook ID:** PB-002
**Severity:** Critical | **Response SLA:** 15 minutes
**Triggering Detection(s):** `DE-CA-001`
**Owner:** SOC Tier 2 / Incident Response

---

## Purpose

This playbook standardizes the response workflow when detection **DE-CA-001** fires, ensuring consistent,
auditable handling regardless of which analyst is on shift.

## Response Steps

### 1. Triage the Alert

Pull the SourceImage, GrantedAccess mask, and process lineage from the DE-CA-001 hit. Confirm the source process is not on the verified-good hash allowlist (EDR/AV agents legitimately touch LSASS).

### 2. Contain

If the source process is unrecognized/unsigned, isolate the host immediately. Suspend (do not necessarily disable yet — preserve for investigation) the logged-on user session pending investigation.

### 3. Scope Credential Exposure

Assume all credentials cached in LSASS on this host at the time of access are compromised — this includes any admin or service accounts that had logged on interactively or via RDP/RunAs in the prior session. Pull this list from Security 4624/4648 logs.

### 4. Force Credential Rotation

Reset passwords for all potentially exposed accounts, prioritizing privileged/domain-admin-equivalent accounts. Invalidate active Kerberos tickets for those accounts (krbtgt rotation may be warranted if domain-admin exposure is confirmed — engage AD team).

### 5. Hunt for Reuse

Search Security 4624/4625 logs across the environment for logon attempts using the exposed accounts from other hosts in the hours following the dumping event — this indicates the credentials were actively used for lateral movement.

### 6. Root Cause & Close

Determine initial access vector for the dumping tool's arrival (phishing, exploited service, prior persistence). Document and generate the incident report via incident_report_generator.py, attaching IOC enrichment for any dropped binary hashes.

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
