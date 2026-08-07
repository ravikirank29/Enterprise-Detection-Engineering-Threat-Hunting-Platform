# Ransomware Containment & Response

**Playbook ID:** PB-001
**Severity:** Critical | **Response SLA:** 15 minutes
**Triggering Detection(s):** `DE-IM-001`
**Owner:** SOC Tier 2 / Incident Response

---

## Purpose

This playbook standardizes the response workflow when detection **DE-IM-001** fires, ensuring consistent,
auditable handling regardless of which analyst is on shift.

## Response Steps

### 1. Detect & Verify

Confirm the DE-IM-001 alert against raw Sysmon EventCode=11 data — check for a burst of file renames/writes with a consistent new extension across many directories. Cross-check DE-DE-002 (Defender tampering) fired recently on the same host, which commonly precedes ransomware deployment.

### 2. Isolate

Immediately isolate the affected host(s) from the network via EDR host-isolation API (do NOT power off — this destroys volatile memory evidence and can trigger destructive routines in some ransomware families). Disable the associated user account(s) if lateral spread is suspected.

### 3. Contain the Blast Radius

Identify and isolate any additional hosts showing the same detection or lateral-movement indicators (DE-LM-001/002) within the prior 24 hours. Disable SMB/admin-share access at the network layer for the affected VLAN/segment if spread is confirmed or suspected.

### 4. Preserve Evidence

Capture a memory image and full disk image (or at minimum, MFT/USN journal + relevant event logs) from patient zero before any remediation. Export the triggering Splunk search results and run incident_report_generator.py to produce the initial incident record.

### 5. Identify the Strain & IOCs

Extract the ransom note, encrypted file extension, and any dropped binaries. Run file hashes through ioc_enrichment.py against VirusTotal. Check ransom note text/format against known-strain databases (ID Ransomware, MalwareHunterTeam) to inform recovery options and decryptor availability.

### 6. Notify

Escalate to IR lead and CISO within SLA. Engage legal/compliance for breach-notification assessment if customer or regulated data may be affected. Do not engage with any threat-actor contact channel without legal and leadership sign-off.

### 7. Eradicate & Recover

Rebuild affected hosts from known-good gold images rather than attempting in-place cleanup. Restore data from backups verified to predate the compromise window (validate backup integrity — check for dormant persistence in backup chain). Rotate all credentials with any exposure on affected hosts, prioritizing privileged/service accounts.

### 8. Post-Incident

Conduct a blameless post-incident review within 5 business days. Feed root-cause findings (initial access vector, dwell time, detection gaps) back into the detection engineering backlog — update this repo's coverage map if a gap contributed to delayed detection.

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
