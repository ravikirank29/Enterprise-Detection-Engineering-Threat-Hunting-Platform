# Account Compromise (Password Spray / Impossible Travel) Response

**Playbook ID:** PB-004
**Severity:** High | **Response SLA:** 60 minutes
**Triggering Detection(s):** `DE-CA-003`
**Owner:** SOC Tier 2 / Incident Response

---

## Purpose

This playbook standardizes the response workflow when detection **DE-CA-003** fires, ensuring consistent,
auditable handling regardless of which analyst is on shift.

## Response Steps

### 1. Triage

Confirm whether any of the sprayed/flagged accounts show a successful authentication following the failed attempts (pivot from DE-CA-003 or DE-IA-003 hit to Security 4624 / AAD sign-in success events for the same account in the following hour).

### 2. Contain

For any account with a confirmed successful login following spray/impossible-travel indicators: force session revocation (AAD: revoke refresh tokens), reset password, and require MFA re-registration.

### 3. Scope

Review the compromised account's activity since the suspicious login: mailbox rule creation (DE-CO-002), OAuth app consent grants, SharePoint/Drive file access, and any admin actions if the account holds elevated roles.

### 4. Notify & Remediate

Notify the account owner and their manager. Remove any malicious inbox rules, revoke any suspicious OAuth grants, and require a security awareness follow-up if the entry vector was phishing.

### 5. Harden

If the source was unauthenticated password spray without success, block the source IP/range at the identity provider and confirm Conditional Access / smart lockout policies are enforced org-wide.

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
