# Required Splunk Lookups

Several detections reference lookup tables that must be populated per-environment before those searches will
run correctly (they are intentionally NOT shipped pre-populated — allowlists are organization-specific and
shipping fake data would create false confidence).

| Lookup File | Used By | Fields | Purpose |
|---|---|---|---|
| `process_reputation_lookup.csv` | DE-CA-001 | `process_path`, `is_known_good` | Verified-hash allowlist of AV/EDR/admin tooling that legitimately touches LSASS |
| `known_admin_workstations_lookup.csv` | DE-LM-002 | `src_ip`, `is_known_admin_ws` | IP ranges of sanctioned jump boxes / PAW (privileged access workstations) |
| `detection_mitre_lookup.csv` | Dashboards | `detection_id`, `tactic`, `technique_id` | Drives the coverage gauge and tactic breakdown panels — generate from `docs/mitre_attack_mapping.md` |
| Corporate VPN egress ranges | DE-IA-003, DE-DI-002 | `cidr_range`, `location_label` | Prevents impossible-travel and discovery-sweep false positives from VPN concentrator IPs |
| Scanner service account allowlist | DE-DI-002 | `src_ip`, `scanner_name` | Excludes Nessus/Qualys/Rapid7 from network sweep detection |

## Example: Building `detection_mitre_lookup.csv`

```csv
detection_id,tactic,technique_id,severity
DE-IA-001,Initial Access,T1566.001,High
DE-IA-002,Initial Access,T1190,Critical
DE-IA-003,Initial Access,T1078,High
DE-EX-001,Execution,T1059.001,High
DE-EX-002,Execution,T1047,Medium
DE-PE-001,Persistence,T1547.001,Medium
DE-PE-002,Persistence,T1053.005,Medium
DE-PR-001,Privilege Escalation,T1055,Critical
DE-PR-002,Privilege Escalation,T1548.002,High
DE-DE-001,Defense Evasion,T1070.001,Critical
DE-DE-002,Defense Evasion,T1562.001,Critical
DE-CA-001,Credential Access,T1003.001,Critical
DE-CA-002,Credential Access,T1552.001,Medium
DE-CA-003,Credential Access,T1110.003,High
DE-DI-001,Discovery,T1087,Low
DE-DI-002,Discovery,T1018,Low
DE-LM-001,Lateral Movement,T1021.002,High
DE-LM-002,Lateral Movement,T1021.001,Medium
DE-CO-001,Collection,T1560.001,Medium
DE-CO-002,Collection,T1114.003,High
DE-EF-001,Exfiltration,T1048.003,High
DE-C2-001,Command and Control,T1071.001,High
DE-IM-001,Impact,T1486,Critical
```

Upload via **Settings → Lookups → Lookup table files** in Splunk, then define it as a lookup definition with
the same name so `| lookup detection_mitre_lookup detection_id OUTPUT tactic` resolves in the dashboard
searches.
