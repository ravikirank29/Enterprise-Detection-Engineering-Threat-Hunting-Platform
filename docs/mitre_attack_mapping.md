# MITRE ATT&CK Coverage Map

23 detections mapped across 12 ATT&CK (Enterprise) tactics. This table is the source of truth linking each
detection ID to its technique, data source, and severity — used to drive the ATT&CK Navigator heatmap export
and the executive dashboard's coverage panel.

| Detection ID | Tactic | Technique ID | Technique Name | Data Source | Severity | File |
|---|---|---|---|---|---|---|
| DE-IA-001 | Initial Access | T1566.001 / T1204.002 | Spearphishing Attachment / User Execution | Sysmon 1 | High | `detections/initial_access/T1566_001_spearphishing_attachment_execution.spl` |
| DE-IA-002 | Initial Access | T1190 | Exploit Public-Facing Application | Sysmon 1, IIS/Apache | Critical | `detections/initial_access/T1190_exploit_public_facing_application.spl` |
| DE-IA-003 | Initial Access | T1078 | Valid Accounts (Impossible Travel) | Azure AD / Okta | High | `detections/initial_access/T1078_valid_accounts_impossible_travel.spl` |
| DE-EX-001 | Execution | T1059.001 | PowerShell | PS Operational 4104 | High | `detections/execution/T1059_001_powershell_obfuscation.spl` |
| DE-EX-002 | Execution | T1047 | Windows Management Instrumentation | Sysmon 1 | Medium | `detections/execution/T1047_wmi_lateral_execution.spl` |
| DE-PE-001 | Persistence | T1547.001 | Registry Run Keys / Startup Folder | Sysmon 13/11 | Medium | `detections/persistence/T1547_001_registry_run_key_persistence.spl` |
| DE-PE-002 | Persistence | T1053.005 | Scheduled Task | Security 4698 | Medium | `detections/persistence/T1053_005_scheduled_task_creation.spl` |
| DE-PR-001 | Privilege Escalation | T1055 | Process Injection | Sysmon 8/10 | Critical | `detections/privilege_escalation/T1055_process_injection.spl` |
| DE-PR-002 | Privilege Escalation | T1548.002 | Bypass User Account Control | Sysmon 1 | High | `detections/privilege_escalation/T1548_002_uac_bypass.spl` |
| DE-DE-001 | Defense Evasion | T1070.001 | Clear Windows Event Logs | Security 1102 / System 104 | Critical | `detections/defense_evasion/T1070_001_windows_event_log_clearing.spl` |
| DE-DE-002 | Defense Evasion | T1562.001 | Disable or Modify Tools | Defender Operational | Critical | `detections/defense_evasion/T1562_001_defender_tampering.spl` |
| DE-CA-001 | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Sysmon 10 | Critical | `detections/credential_access/T1003_001_lsass_memory_access.spl` |
| DE-CA-002 | Credential Access | T1552.001 | Credentials In Files | Sysmon 1 | Medium | `detections/credential_access/T1552_001_credentials_in_files.spl` |
| DE-CA-003 | Credential Access | T1110.003 | Password Spraying | Security 4625 / AAD Sign-In | High | `detections/credential_access/T1110_password_spray.spl` |
| DE-DI-001 | Discovery | T1087 / T1069 | Account / Permission Groups Discovery | Sysmon 1 | Low | `detections/discovery/T1087_account_discovery.spl` |
| DE-DI-002 | Discovery | T1018 / T1046 | Remote System / Network Service Discovery | Firewall/NetFlow | Low | `detections/discovery/T1018_remote_system_discovery.spl` |
| DE-LM-001 | Lateral Movement | T1021.002 | SMB/Windows Admin Shares | Security 5140 | High | `detections/lateral_movement/T1021_002_admin_share_lateral_movement.spl` |
| DE-LM-002 | Lateral Movement | T1021.001 | Remote Desktop Protocol | Security 4624 | Medium | `detections/lateral_movement/T1021_001_rdp_lateral_movement.spl` |
| DE-CO-001 | Collection | T1560.001 | Archive via Utility | Sysmon 1 | Medium | `detections/collection/T1560_001_archive_staging.spl` |
| DE-CO-002 | Collection | T1114.003 | Email Forwarding Rule | O365 Audit Log | High | `detections/collection/T1114_001_mailbox_rule_exfil.spl` |
| DE-EF-001 | Exfiltration | T1048.003 | Exfiltration Over DNS | DNS/Zeek | High | `detections/exfiltration/T1048_dns_exfiltration.spl` |
| DE-C2-001 | Command and Control | T1071.001 | Web Protocols (Beaconing) | Proxy | High | `detections/command_and_control/T1071_001_c2_beaconing.spl` |
| DE-IM-001 | Impact | T1486 | Data Encrypted for Impact (Ransomware) | Sysmon 11 | Critical | `detections/impact/T1486_ransomware_mass_file_encryption.spl` |

## Coverage by Severity

| Severity | Count |
|---|---|
| Critical | 6 |
| High | 9 |
| Medium | 6 |
| Low | 2 |

## Coverage Gaps (Roadmap for v2)

Documented honestly for interview/portfolio credibility — no detection engineering program launches with full
coverage:

- **Cloud-native attack paths** (AWS/Azure control-plane abuse, IAM privilege escalation) — planned for the
  companion AWS IAM Security Auditor project.
- **T1071.004 (DNS-based C2)** beyond tunneling — partial overlap with DE-EF-001, dedicated detection planned.
- **Container/Kubernetes techniques** (T1610, T1611) — out of scope for this phase; no container fleet in the
  current lab data source coverage.
- **Insider-threat behavioral baselining** (UEBA-style) — requires longer data retention than the current lab
  Splunk instance provides; noted as a Phase 3 item.
