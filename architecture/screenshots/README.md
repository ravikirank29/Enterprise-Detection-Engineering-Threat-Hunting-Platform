# Screenshots

Visual reference for the platform. A couple of notes on provenance, in the interest of honesty on a
portfolio repo:

- **`architecture_diagram.png`** — rendered directly from [`architecture_diagram.svg`](../architecture_diagram.svg)
  in this same folder, which is the source of truth.
- **`splunk_detection_search.png`** — a mockup built to match Splunk's actual Search & Reporting UI, showing
  detection `DE-CA-001` (LSASS memory access) running against sample data. This project was built without a
  live licensed Splunk instance to screenshot against, so this mockup demonstrates the expected UI/UX and
  result shape rather than a real deployment. The SPL query itself is copied verbatim from
  `detections/credential_access/T1003_001_lsass_memory_access.spl`, and is real.
- **`executive_security_posture_dashboard.png`** and **`soc_analyst_triage_dashboard.png`** — mockups
  rendered from the actual panel/query structure defined in `dashboards/*.json`, styled to match Splunk
  Dashboard Studio's dark theme. Sample data is illustrative.
- **`automation_scripts_demo.png`** — this one is **not** a mockup. It's a captured terminal session actually
  running `scripts/incident_report_generator.py` and `scripts/ioc_enrichment.py` against sample data, output
  reproduced verbatim.

## Files

| File | Shows |
|---|---|
| `architecture_diagram.png` | End-to-end data flow: sources → Splunk → detections → notables → dashboards/automation → response |
| `splunk_detection_search.png` | The DE-CA-001 credential-dumping detection running in Splunk Search & Reporting |
| `executive_security_posture_dashboard.png` | Leadership-facing view: critical alert count, MTTR, ATT&CK coverage gauge, tactic breakdown, severity trend |
| `soc_analyst_triage_dashboard.png` | Analyst-facing view: open alert queue, workload distribution, new hosts, detection health monitor |
| `automation_scripts_demo.png` | Real terminal output from the incident report generator and IOC enrichment scripts |
