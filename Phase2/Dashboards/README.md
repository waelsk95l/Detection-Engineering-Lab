# Dashboards – Phase 2

This folder contains dashboard documentation for detection use cases developed in Phase 2.

## Purpose

- Visualize detection results
- Provide SOC-friendly monitoring views
- Highlight suspicious activities
- Support analyst investigation workflows

---

## Available Dashboards

### LSASS Access Detection Dashboard

This dashboard focuses on detecting suspicious access to `lsass.exe`, which may indicate credential dumping attempts.

Includes:

- Alert overview
- Severity classification
- MITRE ATT&CK mapping
- Key indicators
- Analyst response actions

---

## Data Sources

- Sysmon Event ID 10
- Process access monitoring

---

## Notes

Dashboards are documented in Markdown format and can be implemented in:

- Splunk
- Elastic (Kibana)
- Other SIEM platforms

---

## Author

WAEL SK
