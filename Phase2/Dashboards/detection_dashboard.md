# Detection Dashboard – LSASS Access

## Alert Name
Suspicious LSASS Access

## Severity
High

## Description
Detection of processes attempting to access `lsass.exe` with high privileges, which may indicate credential dumping activity.

---

## Technique
Credential Access

## MITRE ATT&CK
T1003 – Credential Dumping

---

## Data Source
Sysmon Event ID 10

---

## Detection Logic

- Target process: lsass.exe
- Suspicious access masks:
  - 0x1fffff
  - 0x1010
  - 0x1410
- Untrusted or unknown source process

---

## Indicators

- Access to lsass.exe
- High privilege access mask
- Unknown or suspicious process

---

## Analyst Actions

- Investigate process origin
- Check parent process
- Validate digital signature
- Correlate with other alerts
- Isolate host if confirmed malicious

---

## Notes

This dashboard supports SOC analysts in identifying potential credential dumping attempts in real-time environments.
