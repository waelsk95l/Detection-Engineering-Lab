# Case 9 – LSASS Access Detection

## Overview

This use case focuses on detecting suspicious access to `lsass.exe`, a high-value Windows process commonly targeted during credential access activity.

The goal is to practice advanced detection engineering using:

- Sysmon Event ID 10
- Sigma rules
- Elastic queries
- Splunk queries
- Python-based alert automation

---

## Detection Objective

Identify suspicious process access attempts targeting:

```text
lsass.exe
```

This type of behavior may indicate credential access activity and should be reviewed by SOC analysts.

---

## Log Source

```text
Sysmon
Event ID 10
Process Access
```

---

## MITRE ATT&CK Mapping

- T1003
- T1003.001

---

## Planned Content

This case will include:

- Detection logic
- Sigma rule
- Elastic query
- Splunk query
- Python alert automation
- Detection dashboard
- Analyst report
