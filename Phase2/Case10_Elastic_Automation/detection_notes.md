# Detection Notes – PowerShell Automation Detection

## Objective
Detect suspicious PowerShell execution using Elastic Stack and Python automation.

---

## Detection Logic

The detection focuses on suspicious PowerShell command-line arguments including:

- -nop
- -enc
- EncodedCommand
- IEX
- DownloadString
- Net.WebClient

---

## Event Sources

- Sysmon Event ID 1
- Winlogbeat
- Windows PowerShell logs

---

## Detection Workflow

1. Generate PowerShell activity on Windows target
2. Forward logs using Winlogbeat
3. Store logs inside Elasticsearch
4. Query logs using Kibana Discover
5. Run Python automation script
6. Detect suspicious PowerShell execution
7. Generate alert output

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |
| T1105 | Ingress Tool Transfer |
| T1027 | Obfuscated Files or Information |

---

## Detection Outcome

The automation successfully detected:
- Encoded PowerShell commands
- DownloadString usage
- IEX execution patterns

---

## Analyst Notes

This use case simulates real SOC detection engineering workflows using:
- Elastic Stack
- Python
- Sysmon
- Winlogbeat
