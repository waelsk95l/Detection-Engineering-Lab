# Phase 1 – PowerShell Detection

This phase focuses on detecting PowerShell-based attacks using Windows Security Logs (Event ID 4688).

The following attack scenarios are covered:

- PowerShell Execution
- Encoded PowerShell
- Suspicious Parent Process
- LOLBins Abuse (rundll32)
- Hidden Execution
- Payload Download
- Download Cradle
- Encoded Payload Execution

## Detection Use Cases

| Case | Technique | Detection Focus |
|-----|-----|-----|
| Use Case | Description | MITRE Technique |
|----------|-------------|----------------|
| [Case1 – PowerShell Detection](Case1_powershell_detection) | Detect basic PowerShell execution using Windows Event ID 4688 | T1059.001 |
| [Case2 – Encoded PowerShell](Case2_Encoded_PowerShell) | Detect PowerShell commands executed with Base64 encoded payloads | T1059.001 |
| [Case3 – Suspicious Parent Process](Case3_Suspicious_Parent_Process) | Detect suspicious parent-child process relationships | T1059.001 |
| [Case4 – PowerShell Spawning Rundll32](Case4_PowerShell_Rundll32) | Detect LOLBin abuse where PowerShell launches rundll32 | T1218.011 |
| [Case5 – Encoded Hidden PowerShell](Case5_Encoded_Hidden_PowerShell) | Detect hidden PowerShell execution using encoded commands | T1027 |
| [Case6 – PowerShell Download Payload](Case6_PowerShell_Download_Payload) | HTTP Payload Retrieval | T1105 |
| [Case7 - PowerShell Download Cradle](Case7_PowerShell_IEX_Download) | IEX + Net.WebClient | T1059 |
| [Case8 - Encoded PowerShell Download](Case8_Encoded_PowerShell_Download) | Obfuscated Execution |T1059.001 - T1027 - T1105  |
