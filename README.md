# SOC Detection Engineering Lab

This repository contains a collection of hands-on detection engineering labs designed to simulate common attacker techniques and analyze them using Windows Security Logs.

The purpose of this project is to practice **SOC analysis, threat detection, and incident investigation** using realistic attack simulations.

The labs focus on detecting malicious activity using:

- Windows Event Logs
- PowerShell behavior
- Command line analysis
- LOLBins abuse
- Fileless malware techniques

---

# Lab Environment

Attacker Machine

```
Kali Linux
```

Target Machine

```
Windows 10
```

Logs monitored

```
Windows Security Log
Event ID 4688
```
# Detection Engineering Lab

This repository contains practical detection engineering use cases focused on Windows security monitoring.

The project demonstrates how attackers abuse PowerShell and system binaries, and how these behaviors can be detected using Windows Event Logs and Sigma rules.

Each use case includes:

- Attack simulation
- Detection logic
- Sigma detection rule
- Event log evidence
---

# Detection Use Cases

| Case | Technique | Detection Focus |
|-----|-----|-----|
| Use Case | Description | MITRE Technique |
|----------|-------------|----------------|
| [Case1 – PowerShell Detection](Case1_powershell_detection) | Detect basic PowerShell execution using Windows Event ID 4688 | T1059.001 |
| [Case2 – Encoded PowerShell](Case2_Encoded_PowerShell) | Detect PowerShell commands executed with Base64 encoded payloads | T1059.001 |
| [Case3 – Suspicious Parent Process](Case3_Suspicious_Parent_Process) | Detect suspicious parent-child process relationships | T1059 |
| [Case4 – PowerShell Spawning Rundll32](Case4_PowerShell_Rundll32) | Detect LOLBin abuse where PowerShell launches rundll32 | T1218 |
| [Case5 – Encoded Hidden PowerShell](Case5_Encoded_Hidden_PowerShell) | Detect hidden PowerShell execution using encoded commands | T1059.001 |
| [Case6 – PowerShell Download Payload](Case6_PowerShell_Download_Payload) | HTTP Payload Retrieval | T1105 |
| [Case7 - PowerShell Download Cradle](Case7_PowerShell_IEX_Download) | IEX + Net.WebClient | T1059 |
| [Case8 - Encoded PowerShell Download](Case8_Encoded_PowerShell_Download) | Obfuscated Execution | T1027 |

---

# Detection Techniques Practiced

This project covers several important blue team detection skills:

- PowerShell abuse detection
- Encoded command detection
- Command-line threat hunting
- Fileless malware detection
- Suspicious process creation
- Remote payload retrieval

These techniques are commonly used by:

- Red Team tools
- Malware loaders
- Cobalt Strike
- Fileless attacks

---

# Log Analysis

Most detections rely on analyzing:

```
Event ID 4688
```

Important fields:

```
NewProcessName
CommandLine
ParentProcessName
```

These logs help SOC analysts identify suspicious execution patterns.

---

# Sigma Detection Rules

Each case includes a **Sigma rule** to demonstrate how detection logic can be implemented for SIEM systems.

Sigma rules help translate detection logic into multiple SIEM platforms.

---

# Project Structure

```
SOC-Detection-Lab
│
├── Case-1-PowerShell-Execution
├── Case-2-Encoded-PowerShell
├── Case-3-Suspicious-Parent
├── Case-4-Rundll32-Abuse
├── Case-5-Hidden-PowerShell
├── Case-6-PowerShell-Download
├── Case-7-IEX-Download-Cradle
└── Case-8-Encoded-PowerShell-Download
```

Each case contains:

```
README.md
Sigma Rule
Screenshots
```

---

# Author

Wael Saad Kamal  
Detection Engineer | Network & Security Engineer  

Email: waelsk95@gmail.com

---

# Goal of This Project

The goal of this project is to build a **Detection Engineering portfolio** demonstrating practical SOC investigation and threat detection skills.

This lab environment helps simulate attacker behavior and improve blue team analysis capabilities.
