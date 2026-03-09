# Use Case 4 – PowerShell Spawning Rundll32

## Objective

Detect suspicious execution where PowerShell launches rundll32.exe.

Attackers often abuse rundll32.exe as a Living-Off-The-Land Binary (LOLBIN) to execute malicious code.

---

## Attack Simulation

The following PowerShell command was executed:
powershell -ExecutionPolicy Bypass -Command "Start-Process rundll32.exe"


This generates the following process chain:
powershell.exe → rundll32.exe


Such behavior can indicate suspicious activity if PowerShell spawns system binaries.

---

## MITRE ATT&CK Mapping

Technique:

T1218 – Signed Binary Proxy Execution

Sub-technique:

T1218.011 – Rundll32

---

## Detection Rule

Example Sigma rule is available in: sigma-rule.yml

---

## Lab Evidence

### 1. PowerShell executing rundll32.exe

![PowerShell Execution](screenshots1.jpg)

---

### 2. Windows Security Event 4688 showing rundll32 process creation

![Event Log](screenshots2.jpg)

