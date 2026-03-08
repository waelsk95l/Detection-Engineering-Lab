# Case 2 – Encoded PowerShell Execution Detection

## Attack Description
Attackers often use Base64 encoded PowerShell commands to evade detection and hide malicious scripts.

## Lab Environment
- Windows 10 target machine
- Sysmon installed
- Kali Linux attacker machine

## Attack Simulation
Encoded PowerShell command execution using:

powershell -NoProfile -WindowStyle Hidden -EncodedCommand

## Detection Method
Monitoring Windows Security Event ID 4688 for suspicious PowerShell command lines containing:

- EncodedCommand
- Hidden window style
- NoProfile

## Detection Rule
Sigma rule used to detect suspicious PowerShell encoded execution.

## Screenshots
See screenshots in this folder.
