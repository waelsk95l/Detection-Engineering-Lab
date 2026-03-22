# Detection Dashboard – LSASS Access

## Alert Name
Suspicious LSASS Process Access

## Severity
High

---

## Description
This detection identifies processes attempting to access the LSASS (Local Security Authority Subsystem Service) memory space.

Such behavior is commonly associated with credential dumping techniques used by attackers to extract authentication material such as passwords, hashes, or Kerberos tickets.

---

## Technique
Credential Access

## MITRE ATT&CK
- T1003 – Credential Dumping  
- T1003.001 – LSASS Memory  

---

## Data Source
- Sysmon Event ID 10 (Process Access)
- Collected via Winlogbeat
- Analyzed using:
  - Elastic Stack (Elasticsearch + Kibana)
  - Splunk SIEM

---

## Detection Logic

Trigger alert when:

- `event.code = 10`
- AND `TargetImage` contains `lsass.exe`

### High-Risk Access Masks:
- `0x1fffff` → Full Access (Critical)
- `0x1010` → Read/Query
- `0x1410` → Read + Memory Access
- `0x2000` → Query Information (Observed in lab)

### Suspicious Conditions:
- Access to LSASS by non-system processes
- Unknown or unsigned executables
- Unusual parent-child process relationships
- Execution from non-standard paths:
  - Temp
  - AppData
  - ProgramData

---

## Indicators

- Access to: `C:\Windows\System32\lsass.exe`
- Presence of Sysmon Event ID 10
- Suspicious or unknown source process
- Elevated or unusual access rights
- Repeated access attempts

---

## Elastic Detection Query (KQL)

```kql
event.code:10 AND winlog.event_data.TargetImage:"*lsass.exe"

```

### Analyst Investigation Steps

Identify source process (if available)
Review process execution path
Check parent process relationship
Validate digital signature and file hash
Correlate with:
Event ID 1 (Process Creation)
Network connections
Determine if activity matches known security tools
Escalate if process is unknown or suspicious


### False Positives

Legitimate access to LSASS may occur from:

 - Antivirus software
 - Endpoint Detection & Response (EDR) tools
 - Backup or monitoring agents

   
### Recommendation:

Whitelist known trusted processes to reduce noise.


### Response Actions
 - Isolate affected host if malicious activity is confirmed
 - Terminate suspicious process
 - Collect forensic evidence (memory dump if required)
 - Reset potentially compromised credentials
 - Monitor for lateral movement or persistence

   
### Notes

 - Detection validated using a real-time SOC lab
 - Logs collected via Sysmon and forwarded using Winlogbeat
 - Analysis performed in both Elastic and Splunk environments
 - Some fields like SourceImage may not always appear depending on event structure
 - GrantedAccess values provide insight into the level of access


### Conclusion

This detection successfully identifies LSASS access behavior using real-time log ingestion.

It demonstrates end-to-end SOC capabilities including:

 - Log collection
 - Detection engineering
 - Threat analysis
 - Multi-platform validation (Elastic + Splunk)

## Related Use Case

This dashboard is based on the following lab:

👉 ../Case9_LSASS_Access_Detection/

```
