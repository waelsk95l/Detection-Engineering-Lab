# Case 9 – LSASS Access Detection

## Overview

This use case focuses on detecting suspicious access to **lsass.exe**, a critical Windows process responsible for handling authentication and storing sensitive credentials.

Attackers often target LSASS to extract credentials using credential dumping techniques.

---

## Objective

Detect unauthorized or suspicious process access to:

```text
lsass.exe
```

Such activity may indicate:

- Credential dumping
- Privilege escalation
- Post-exploitation behavior

---

## Attack Simulation

A simulated malicious process attempts to access LSASS with high privileges.

Example:

```text
malware.exe → lsass.exe
```

---

## Log Source

```text
Sysmon
Event ID: 10
Process Access
```

---

## Key Detection Indicators

- Access to `lsass.exe`
- Suspicious process (unknown executable)
- High privilege access rights:
  - `0x1fffff`
  - `0x1010`
  - `0x1410`

---

## MITRE ATT&CK Mapping

- T1003 – Credential Dumping
- T1003.001 – LSASS Memory

---

## Detection Logic

This detection is based on identifying:

- Target process = `lsass.exe`
- Suspicious access mask values
- Unknown or non-system source process

---

## Sigma Rule

See:

```text
sigma-rule.yml
```

---

## SIEM Queries

### Elastic

```text
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe
```

### Splunk

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
```

---

## Sample Log

See:

```text
sample-log.json
```

---

## Automation

This use case includes Python-based detection:

- Log parser
- Detection engine
- Alert generator

Located in:

```text
Phase2/Automation
```

---

## Detection Output

When detection conditions are met:

```text
[ALERT] Suspicious LSASS access detected!
```

---

## Analyst Investigation Steps

1. Identify source process
2. Check process path and hash
3. Analyze parent process
4. Verify if activity is legitimate (EDR/AV) or malicious
5. Investigate lateral movement or persistence

---

## False Positives

- Antivirus software
- EDR solutions
- Security tools accessing LSASS

---

## Severity

```text
High
```

---

## Conclusion

Access to LSASS is highly sensitive and often associated with credential theft.

This detection helps SOC analysts identify and respond to potential credential access attempts early.

---

## Skills Demonstrated

- Sysmon log analysis
- Detection engineering
- Sigma rule creation
- SIEM query development
- Python-based alerting
- Threat investigation
