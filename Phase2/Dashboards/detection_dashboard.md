# Detection Dashboard – LSASS Access

## Alert Name
Suspicious LSASS Access

## Severity
High

## Technique
Credential Access

## MITRE ATT&CK
T1003

## Data Source
Sysmon Event ID 10

## Indicators
- Access to lsass.exe
- High privilege access mask
- Unknown process source

## Analyst Action
- Investigate process origin
- Check parent process
- Isolate host if confirmed malicious
