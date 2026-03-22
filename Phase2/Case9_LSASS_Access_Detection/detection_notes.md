# Detection Notes – Case 9

This detection identifies suspicious access to LSASS memory.

Key Indicators:
- Process accessing lsass.exe
- High privilege access rights
- Unknown or non-system process

Investigation Focus:
- SourceImage path
- Parent process
- Command line arguments
- Frequency of access

This detection is mapped to MITRE ATT&CK T1003.001

## Validation Platforms

- Splunk SIEM
- Elastic Stack (Elasticsearch + Kibana + Winlogbeat)
