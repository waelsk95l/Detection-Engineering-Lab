# Case 10 - Elastic Automation Detection

##  Scenario
Detect automated suspicious activities using Elastic Stack and Python scripts.

##  Detection Objective
- Identify automated attacks
- Detect abnormal scripting behavior
- Monitor suspicious processes

##  Detection Logic
- Unusual process execution
- High frequency events
- Suspicious PowerShell usage
- Encoded commands

##  Tools Used
- Elastic Stack (Elasticsearch + Kibana)
- Python Automation
- Sysmon Logs

##  MITRE ATT&CK Mapping
| Technique | ID |
|----------|----|
| Command and Scripting Interpreter (PowerShell) | T1059.001 |
| Obfuscated Files or Information | T1027 |

##  Example Detection Query (Elastic)
```kql
process.name : "powershell.exe" AND process.command_line : "*enc*"
