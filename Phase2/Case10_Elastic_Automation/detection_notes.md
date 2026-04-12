# Detection Notes – Case 10

This detection focuses on suspicious PowerShell execution observed in a real-time Elastic lab.

## Key Indicators
- PowerShell process creation
- Hidden window execution
- NoProfile usage
- Encoded or obfuscated commands
- Use of IEX or DownloadString

## Investigation Focus
- Full command line
- Parent process
- User context
- Repeated execution behavior
- Related network or file events

## Analyst Notes
PowerShell is legitimate by nature, so context is important.
The goal is not to flag every PowerShell event, but to identify suspicious combinations of behavior.

## MITRE Mapping
- T1059.001 – PowerShell
- T1027 – Obfuscated Files or Information
- T1105 – Ingress Tool Transfer
