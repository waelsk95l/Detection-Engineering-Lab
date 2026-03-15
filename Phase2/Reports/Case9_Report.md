# Incident Report – LSASS Access Detection

## Summary
A suspicious process attempted to access lsass.exe with high privileges.

## Details
- Source Process: malware.exe
- Target Process: lsass.exe
- Access Mask: 0x1fffff

## Analysis
This behavior is commonly associated with credential dumping techniques.

## MITRE Mapping
T1003 – Credential Dumping

## Recommendation
- Investigate the source binary
- Check for persistence mechanisms
- Perform memory analysis if needed

## Conclusion
Potential credential access attempt detected.
