# Phase 2 – Advanced Detection Engineering

Phase 2 represents an advanced stage of the Detection Engineering Lab, focusing on real-world SOC operations, detection logic, and threat analysis.

## Objectives

- Build real-world detection use cases
- Simulate attacker behavior (attack simulation)
- Develop detection rules across multiple platforms
- Create dashboards for security monitoring
- Document incidents in analyst-style reports
- Prepare for automation using Python

---

## Technologies Used

- Windows Sysmon
- Splunk SIEM
- Sigma Rules
- Elastic (Query level)
- Python (Detection Automation – upcoming)

---

## Use Cases

### Case 9 – LSASS Access Detection

Detection of suspicious access attempts to `lsass.exe`, commonly associated with credential dumping techniques.

Includes:

- Splunk detection queries
- Sigma detection rule
- Elastic query (cross-platform detection)
- Dashboard documentation
- Incident report

---

## Project Structure

Phase2/ 
├── Automation/ ├──       Case9_LSASS_Access_Detection/ ├── Dashboards/ ├── Detection-Rules/ ├── Reports/ └── README.md
