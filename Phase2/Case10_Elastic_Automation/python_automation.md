# Python Automation – Elastic Detection

## Overview

This automation script connects to Elasticsearch and automatically searches for suspicious PowerShell activity.

---

## Features

- Connect to Elasticsearch
- Query PowerShell events
- Detect suspicious command-line arguments
- Print alert output
- Simulate SOC automation workflow

---

## Detection Keywords

- -nop
- -enc
- DownloadString
- IEX
- Net.WebClient

---

## Python Libraries

- elasticsearch
- urllib3

---

## Detection Output

The script generates:
- Hostname
- Username
- Event timestamp
- Process name
- Command line
- Detection alert

---

## Example Detection

[ALERT] Suspicious PowerShell detected
