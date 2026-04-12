import requests
import json
from requests.auth import HTTPBasicAuth

ELASTIC_URL = "https://localhost:9200/winlogbeat-*/_search"
USERNAME = "elastic"
PASSWORD = "YOUR_PASSWORD"

query = {
    "size": 20,
    "query": {
        "bool": {
            "must": [
                {"match": {"event.code": "1"}},
                {"wildcard": {"process.name.keyword": "powershell.exe"}}
            ]
        }
    },
    "_source": [
        "@timestamp",
        "host.name",
        "process.name",
        "process.command_line",
        "user.name"
    ]
}

response = requests.get(
    ELASTIC_URL,
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={"Content-Type": "application/json"},
    data=json.dumps(query),
    verify=False
)

data = response.json()

keywords = ["-nop", "hidden", "iex", "enc", "downloadstring"]

print("[*] Checking PowerShell events...\n")

for hit in data.get("hits", {}).get("hits", []):
    source = hit.get("_source", {})
    cmd = source.get("process", {}).get("command_line", "")
    host = source.get("host", {}).get("name", "unknown")
    timestamp = source.get("@timestamp", "unknown")

    if any(k.lower() in cmd.lower() for k in keywords):
        print("[ALERT] Suspicious PowerShell detected")
        print(f"Time: {timestamp}")
        print(f"Host: {host}")
        print(f"CommandLine: {cmd}")
        print("-" * 60)
