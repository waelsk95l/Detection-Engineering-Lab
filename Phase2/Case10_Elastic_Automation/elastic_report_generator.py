import requests
import json
from requests.auth import HTTPBasicAuth

ELASTIC_URL = "https://localhost:9200/winlogbeat-*/_search"
USERNAME = "elastic"
PASSWORD = "YOUR_PASSWORD"

query = {
    "size": 10,
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
        "process.command_line"
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

with open("sample_output.txt", "w", encoding="utf-8") as f:
    f.write("PowerShell Detection Report\n")
    f.write("=" * 50 + "\n")

    for hit in data.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        timestamp = source.get("@timestamp", "unknown")
        host = source.get("host", {}).get("name", "unknown")
        cmd = source.get("process", {}).get("command_line", "N/A")

        f.write(f"Time: {timestamp}\n")
        f.write(f"Host: {host}\n")
        f.write(f"Command: {cmd}\n")
        f.write("-" * 50 + "\n")

print("[OK] Report saved to sample_output.txt")
