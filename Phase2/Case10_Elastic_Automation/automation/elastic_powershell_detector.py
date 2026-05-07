from elasticsearch import Elasticsearch
import urllib3

urllib3.disable_warnings()

ES_URL = "https://127.0.0.1:9200"
ES_USER = "elastic"
ES_PASS = "pass@2020"

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    verify_certs=False,
    ssl_show_warn=False,
    request_timeout=30
)

# Test connection
try:
    info = es.info()
    print("[OK] Connected to Elasticsearch")
    print("Cluster Name:", info["cluster_name"])
except Exception as e:
    print("[ERROR] Connection failed")
    print(e)
    exit()

# 🔥 Detection Query (ONLY useful events)
query = {
    "bool": {
        "must": [
            {
                "match": {
                    "process.name": "powershell.exe"
                }
            },
            {
                "match": {
                    "event.code": "1"
                }
            }
        ]
    }
}

try:
    response = es.search(
        index="winlogbeat-*",
        query=query,
        size=10
    )

    hits = response["hits"]["hits"]

    print(f"\n[+] Found {len(hits)} REAL PowerShell executions\n")

    for hit in hits:
        source = hit["_source"]

        timestamp = source.get("@timestamp", "N/A")
        host = source.get("host", {}).get("name", "N/A")
        user = source.get("user", {}).get("name", "N/A")
        process_name = source.get("process", {}).get("name", "N/A")
        command_line = source.get("process", {}).get("command_line", "N/A")

        # 🔥 detection logic
        suspicious_keywords = [
            "-enc",
            "encodedcommand",
            "-nop",
            "noprofile",
            "iex",
            "downloadstring",
            "bypass"
        ]

        is_suspicious = False

        if command_line != "N/A":
            cmd_lower = command_line.lower()
            for keyword in suspicious_keywords:
                if keyword in cmd_lower:
                    is_suspicious = True

        print("=" * 60)
        print("Time:", timestamp)
        print("Host:", host)
        print("User:", user)
        print("Process:", process_name)
        print("Command Line:", command_line)

        if is_suspicious:
            print("🚨 [ALERT] Suspicious PowerShell detected")
        else:
            print("🟢 [OK] Normal PowerShell")

    print("=" * 60)

except Exception as e:
    print("[ERROR] Query failed")
    print(e)
