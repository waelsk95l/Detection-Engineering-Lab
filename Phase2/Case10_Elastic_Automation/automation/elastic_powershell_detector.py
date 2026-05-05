
from elasticsearch import Elasticsearch
import urllib3

urllib3.disable_warnings()

ES_URL = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "elastic"

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    verify_certs=False
)

if es.ping():
    print("[OK] Connected to Elasticsearch")
else:
    print("[ERROR] Connection failed")
