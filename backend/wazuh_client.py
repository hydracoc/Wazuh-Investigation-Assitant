import requests
import os
from dotenv import load_dotenv

load_dotenv()

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS")

def get_alerts(limit=20, severity_min=0, index="wazuh-alerts-4.x-*"):
    """Fetch alerts from Wazuh indexer filtered by minimum severity level."""
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule", "agent", "data", "location", "full_log"
        ],
        "query": {
            "range": {
                "rule.level": {"gte": severity_min}
            }
        }
    }

    response = requests.post(
        f"{INDEXER_URL}/{index}/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False
    )

    hits = response.json().get("hits", {}).get("hits", [])
    return [hit["_source"] for hit in hits]


def get_alerts_by_rule_group(group, limit=20):
    """Fetch alerts filtered by rule group e.g. rootcheck, ossec."""
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule", "agent", "data", "location", "full_log"
        ],
        "query": {
            "match": {"rule.groups": group}
        }
    }

    response = requests.post(
        f"{INDEXER_URL}/{index}/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False
    )

    hits = response.json().get("hits", {}).get("hits", [])
    return [hit["_source"] for hit in hits]
