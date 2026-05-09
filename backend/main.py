from flask import Flask, jsonify, request, send_from_directory
from wazuh_client import get_alerts
from ai_engine import (
    summarize_alerts,
    investigate_single_alert,
    answer_question,
    generate_dql,
    generate_search_dsl
)
from collections import Counter
import json
import requests
import os
import warnings
from dotenv import load_dotenv

warnings.filterwarnings("ignore")
load_dotenv()

app = Flask(__name__)

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

KNOWN_DSL_FILTERS = {
    "critical":     {"range": {"rule.level": {"gte": 12}}},
    "high":         {"range": {"rule.level": {"gte": 7}}},
    "today":        {"range": {"timestamp": {"gte": "now/d"}}},
    "rootcheck":    {"match": {"rule.groups": "rootcheck"}},
    "gdpr":         {"exists": {"field": "rule.gdpr"}},
    "pci":          {"exists": {"field": "rule.pci_dss"}},
    "kubernetes":   {"match": {"data.integration": "kubernetes"}},
    "scc":          {"match": {"rule.groups": "k8s_security"}},
    "rbac":         {"match": {"rule.groups": "k8s_rbac"}},
    "crash":        {"match": {"data.reason": "BackOff"}},
}

KNOWN_DQL_MAP = {
    "critical":   "rule.level >= 12",
    "high":       "rule.level >= 7",
    "today":      "timestamp >= now/d",
    "rootcheck":  "rule.groups:rootcheck",
    "gdpr":       "rule.gdpr:*",
    "pci":        "rule.pci_dss:*",
    "kubernetes": "data.integration:kubernetes",
    "scc":        "rule.groups:k8s_security",
    "rbac":       "rule.groups:k8s_rbac OR rule.groups:k8s_audit",
    "crash":      "data.reason:BackOff",
}


def build_base_dsl(size=10, filter_query=None):
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule", "agent", "data", "full_log"]
    }
    if filter_query:
        query["query"] = filter_query
    return query


def match_known_filter(message):
    msg = message.lower()
    for key, dsl in KNOWN_DSL_FILTERS.items():
        if key in msg:
            return dsl, KNOWN_DQL_MAP.get(key, key)
    return None, None


def run_indexer_query(dsl_query):
    print(f"\nDSL: {json.dumps(dsl_query, indent=2)}")
    res = requests.post(
        f"{os.getenv('WAZUH_INDEXER_URL')}/wazuh-alerts-4.x-*/_search",
        auth=(os.getenv('WAZUH_INDEXER_USER'), os.getenv('WAZUH_INDEXER_PASS')),
        json=dsl_query,
        verify=False
    )
    return res.json()


def format_alert_breakdown(alerts):
    rule_counts = Counter(a['rule']['id'] for a in alerts)
    seen = set()
    breakdown = ""
    for a in alerts:
        rid = a['rule']['id']
        if rid not in seen:
            seen.add(rid)
            breakdown += f"\n- **Rule {rid}** (Level {a['rule']['level']}): {a['rule']['description']} — {rule_counts[rid]}x"
    return breakdown


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/alerts", methods=["GET"])
def alerts():
    limit = request.args.get("limit", 15, type=int)
    severity = request.args.get("severity", 0, type=int)
    data = get_alerts(limit=limit, severity_min=severity)
    return jsonify(data)


@app.route("/api/summary", methods=["GET"])
def summary():
    """Get AI summary of recent alerts."""
    limit = request.args.get("limit", 10, type=int)
    severity = request.args.get("severity", 0, type=int)
    alerts = get_alerts(limit=limit, severity_min=severity)
    if not alerts:
        return jsonify({"alert_count": 0, "summary": "No alerts found."})
    return jsonify({
        "alert_count": len(alerts),
        "summary": summarize_alerts(alerts)
    })


@app.route("/api/investigate", methods=["POST"])
def investigate():
    """Investigate a specific alert passed from the frontend."""
    alert = request.get_json()
    if not alert:
        return jsonify({"error": "No alert data provided"}), 400
    analysis = investigate_single_alert(alert)
    return jsonify({"analysis": analysis})


@app.route("/api/search", methods=["POST"])
def search():
    """Search alerts by natural language and return AI summary."""
    data = request.get_json()
    user_message = data.get("message", "")

    # Try known filter first
    filter_query, dql = match_known_filter(user_message)

    if not filter_query:
        # Fall back to AI-generated DSL
        dsl_string = generate_search_dsl(user_message)
        try:
            filter_query = json.loads(dsl_string).get("query", {"match_all": {}})
            dql = generate_dql(user_message)
        except json.JSONDecodeError:
            return jsonify({
                "response": (
                    "I couldn't parse that search. Try:\n"
                    "- 'show me high severity alerts'\n"
                    "- 'show me GDPR alerts'\n"
                    "- 'show me kubernetes SCC violations'\n"
                    "- 'show me crash-looping pods'"
                )
            })

    result = run_indexer_query(build_base_dsl(size=10, filter_query=filter_query))
    hits = result.get("hits", {}).get("hits", [])
    found = [h["_source"] for h in hits]

    if not found:
        return jsonify({
            "response": f"No alerts found.\n\nDQL to verify: `{dql}`"
        })

    breakdown = format_alert_breakdown(found)
    ai_summary = summarize_alerts(found)

    return jsonify({
        "response": (
            f"Found **{len(found)}** alerts.\n\n"
            f"**Breakdown:**{breakdown}\n\n"
            f"**DQL for Wazuh Dashboard:** `{dql}`\n\n"
            f"**Analysis:**\n{ai_summary}"
        )
    })


@app.route("/api/count", methods=["POST"])
def count():
    """Count alerts matching a query."""
    data = request.get_json()
    user_message = data.get("message", "")

    filter_query, dql = match_known_filter(user_message)
    dsl = build_base_dsl(size=0, filter_query=filter_query or {"match_all": {}})

    result = run_indexer_query(dsl)
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    dql_str = dql or "*"

    return jsonify({
        "response": f"There are **{total}** alerts matching your query.\n\nDQL to verify: `{dql_str}`"
    })


@app.route("/api/dql", methods=["POST"])
def dql_endpoint():
    """Generate a DQL query for Wazuh Dashboard."""
    data = request.get_json()
    user_message = data.get("message", "")

    # Check known map first
    _, known_dql = match_known_filter(user_message)
    if known_dql:
        dql = known_dql
    else:
        dql = generate_dql(user_message)

    return jsonify({
        "response": (
            f"**DQL Query for Wazuh Dashboard:**\n\n"
            f"`{dql}`\n\n"
            f"Paste this into the search bar in Wazuh Discover with DQL mode enabled."
        )
    })


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")
    history = data.get("history", [])

    # Fetch alerts across severity levels for better context
    high_alerts = get_alerts(limit=5, severity_min=7)
    all_alerts = get_alerts(limit=5, severity_min=0)
    
    # Merge, deduplicate by timestamp
    seen = set()
    combined = []
    for a in high_alerts + all_alerts:
        key = a.get('timestamp', '') + a.get('rule', {}).get('id', '')
        if key not in seen:
            seen.add(key)
            combined.append(a)

    answer = answer_question(combined, user_message, history)
    return jsonify({"response": answer})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
