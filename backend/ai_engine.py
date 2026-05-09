import os
import warnings
from dotenv import load_dotenv
from ibm_watsonx_ai import APIClient, Credentials
from ibm_watsonx_ai.foundation_models import ModelInference

warnings.filterwarnings("ignore")
load_dotenv()

credentials = Credentials(
    url=os.getenv("WATSONX_URL"),
    api_key=os.getenv("WATSONX_API_KEY")
)

client = APIClient(
    credentials=credentials,
    project_id=os.getenv("WATSONX_PROJECT_ID")
)

model = ModelInference(
    model_id="meta-llama/llama-3-3-70b-instruct",
    api_client=client,
    params={
        "max_new_tokens": 500,
        "temperature": 0.1,
        "repetition_penalty": 1.3
    }
)


def clean_response(text):
    """Remove model artifacts and self-corrections."""
    cutoffs = ["Note:", "The correct answer", "The final answer", "However,\nNote"]
    for marker in cutoffs:
        if marker in text:
            text = text[:text.index(marker)]
    return text.strip()


def summarize_alerts(alerts):
    """Generate a structured SOC analyst summary for a list of alerts."""
    if not alerts:
        return "No alerts to summarize."

    alert_text = _format_alerts(alerts)

    prompt = f"""<|system|>
You are a SOC analyst assistant reviewing Wazuh SIEM alerts from a Kubernetes cluster.
Respond in exactly this structure, no deviations:

SUMMARY:
<2-3 sentences: what is happening, which resources are affected>

SEVERITY:
<High / Medium / Low — one sentence explaining why>

COMPLIANCE IMPACT:
<Which PCI-DSS or GDPR requirements are affected and why>

RECOMMENDED ACTIONS:
1. <specific action>
2. <specific action>
3. <specific action>
4. <specific action>
5. <specific action>

Do not add anything outside this structure.
<|user|>
Analyze these Wazuh alerts:
{alert_text}
<|assistant|>"""

    return clean_response(model.generate_text(prompt=prompt))


def investigate_single_alert(alert):
    """Deep investigation of one specific alert."""
    prompt = f"""<|system|>
You are a SOC analyst. Write exactly 4 sentences about this alert. No more.
Sentence 1: What triggered this alert and what it means technically.
Sentence 2: The risk level and why.
Sentence 3: Compliance implications if any.
Sentence 4: The single most important immediate action.
Do not write introductions, conclusions, or anything outside these 4 sentences.
<|user|>
Rule ID: {alert.get('rule', {}).get('id')}
Level: {alert.get('rule', {}).get('level')}
Description: {alert.get('rule', {}).get('description')}
Log: {alert.get('full_log', '')[:300]}
Groups: {alert.get('rule', {}).get('groups', [])}
Namespace: {alert.get('data', {}).get('namespace', 'N/A')}
PCI-DSS: {alert.get('rule', {}).get('pci_dss', [])}
GDPR: {alert.get('rule', {}).get('gdpr', [])}
<|assistant|>"""

    return clean_response(model.generate_text(prompt=prompt))


def answer_question(alerts, question, history=None):
    """Answer a specific analyst question about current alerts."""
    alert_text = _format_alerts(alerts[:10])
    history_text = _format_history(history or [])

    # Build severity summary for context
    levels = [a.get('rule', {}).get('level', 0) for a in alerts]
    severity_context = (
        f"Alert severity summary: "
        f"{sum(1 for l in levels if l >= 12)} critical (12+), "
        f"{sum(1 for l in levels if 7 <= l < 12)} high (7-11), "
        f"{sum(1 for l in levels if l < 7)} low (<7)"
    )

    prompt = f"""<|system|>
You are a SOC analyst assistant. Answer the analyst's question based on the provided alerts.
Be direct and factual. Maximum 3 sentences. No hedging. No reasoning steps.
If the answer is a number, state it directly.
If the question cannot be answered from the alerts, say so in one sentence.
<|user|>
{severity_context}

Current alerts:
{alert_text}

{f"Previous conversation:{chr(10)}{history_text}" if history_text else ""}

Question: {question}
<|assistant|>"""

    return clean_response(model.generate_text(prompt=prompt))


def generate_dql(user_request):
    """Generate a valid Wazuh OpenSearch DQL query from natural language."""
    prompt = f"""<|system|>
You are a Wazuh OpenSearch expert. Convert the request to a valid DQL query.

DQL rules:
- Field:value for exact match
- field:value* for wildcard
- field >= N for numeric comparison
- AND / OR / NOT for logic
- No pipe characters
- No backticks

Wazuh field reference:
- rule.level (1-15, use >= for ranges)
- rule.id (e.g. rule.id:100504)
- rule.groups (e.g. rule.groups:k8s_security)
- rule.description
- rule.gdpr (e.g. rule.gdpr:*)
- rule.pci_dss (e.g. rule.pci_dss:*)
- data.integration:kubernetes
- data.event_type (k8s_warning_event, k8s_rbac_binding, k8s_pod_unhealthy)
- data.namespace
- data.name
- data.reason (FailedCreate, BackOff, Failed, Forbidden)
- data.message
- agent.name

Return ONLY the raw DQL string. No explanation. No quotes wrapping it. No pipe at start.
<|user|>
Request: {user_request}
<|assistant|>"""

    response = model.generate_text(prompt=prompt)
    # Clean up any artifacts
    dql = clean_response(response)
    dql = dql.strip().lstrip('|').strip()
    # Remove any wrapping quotes
    if dql.startswith('"') and dql.endswith('"'):
        dql = dql[1:-1]
    return dql


def generate_search_dsl(user_request):
    """Generate OpenSearch DSL JSON for backend queries."""
    prompt = f"""<|system|>
You are an OpenSearch expert. Convert the request to a valid OpenSearch DSL JSON query object.
Return ONLY raw JSON. No markdown. No explanation. No code blocks.

Available fields: rule.level (numeric), rule.id, rule.groups, data.namespace,
data.name, data.reason, data.message, data.integration, data.event_type, timestamp

Always include: size (default 10), sort by timestamp desc, _source fields list.
<|user|>
Request: {user_request}
Output:"""

    response = model.generate_text(prompt=prompt)
    return response.strip().replace("```json", "").replace("```", "").strip()


def _format_alerts(alerts):
    """Format alerts list for prompt injection."""
    text = ""
    for a in alerts:
        rule = a.get('rule', {})
        text += (
            f"\n[{a.get('timestamp', 'unknown')}] "
            f"Rule {rule.get('id')} (Level {rule.get('level')}): "
            f"{rule.get('description')}\n"
            f"  Log: {a.get('full_log', '')[:200]}\n"
            f"  Namespace: {a.get('data', {}).get('namespace', 'N/A')}\n"
            f"  Compliance: PCI-DSS {rule.get('pci_dss', [])} | GDPR {rule.get('gdpr', [])}\n"
        )
    return text


def _format_history(history):
    """Format conversation history for prompt injection."""
    text = ""
    for msg in history[-6:]:
        role = "Analyst" if msg.get('role') == 'user' else "Assistant"
        content = msg.get('content', '')[:300]
        text += f"{role}: {content}\n"
    return text
