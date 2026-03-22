#!/var/ossec/framework/python/bin/python3
# custom-dfir_iris
# Wazuh custom integration:
# rule_id 100622,100623 -> send alert to DFIR-IRIS + Telegram DFIR

import sys
import json
import requests
import logging
import os
import hashlib
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"
DEDUP_DIR = "/var/ossec/var/run/custom-dfir_iris"
TELEGRAM_BOT_TOKEN = "ISI_BOT_TOKEN"
TELEGRAM_CHAT_ID = "-1001234567890"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

os.makedirs(DEDUP_DIR, exist_ok=True)


def safe_get(dct, path, default="N/A"):
    cur = dct
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur if cur not in [None, ""] else default


def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logging.warning("Telegram token/chat_id not configured. Skipping Telegram send.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code not in [200, 201]:
            logging.error("Failed to send Telegram. Status=%s Body=%s", resp.status_code, resp.text)
    except Exception as exc:
        logging.error("Telegram send exception: %s", exc)


def dedup_key(alert_json):
    rule_id = str(safe_get(alert_json, ["rule", "id"], "0"))
    agent_name = safe_get(alert_json, ["agent", "name"], "unknown-agent")
    misp_value = safe_get(alert_json, ["data", "misp", "value"], "")
    if misp_value == "N/A":
        misp_value = safe_get(alert_json, ["misp", "value"], "")
    if misp_value == "N/A":
        misp_value = safe_get(alert_json, ["syscheck", "sha256_after"], "")
    if misp_value == "N/A":
        misp_value = safe_get(alert_json, ["syscheck", "md5_after"], "")
    raw = f"{rule_id}|{agent_name}|{misp_value}"
    return hashlib.sha256(raw.encode()).hexdigest()


def already_sent(alert_json, ttl_seconds=3600):
    key = dedup_key(alert_json)
    path = os.path.join(DEDUP_DIR, key)
    now = datetime.utcnow().timestamp()

    try:
        if os.path.exists(path):
            age = now - os.path.getmtime(path)
            if age < ttl_seconds:
                return True
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(str(now))
    except Exception as exc:
        logging.warning("Dedup check failed: %s", exc)

    return False


def get_misp_block(alert_json):
    misp_data = safe_get(alert_json, ["data", "misp"], None)
    if misp_data != "N/A" and isinstance(misp_data, dict):
        return misp_data

    misp_data = safe_get(alert_json, ["misp"], None)
    if misp_data != "N/A" and isinstance(misp_data, dict):
        return misp_data

    return {}


def get_observable_type(rule_id, misp_type, misp_value):
    if str(rule_id) == "100622":
        return "network"
    if str(rule_id) == "100623":
        return "file"

    if misp_type in ["ip-src", "ip-dst", "ip"]:
        return "network"
    if misp_type in ["md5", "sha1", "sha256", "filename|sha256", "filename|md5"]:
        return "file"
    if "." in str(misp_value) and " " not in str(misp_value):
        return "network"
    return "generic"


def format_alert_details(alert_json):
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {})
    mitre = rule.get("mitre", {})

    misp = get_misp_block(alert_json)

    mitre_ids = ", ".join(mitre.get("id", ["N/A"])) if isinstance(mitre.get("id"), list) else str(mitre.get("id", "N/A"))
    mitre_tactics = ", ".join(mitre.get("tactic", ["N/A"])) if isinstance(mitre.get("tactic"), list) else str(mitre.get("tactic", "N/A"))
    mitre_techniques = ", ".join(mitre.get("technique", ["N/A"])) if isinstance(mitre.get("technique"), list) else str(mitre.get("technique", "N/A"))

    details = [
        f"Rule ID: {rule.get('id', 'N/A')}",
        f"Rule Level: {rule.get('level', 'N/A')}",
        f"Rule Description: {rule.get('description', 'N/A')}",
        f"Agent ID: {agent.get('id', 'N/A')}",
        f"Agent Name: {agent.get('name', 'N/A')}",
        f"Agent IP: {agent.get('ip', 'N/A')}",
        f"MITRE IDs: {mitre_ids}",
        f"MITRE Tactics: {mitre_tactics}",
        f"MITRE Techniques: {mitre_techniques}",
        f"MISP Event ID: {misp.get('event_id', 'N/A')}",
        f"MISP Category: {misp.get('category', 'N/A')}",
        f"MISP Type: {misp.get('type', 'N/A')}",
        f"MISP Value: {misp.get('value', 'N/A')}",
        f"File Path: {misp.get('file_path', safe_get(alert_json, ['syscheck', 'path'], 'N/A'))}",
        f"Location: {alert_json.get('location', 'N/A')}",
        f"Timestamp: {alert_json.get('timestamp', 'N/A')}",
        f"Full Log: {alert_json.get('full_log', 'N/A')}"
    ]
    return "\n".join(details)


def map_severity(rule_level):
    try:
        level = int(rule_level)
    except Exception:
        return 2

    if level < 5:
        return 2
    if level < 7:
        return 3
    if level < 10:
        return 4
    if level < 13:
        return 5
    return 6


def build_payload(alert_json):
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {})
    misp = get_misp_block(alert_json)

    rule_id = str(rule.get("id", "0"))
    misp_type = misp.get("type", "N/A")
    misp_value = misp.get("value", "N/A")
    observable_type = get_observable_type(rule_id, misp_type, misp_value)

    if rule_id == "100622":
        title_prefix = "[MISP NETWORK IOC]"
    elif rule_id == "100623":
        title_prefix = "[MISP FILE IOC]"
    else:
        title_prefix = "[MISP IOC]"

    title = f"{title_prefix} {rule.get('description', 'No Description')}"
    severity = map_severity(rule.get("level", 0))
    description = format_alert_details(alert_json)

    tags = [
        "wazuh",
        "misp",
        f"rule-{rule_id}",
        agent.get("name", "unknown-agent")
    ]
    if observable_type == "network":
        tags.append("network-ioc")
    elif observable_type == "file":
        tags.append("file-ioc")

    payload = {
        "alert_title": title,
        "alert_description": description,
        "alert_source": "Wazuh",
        "alert_source_ref": alert_json.get("id", "Unknown-ID"),
        "alert_source_link": "https://IP-WAZUH/app/wz-home",
        "alert_severity_id": severity,
        "alert_status_id": 2,
        "alert_source_event_time": alert_json.get("timestamp", "Unknown-Timestamp"),
        "alert_note": "",
        "alert_tags": ",".join(tags),
        "alert_customer_id": 1,
        "alert_source_content": alert_json
    }
    return payload, observable_type, misp_value, misp


def send_to_iris(hook_url, api_key, payload):
    headers = {
        "Authorization": "Bearer " + api_key,
        "content-type": "application/json"
    }

    resp = requests.post(
        hook_url,
        json=payload,
        headers=headers,
        verify=False,
        timeout=20
    )
    return resp


def main():
    if len(sys.argv) < 4:
        logging.error("Usage: custom-dfir_iris <alert_file> <api_key> <hook_url>")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    try:
        with open(alert_file, "r", encoding="utf-8") as handle:
            alert_json = json.load(handle)
    except Exception as exc:
        logging.error("Failed to read alert file: %s", exc)
        sys.exit(1)

    rule_id = str(safe_get(alert_json, ["rule", "id"], "0"))

    if rule_id not in ["100622", "100623"]:
        logging.info("Skipping rule_id=%s because it is not in target set.", rule_id)
        sys.exit(0)

    misp = get_misp_block(alert_json)
    if not misp:
        logging.info("Skipping alert because MISP block was not found.")
        sys.exit(0)

    if already_sent(alert_json):
        logging.info("Duplicate alert suppressed for rule_id=%s", rule_id)
        sys.exit(0)

    try:
        payload, observable_type, misp_value, misp_data = build_payload(alert_json)
        response = send_to_iris(hook_url, api_key, payload)

        if response.status_code in [200, 201, 202, 204]:
            logging.info("Sent alert to IRIS successfully. rule_id=%s status=%s", rule_id, response.status_code)

            telegram_msg = (
                f"*DFIR IRIS ALERT CREATED*\n"
                f"Rule ID: `{rule_id}`\n"
                f"Agent: `{safe_get(alert_json, ['agent', 'name'], 'N/A')}`\n"
                f"Type: `{observable_type}`\n"
                f"IOC: `{misp_value}`\n"
                f"MISP Event ID: `{misp_data.get('event_id', 'N/A')}`\n"
                f"Severity: `{safe_get(alert_json, ['rule', 'level'], 'N/A')}`"
            )
            send_telegram(telegram_msg)
        else:
            logging.error(
                "Failed sending alert to IRIS. status=%s body=%s",
                response.status_code,
                response.text
            )
            sys.exit(1)

    except Exception as exc:
        logging.error("Unhandled exception while sending to IRIS: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
