#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import re
from datetime import datetime

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip3 install requests")
    sys.exit(1)

CHAT_ID = "<chat-id>"

def extract_ip(description):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_match = re.search(ip_pattern, description)
    return ip_match.group(0) if ip_match else 'N/A'

def extract_domain(description):
    domain_pattern = r'(?:(?:https?|ftp):\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    domain_match = re.search(domain_pattern, description)
    return domain_match.group(1) if domain_match else 'Unknown target'

def create_message(alert_json):
    # Get alert information
    title = alert_json['rule']['description'] if 'description' in alert_json['rule'] else ''
    description = alert_json['full_log'] if 'full_log' in alert_json else ''
    description = description.replace("\\n", "\n")  # Replace escaped newlines with actual newlines
    alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else ''
    groups = ', '.join(alert_json['rule']['groups']) if 'groups' in alert_json['rule'] else ''
    rule_id = alert_json['rule']['id'] if 'rule' in alert_json else ''
    agent_name = alert_json['agent']['name'] if 'name' in alert_json['agent'] else ''
    agent_id = alert_json['agent']['id'] if 'id' in alert_json['agent'] else ''

    # Extract attacker IP from description (log)
    attacker_ip = extract_ip(description)
    # Extract target domain from description (log)
    target = extract_domain(description)

    # Get current time in the desired format
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Format message with HTML
    msg_content = f'<b>Attack: {title}</b>\n'  # Add "Attack:" prefix before the title
    msg_content += f'<pre><code class="language-shell">{description}</code></pre>\n'  # Wrap description in <pre> tag for monospace
    msg_content += f'<b>Target:</b> {target}\n'
    msg_content += f'<b>IP Attacker:</b> {attacker_ip}\n'
    msg_content += f'<b>Groups:</b> {groups}\n' if len(groups) > 0 else ''
    msg_content += f'<b>Rule:</b> {rule_id} (Level {alert_level})\n'
    msg_content += f'<b>Agent:</b> {agent_name} ({agent_id})\n' if len(agent_name) > 0 else ''
    msg_content += f'<b>Time:</b> {current_time}\n'  # Add the current time

    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = msg_content
    msg_data['parse_mode'] = 'html'  # Use HTML parse mode to support <pre> and other HTML tags

    # Debug information
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f'MSG: {msg_data}\n')

    return json.dumps(msg_data)


# Read configuration parameters
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Send the request
msg_data = create_message(alert_json)
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
response = requests.post(hook_url, headers=headers, data=msg_data)

# Debug information
with open('/var/ossec/logs/integrations.log', 'a') as f:
    f.write(f'RESPONSE: {response}\n')

sys.exit(0)
