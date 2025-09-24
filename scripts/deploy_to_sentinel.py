#!/usr/bin/env python3
# scripts/deploy_to_sentinel.py

import os
import json
import yaml
import requests
from pathlib import Path
from datetime import datetime

# Config
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")
WORKSPACE_NAME = os.getenv("WORKSPACE_NAME")

# 🔧 CORRIGÉ : Suppression des espaces dans les URLs
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
API_URL = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/alertRules"

RULES_DIR = Path("rules")
LOG_FILE = Path("logs/deploy.log")

LOG_FILE.parent.mkdir(exist_ok=True)


def log_message(level, msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        print(f"{level}: {msg}")
        f.write(f"{datetime.utcnow().isoformat()} | {level}: {msg}\n")


def get_access_token():
    # 🔧 CORRIGÉ : Suppression des espaces dans le scope
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://management.azure.com/.default',
        'grant_type': 'client_credentials'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        r = requests.post(AUTH_URL, data=payload, headers=headers)
        r.raise_for_status()
        return r.json()['access_token']
    except Exception as e:
        log_message("ERROR", f"Auth failed: {e}")
        exit(1)


def deploy_rule(rule_data, token):
    rule_id = rule_data["id"]
    url = f"{API_URL}/{rule_id}?api-version=2023-02-01"

    # ✅ 1. Gravité
    severity_map = {
        "Low": "Low",
        "Medium": "Medium",
        "High": "High",
        "Critical": "Critical",
        "Warning": "Medium"
    }
    severity = severity_map.get(rule_data.get("severity", "Medium").capitalize(), "Medium")

    # ✅ 2. Tactiques
    MITRE_TACTIC_MAP = {
        "initial-access": "InitialAccess",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "PrivilegeEscalation",
        "defense-evasion": "DefenseEvasion",
        "credential-access": "CredentialAccess",
        "discovery": "Discovery",
        "lateral-movement": "LateralMovement",
        "collection": "Collection",
        "command-and-control": "CommandAndControl",
        "exfiltration": "Exfiltration",
        "impact": "Impact"
    }
    tactics = [
        MITRE_TACTIC_MAP.get(t.lower().replace('_', '-'), t.capitalize())
        for t in rule_data.get("tactics", [])
    ]

    # ✅ 3. Techniques
    techniques = [
        tech.split('.')[-1] if '.' in tech else tech
        for tech in rule_data.get("techniques", [])
    ]

    # ✅ 4. Headers
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # ✅ 5. Payload
    payload = {
        "etag": "*",
        "kind": "Scheduled",
        "properties": {
            "displayName": rule_data["name"],
            "description": rule_data["description"],
            "severity": severity,
            "enabled": rule_data.get("status", "test") == "active",
            "query": rule_data["query"],
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": tactics,
            "techniques": techniques,
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT1H",
                    "matchingMethod": "AllEntities"
                }
            },
            "alertRuleTemplateName": None,
            "customDetails": None,
            "entityMappings": [
                {
                    "entityType": "Host",
                    "fieldMappings": [{"identifier": "FullName", "columnName": "Computer"}]
                },
                {
                    "entityType": "Account",
                    "fieldMappings": [{"identifier": "FullName", "columnName": "AccountName"}]
                }
            ]
        }
    }

    try:
        r = requests.put(url, json=payload, headers=headers)
        if r.status_code in [200, 201]:
            log_message("SUCCESS", f"{rule_id} déployée/mise à jour")
        else:
            log_message("ERROR", f"{rule_id} échec [{r.status_code}]: {r.text}")
    except Exception as e:
        log_message("ERROR", f"{rule_id} exception: {e}")


def main():
    token = get_access_token()
    rules_files = list(RULES_DIR.glob("*.yml"))

    for file in rules_files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)

            log_message("INFO", f"Déploiement: {rule['id']} - {rule['name']}")
            deploy_rule(rule, token)

        except Exception as e:
            log_message("ERROR", f"Échec lecture {file}: {e}")


if __name__ == "__main__":
    main()