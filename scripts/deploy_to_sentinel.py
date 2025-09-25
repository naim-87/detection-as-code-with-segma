#!/usr/bin/env python3
# scripts/deploy_to_sentinel.py

import os
import json
import yaml
import requests
import re
from pathlib import Path
from datetime import datetime

# === Configuration from environment variables ===
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")
WORKSPACE_NAME = os.getenv("WORKSPACE_NAME")

# 🔧 CORRIGÉ : Suppression des espaces autour des variables
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
API_URL = (f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
           f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights"
           f"/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/alertRules")

RULES_DIR = Path("rules")
LOG_FILE = Path("logs/deploy.log")
LOG_FILE.parent.mkdir(exist_ok=True)


def log_message(level, msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        line = f"{datetime.utcnow().isoformat()} | {level}: {msg}"
        print(line)
        f.write(line + "\n")


# === Normalization helpers ===
ALLOWED_SEVERITIES = {"High", "Medium", "Low", "Informational"}
ALLOWED_TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "Exfiltration", "CommandAndControl", "Impact", "PreAttack",
    "ImpairProcessControl", "InhibitResponseFunction"
}

ATTACK_PREFIX_RE = re.compile(r"(?i)ATTACK\.?\.?T?(\d{4})(?:\.\d+)?")
T_FULL_RE = re.compile(r"T(\d{4})(?:\.\d+)?")


def normalize_severity(raw):
    if not raw:
        return "Informational"
    s = str(raw).strip()
    mapping = {
        "critical": "High", "warn": "Informational", "warning": "Informational",
        "info": "Informational", "information": "Informational", "informational": "Informational"
    }
    s_lower = s.lower()
    if s_lower in mapping:
        return mapping[s_lower]
    for allowed in ALLOWED_SEVERITIES:
        if s_lower == allowed.lower():
            return allowed
    return "Informational"


def normalize_tactic(t):
    if not t:
        return None
    token = re.sub(r'[^0-9A-Za-z]', ' ', str(t)).strip()
    parts = [p.capitalize() for p in token.split() if p]
    candidate = "".join(parts)
    if candidate in ALLOWED_TACTICS:
        return candidate
    for cand in ALLOWED_TACTICS:
        if cand.lower() == str(t).strip().lower().replace('-', '').replace('_', ''):
            return cand
    return None


def normalize_technique(tech):
    if not tech:
        return None
    txt = str(tech).strip()
    m = T_FULL_RE.search(txt)
    if m:
        return "T" + m.group(1)
    m2 = ATTACK_PREFIX_RE.search(txt)
    if m2:
        return "T" + m2.group(1)
    return None


def ensure_entity_mappings(entity_mappings, rule_query=None):
    """
    Assure que entityMappings contient 1 à 5 éléments avec des identifiants valides.
    Corrige les erreurs courantes (ex: hostName → HostName, accountName → Name).
    """
    # Identifiants valides selon l'API Sentinel
    VALID_HOST_IDENTIFIERS = {
        "DnsDomain", "NTDomain", "HostName", "NetBiosName",
        "AzureID", "OMSAgentID", "OSFamily", "OSVersion",
        "IsDomainJoined", "FullName"
    }
    VALID_ACCOUNT_IDENTIFIERS = {
        "Name", "NTDomain", "DnsDomain", "UPNSuffix", "Sid",
        "AadTenantId", "AadUserId", "PUID", "IsDomainJoined",
        "DisplayName", "ObjectGuid", "CloudAppAccountId",
        "IsAnonymized", "FullName"
    }

    # === Étape 1 : Valider et corriger les mappings existants ===
    if entity_mappings and isinstance(entity_mappings, list):
        fixed_mappings = []
        for em in entity_mappings:
            if not isinstance(em, dict):
                continue
            etype = em.get("entityType")
            field_mappings = em.get("fieldMappings", [])

            # Correction pour Host
            if etype == "Host":
                for fm in field_mappings:
                    ident = fm.get("identifier")
                    if ident and ident.lower() == "hostname":
                        fm["identifier"] = "HostName"
                    elif ident and ident not in VALID_HOST_IDENTIFIERS:
                        fm["identifier"] = "HostName"

            # Correction pour Account
            elif etype == "Account":
                for fm in field_mappings:
                    ident = fm.get("identifier")
                    if ident and ident.lower() in ("accountname", "username", "fullname"):
                        fm["identifier"] = "Name"
                    elif ident and ident not in VALID_ACCOUNT_IDENTIFIERS:
                        fm["identifier"] = "Name"

            fixed_mappings.append(em)

        # Retourner seulement s’il y a au moins 1 mapping valide
        if fixed_mappings:
            return fixed_mappings[:5]  # Max 5

    # === Étape 2 : Création automatique si vide ou invalide ===
    placeholder = []
    q = (rule_query or "").lower()

    # Détecter Computer / Host
    if any(kw in q for kw in ["computer", "hostname", "devicename", "machinename"]):
        placeholder.append({
            "entityType": "Host",
            "fieldMappings": [
                {"identifier": "HostName", "columnName": "Computer"}
            ]
        })

    # Détecter Account / User
    if any(kw in q for kw in ["accountname", "username", "user", "logonuser"]):
        placeholder.append({
            "entityType": "Account",
            "fieldMappings": [
                {"identifier": "Name", "columnName": "AccountName"}
            ]
        })

    # Détecter IP
    if any(kw in q for kw in ["srcip", "dstip", "sourceip", "clientip", "remoteip"]):
        placeholder.append({
            "entityType": "IP",
            "fieldMappings": [
                {"identifier": "Address", "columnName": "IpAddress"}
            ]
        })

    # Fallback minimal obligatoire
    if not placeholder:
        log_message("WARNING", "No entityMappings found; adding minimal placeholder.")
        placeholder = [{
            "entityType": "Host",
            "fieldMappings": [
                {"identifier": "HostName", "columnName": "Computer"}
            ]
        }]

    return placeholder[:5]


# === Auth & Deployment ===
def get_access_token():
    # 🔧 CORRIGÉ : Suppression des espaces dans le scope
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://management.azure.com/.default',  # ✅ Sans espaces
        'grant_type': 'client_credentials'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        r = requests.post(AUTH_URL, data=payload, headers=headers)
        r.raise_for_status()
        return r.json()['access_token']
    except Exception as e:
        log_message("ERROR", f"Auth failed: {e}")
        raise SystemExit(1)


def deploy_rule(rule_data, token):
    rule_id = rule_data.get("id") or rule_data.get("name")
    if not rule_id:
        log_message("ERROR", "Skipping rule with no id/name")
        return

    url = f"{API_URL}/{rule_id}?api-version=2023-02-01"

    severity = normalize_severity(rule_data.get("severity"))
    raw_tactics = rule_data.get("tactics") or []
    tactics = [normalize_tactic(t) for t in raw_tactics if normalize_tactic(t)]
    raw_techs = rule_data.get("techniques") or []
    techniques = [normalize_technique(t) for t in raw_techs if normalize_technique(t)]
    em_final = ensure_entity_mappings(rule_data.get("entityMappings"), rule_data.get("query"))

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "etag": "*",
        "kind": "Scheduled",
        "properties": {
            "displayName": rule_data.get("name"),
            "description": rule_data.get("description", ""),
            "severity": severity,
            "enabled": rule_data.get("status", "test") == "active",
            "query": rule_data.get("query", ""),
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
            "entityMappings": em_final
        }
    }

    # Validation finale avant envoi
    if severity not in ALLOWED_SEVERITIES:
        log_message("ERROR", f"{rule_id} -> invalid severity: {severity}")
        return
    if not (1 <= len(em_final) <= 5):
        log_message("ERROR", f"{rule_id} -> entityMappings length invalid: {len(em_final)}")
        return

    try:
        r = requests.put(url, json=payload, headers=headers)
        if r.status_code in (200, 201):
            log_message("SUCCESS", f"{rule_id} déployée/mise à jour")
        else:
            log_message("ERROR", f"{rule_id} échec [{r.status_code}]: {r.text}")
    except Exception as e:
        log_message("ERROR", f"{rule_id} exception: {e}")


def main():
    # Vérifie que toutes les variables sont définies
    required_env = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
                    "SUBSCRIPTION_ID", "RESOURCE_GROUP", "WORKSPACE_NAME"]
    missing = [var for var in required_env if not os.getenv(var)]
    if missing:
        log_message("ERROR", f"Variables manquantes: {missing}")
        exit(1)

    token = get_access_token()
    rules_files = list(RULES_DIR.glob("*.yml"))

    for file in rules_files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            log_message("INFO", f"Déploiement: {rule.get('id')} - {rule.get('name')}")
            deploy_rule(rule, token)
        except Exception as e:
            log_message("ERROR", f"Échec lecture {file}: {e}")


if __name__ == "__main__":
    main()