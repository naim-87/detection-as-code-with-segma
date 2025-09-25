#!/usr/bin/env python3
# scripts/convert_sigma_to_daac.py

import yaml
import json
import sys
import re
import uuid
from pathlib import Path
from datetime import datetime
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from jsonschema import validate

# === Répertoires ===
SIGMA_DIR = Path("sigma-rules")
DAAC_DIR = Path("rules")
SCHEMA_PATH = Path("schemas/rule-schema.json")
LOG_FILE = Path("logs/conversion.log")

DAAC_DIR.mkdir(exist_ok=True)
LOG_FILE.parent.mkdir(exist_ok=True)

# === Mapping : Catégorie Sigma → Table Sentinel Native ===
CATEGORY_TO_SENTINEL_TABLE = {
    "process_creation": "DeviceProcessEvents",
    "image_load": "DeviceImageLoadEvents",
    "registry_add": "DeviceRegistryEvents",
    "registry_delete": "DeviceRegistryEvents",
    "registry_event": "DeviceRegistryEvents",
    "file_create": "DeviceFileEvents",
    "file_delete": "DeviceFileEvents",
    "file_access": "DeviceFileEvents",
    "network_connection": "DeviceNetworkEvents",
    "dns_query": "DeviceDnsEvents",
    "driver_load": "DeviceImageLoadEvents",  # Driver load souvent loggé via ImageLoad
    "logon": "DeviceLogonEvents",
    "authentication": "DeviceLogonEvents",
    "ps_script": "DeviceProcessEvents",      # PowerShell = process
    "ps_classic_start": "DeviceProcessEvents",
}

# === Mapping : Champs Sigma → Champs Sentinel (tables natives) ===
FIELD_TO_SENTINEL_FIELD = {
    # --- Processus ---
    "Image": "FileName",
    "CommandLine": "ProcessCommandLine",
    "CurrentDirectory": "FolderPath",
    "ParentImage": "InitiatingProcessFolderPath",
    "ParentCommandLine": "InitiatingProcessCommandLine",
    "ParentProcessName": "InitiatingProcessFileName",
    "CreatorProcessName": "InitiatingProcessFileName",
    "Hashes": "SHA1",  # ou MD5/SHA256 selon contexte
    "NewProcessName": "FileName",

    # --- Fichiers ---
    "TargetFilename": "FileName",
    "FilePath": "FolderPath",
    "FileExtension": "FileExtension",

    # --- Registre ---
    "TargetObject": "RegistryKey",
    "Details": "RegistryValueData",
    "NewName": "RegistryValueName",
    "EventType": "RegistryOperation",

    # --- DNS ---
    "QueryName": "DnsQuery",
    "QueryResults": "DnsResponse",

    # --- Réseau ---
    "DestinationIp": "RemoteIP",
    "DestinationPort": "RemotePort",
    "SourceIp": "LocalIP",
    "SourcePort": "LocalPort",
    "Protocol": "Protocol",

    # --- Authentification / Session ---
    "SubjectUserName": "AccountName",
    "SubjectUserSid": "AccountSid",
    "TargetUserName": "AccountName",
    "TargetUserSid": "AccountSid",
    "TargetDomainName": "DomainName",
    "IpAddress": "RemoteIP",
    "LogonType": "LogonType",
    "AuthenticationPackageName": "AuthenticationPackage",

    # --- Pilotes / Modules ---
    "LoadedImage": "FileName",
    "Signature": "Signer",

    # --- Divers ---
    "Data": "CommandLine",
    "IntegrityLevel": "ProcessIntegrityLevel",
}

# === Liste des champs valides par table (pour validation/correction) ===
VALID_FIELDS_BY_TABLE = {
    "DeviceProcessEvents": [
        "TimeGenerated", "DeviceName", "FileName", "ProcessCommandLine",
        "FolderPath", "InitiatingProcessFileName", "InitiatingProcessCommandLine",
        "InitiatingProcessFolderPath", "ProcessId", "UserId", "UserDomain",
        "ProcessVersionInfoOriginalFileName", "SHA1", "MD5", "SHA256",
        "ProcessIntegrityLevel", "AccountName"
    ],
    "DeviceRegistryEvents": [
        "TimeGenerated", "DeviceName", "RegistryKey", "RegistryValueName",
        "RegistryValueData", "RegistryOperation", "AccountId", "AccountName"
    ],
    "DeviceFileEvents": [
        "TimeGenerated", "DeviceName", "FileName", "FolderPath", "FileSize",
        "ActionType", "PreviousFileSize"
    ],
    "DeviceNetworkEvents": [
        "TimeGenerated", "DeviceName", "RemoteIP", "RemotePort", "LocalIP",
        "LocalPort", "Protocol", "InitiatingProcessFileName"
    ],
    "DeviceDnsEvents": [
        "TimeGenerated", "DeviceName", "DnsQuery", "DnsResponse", "ResultCode"
    ],
    "DeviceImageLoadEvents": [
        "TimeGenerated", "DeviceName", "FileName", "FolderPath", "Signer",
        "Imphash", "MD5", "SHA1", "SHA256"
    ],
    "DeviceLogonEvents": [
        "TimeGenerated", "DeviceName", "AccountName", "AccountSid", "DomainName",
        "LogonType", "AuthenticationPackage", "RemoteIP"
    ],
}


def log_conversion(message: str):
    """Écrit dans le fichier de log."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {message}\n")


def load_schema():
    """Charge le schéma JSON."""
    if not SCHEMA_PATH.exists():
        print(f"❌ Schema non trouvé : {SCHEMA_PATH}")
        sys.exit(1)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_rule(rule: dict, rule_name: str, schema: dict) -> bool:
    """Valide la règle contre le schéma JSON."""
    try:
        validate(instance=rule, schema=schema)
        print(f"✅ {rule_name} : valide")
        return True
    except Exception as e:
        print(f"❌ {rule_name} : erreur → {str(e)}")
        log_conversion(f"VALIDATION_ERROR: {rule_name} → {str(e)}")
        return False


def generate_daac_id(sigma_id: str) -> str:
    """Génère un ID DaaC formaté SIGMA-YYYY-XXX"""
    digits = re.sub(r"\D", "", sigma_id or "")
    if len(digits) >= 7:
        prefix = int(digits[:4]) % 10000
        suffix = int(digits[4:7]) % 1000
        return f"SIGMA-{prefix:04d}-{suffix:03d}"
    base = abs(hash(sigma_id or str(uuid.uuid4()))) % 1000
    year = datetime.now().year % 10000
    return f"SIGMA-{year:04d}-{base:03d}"


def correct_invalid_fields(detection: dict, table: str):
    """Remplace les champs non valides par des équivalents pertinents."""
    valid_fields = VALID_FIELDS_BY_TABLE.get(table, [])
    if not valid_fields:
        return detection

    def fix(obj):
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if key == "field" and isinstance(obj[key], str):
                    field = obj[key]
                    if field not in valid_fields:
                        # Remplacement intelligent
                        if "Command" in field or "Line" in field:
                            obj["field"] = "ProcessCommandLine"
                        elif "Image" in field or "File" in field:
                            obj["field"] = "FileName"
                        elif "Registry" in field or "Key" in field:
                            obj["field"] = "RegistryKey"
                        elif "IP" in field:
                            obj["field"] = "RemoteIP"
                        else:
                            obj["field"] = valid_fields[0]  # fallback
                        print(f"🔧 [CORRIGÉ] Champ invalide '{field}' → '{obj['field']}' ({table})")
                else:
                    fix(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                fix(item)

    fix(detection)
    return detection


def convert_sigma_file(sigma_path: Path, schema: dict):
    try:
        with open(sigma_path, 'r', encoding='utf-8') as f:
            sigma_data = yaml.safe_load(f)

        if not sigma_data:
            raise ValueError("Fichier vide ou invalide")

        log_conversion(f"CONVERTING: {sigma_path.name}")

        # === 1. Déterminer la table cible à partir de la catégorie ===
        category = sigma_data.get("logsource", {}).get("category")
        sentinel_table = CATEGORY_TO_SENTINEL_TABLE.get(category)
        if not sentinel_table:
            print(f"⚠️ Catégorie inconnue: {category}, on utilise DeviceProcessEvents par défaut")
            sentinel_table = "DeviceProcessEvents"

        # === 2. Corriger les champs invalides AVANT conversion ===
        if "detection" in sigma_data:
            sigma_data["detection"] = correct_invalid_fields(sigma_data["detection"], sentinel_table)

        # === 3. Générer ou corriger l'ID ===
        if not re.match(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", sigma_data.get("id", "")):
            old_id = sigma_data.get("id", "missing")
            sigma_data["id"] = str(uuid.uuid4())
            print(f"🔁 ID généré: {old_id} → {sigma_data['id']}")

        rule_title = sigma_data.get("title", sigma_path.stem)

        # === 4. Charger la collection Sigma ===
        try:
            sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
        except Exception as e:
            if "must be an UUID" in str(e):
                sigma_data["id"] = str(uuid.uuid4())
                sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
            else:
                raise

        # === 5. Générer la requête KQL via ASIM pipeline ===
        backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline())
        kql_queries = backend.convert(sigma_collection)
        if not kql_queries:
            raise ValueError("Aucune requête générée")
        kql_query = kql_queries[0]

        # === 6. Appliquer le mapping des champs Sigma → Sentinel ===
        for sigma_field, sentinel_field in FIELD_TO_SENTINEL_FIELD.items():
            kql_query = re.sub(rf'\b{re.escape(sigma_field)}\b', sentinel_field, kql_query)

        # === 7. Remplacer les tables im* par leurs équivalents natifs (même entre quotes) ===
        kql_query = re.sub(rf'\bim[A-Za-z]+\b', sentinel_table, kql_query)
        kql_query = re.sub(rf"'im[A-Za-z]+'", f"'{sentinel_table}'", kql_query)
        kql_query = re.sub(rf'"im[A-Za-z]+"', f'"{sentinel_table}"', kql_query)

        # Nettoyer les guillemets simples autour si présents
        kql_query = kql_query.strip().strip("'\"")

        # === 8. Extraire MITRE ATT&CK ===
        tactics, techniques, tags = [], [], []
        for tag in sigma_data.get("tags", []):
            t_upper = tag.upper()
            if re.match(r"^ATTACK\.T[0-9]{4}(\.[0-9]{3})?$", t_upper):
                techniques.append(t_upper)
            elif t_upper.startswith("ATTACK."):
                tactic = tag.split(".")[-1].lower()
                if tactic not in tactics:
                    tactics.append(tactic)
            else:
                tags.append(tag)

        # === 9. Générer l'ID DaaC ===
        daac_id = generate_daac_id(sigma_data["id"])

        # === 10. Créer la règle DaaC ===
        daac_rule = {
            "id": daac_id,
            "name": rule_title,
            "description": sigma_data.get("description", "No description"),
            "tactics": sorted(set(tactics)),
            "techniques": sorted(set(techniques)),
            "severity": sigma_data.get("level", "medium").capitalize(),
            "query": kql_query.strip(),
            "status": "test",
            "version": 1.0,
            "clients": ["*"],
            "tags": tags,
            "author": sigma_data.get("author", "community"),
            "last_modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        }

        # === 11. Validation du schéma ===
        if not validate_rule(daac_rule, sigma_path.name, schema):
            return

        # === 12. Sauvegarder ===
        output_file = DAAC_DIR / f"{daac_id}.yml"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"# source: {sigma_path.name}\n")
            yaml.dump(daac_rule, f, sort_keys=False, indent=2, allow_unicode=True)

        log_conversion(f"SUCCESS: {sigma_path.name} → {output_file.name}")
        print(f"✅ Converti: {sigma_path.name} → {output_file.name}")

    except Exception as e:
        error_msg = f"FAILED: {sigma_path.name} → {str(e)}"
        log_conversion(f"ERROR: {error_msg}")
        print(f"❌ {error_msg}")


def main():
    if not SIGMA_DIR.exists():
        print(f"❌ Dossier introuvable : {SIGMA_DIR}")
        sys.exit(1)
    if not SCHEMA_PATH.exists():
        print(f"❌ Schéma introuvable : {SCHEMA_PATH}")
        sys.exit(1)

    schema = load_schema()
    sigma_files = list(SIGMA_DIR.glob("*.yml"))

    if not sigma_files:
        print("📭 Aucun fichier .yml trouvé dans sigma-rules/")
        return

    print(f"🔍 {len(sigma_files)} règles Sigma trouvées. Démarrage de la conversion...\n")
    for file in sigma_files:
        convert_sigma_file(file, schema)

    print(f"\n🎉 Conversion terminée. Journal : {LOG_FILE}")


if __name__ == "__main__":
    main()