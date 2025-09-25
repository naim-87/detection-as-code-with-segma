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

# === Mapping : Catégorie Sigma → Table ASIM (officielle) ===
CATEGORY_TO_ASIM_TABLE = {
    "process_creation": "imProcessCreate",
    "process_termination": "imProcessTerminate",
    "image_load": "_Im_ImageLoad",           # ou imImageLoad selon pipeline
    "registry_add": "imRegistry",
    "registry_delete": "imRegistry",
    "registry_event": "imRegistry",
    "file_create": "imFileEvent",
    "file_delete": "imFileEvent",
    "file_access": "imFileEvent",
    "network_connection": "_Im_NetworkSession",
    "dns_query": "_Im_Dns",
    "driver_load": "_Im_Driver",
    "authentication": "imAuthentication",
    "logon": "imAuthentication",  # souvent fusionné
    "audit_event": "_Im_AuditEvent",
    "web_session": "_Im_WebSession",
    "ps_script": "imProcessCreate",
    "ps_classic_start": "imProcessCreate",
    "ps_module_load": "_Im_ImageLoad",
}

# === Mapping : Table ASIM → Table Sentinel Native ===
ASIM_TO_SENTINEL_TABLE = {
    "imProcessCreate": "DeviceProcessEvents",
    "imProcessTerminate": "DeviceProcessEvents",
    "_Im_ImageLoad": "DeviceImageLoadEvents",
    "imImageLoad": "DeviceImageLoadEvents",
    "imRegistry": "DeviceRegistryEvents",
    "imFileEvent": "DeviceFileEvents",
    "_Im_NetworkSession": "DeviceNetworkEvents",
    "_Im_Dns": "DeviceDnsEvents",
    "_Im_Driver": "DeviceImageLoadEvents",
    "imAuthentication": "DeviceLogonEvents",
    "_Im_AuditEvent": "SecurityEvent",  # ou Custom Logs
    "_Im_WebSession": "WebAppLogs",     # ex: Azure App Service
}

# === Mapping : Champs Sigma → Champs ASIM/Sentinel ===
FIELD_TO_ASIM_FIELD = {
    # --- Processus ---
    "Image": "FileName",
    "CommandLine": "ProcessCommandLine",
    "CurrentDirectory": "FolderPath",
    "ParentImage": "InitiatingProcessFolderPath",
    "ParentCommandLine": "InitiatingProcessCommandLine",
    "ParentProcessName": "InitiatingProcessFileName",
    "CreatorProcessName": "InitiatingProcessFileName",
    "Hashes": "SHA1",

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

    # --- Authentification ---
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


def log_conversion(message: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {message}\n")


def load_schema():
    if not SCHEMA_PATH.exists():
        print(f"❌ Schema non trouvé : {SCHEMA_PATH}")
        sys.exit(1)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_rule(rule: dict, rule_name: str, schema: dict) -> bool:
    try:
        validate(instance=rule, schema=schema)
        print(f"✅ {rule_name} : valide")
        return True
    except Exception as e:
        print(f"❌ {rule_name} : erreur → {str(e)}")
        log_conversion(f"VALIDATION_ERROR: {rule_name} → {str(e)}")
        return False


def generate_daac_id(sigma_id: str) -> str:
    digits = re.sub(r"\D", "", sigma_id or "")
    if len(digits) >= 7:
        prefix = int(digits[:4]) % 10000
        suffix = int(digits[4:7]) % 1000
        return f"SIGMA-{prefix:04d}-{suffix:03d}"
    base = abs(hash(sigma_id or str(uuid.uuid4()))) % 1000
    year = datetime.now().year % 10000
    return f"SIGMA-{year:04d}-{base:03d}"


def convert_sigma_file(sigma_path: Path, schema: dict):
    try:
        with open(sigma_path, 'r', encoding='utf-8') as f:
            sigma_data = yaml.safe_load(f)

        if not sigma_data:
            raise ValueError("Fichier YAML vide ou invalide")

        log_conversion(f"CONVERTING: {sigma_path.name}")

        # === 1. Déterminer la catégorie et la table ASIM cible ===
        category = sigma_data.get("logsource", {}).get("category")
        asim_table = CATEGORY_TO_ASIM_TABLE.get(category)
        if not asim_table:
            print(f"⚠️ Catégorie inconnue: {category}, on utilise imProcessCreate par défaut")
            asim_table = "imProcessCreate"

        # Trouver la table Sentinel correspondante
        sentinel_table = ASIM_TO_SENTINEL_TABLE.get(asim_table, "DeviceProcessEvents")

        # === 2. Corriger l'ID si invalide ===
        if not re.match(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", sigma_data.get("id", "")):
            old_id = sigma_data.get("id", "missing")
            sigma_data["id"] = str(uuid.uuid4())
            print(f"🔁 ID généré: {old_id} → {sigma_data['id']}")

        rule_title = sigma_data.get("title", sigma_path.stem)

        # === 3. Charger la collection Sigma ===
        try:
            sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
        except Exception as e:
            if "must be an UUID" in str(e):
                sigma_data["id"] = str(uuid.uuid4())
                sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
            else:
                raise

        # === 4. Générer la requête KQL via le pipeline ASIM ===
        backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline())
        kql_queries = backend.convert(sigma_collection)
        if not kql_queries:
            raise ValueError("Aucune requête KQL générée")
        kql_query = kql_queries[0]

        # === 5. Appliquer le mapping des champs Sigma → ASIM ===
        for sigma_field, asim_field in FIELD_TO_ASIM_FIELD.items():
            kql_query = re.sub(rf'\b{re.escape(sigma_field)}\b', asim_field, kql_query)

        # === 6. Remplacer Im_Field → _Im_Field si nécessaire ===
        kql_query = re.sub(r'\b(Im_[A-Za-z_]+)\b', r'_\1', kql_query)

        # === 7. Remplacer la table ASIM par la table Sentinel (partout) ===
        kql_query = re.sub(rf'\b{re.escape(asim_table)}\b', sentinel_table, kql_query)
        kql_query = re.sub(rf"'{re.escape(asim_table)}'", f"'{sentinel_table}'", kql_query)
        kql_query = re.sub(rf'"{re.escape(asim_table)}"', f'"{sentinel_table}"', kql_query)

        # === 8. Nettoyer les guillemets entourant la requête ===
        kql_query = kql_query.strip()
        if kql_query.startswith(("'", '"')) and kql_query.endswith(("'", '"')):
            kql_query = kql_query[1:-1]

        # Corriger les guillemets impairs
        if kql_query.count('"') % 2 != 0 and kql_query.rstrip().endswith('"'):
            kql_query = kql_query.rstrip()[:-1]

        kql_query = re.sub(r' +', ' ', kql_query)  # espaces multiples

        # === 9. Extraire MITRE ATT&CK ===
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

        # === 10. Générer l'ID DaaC ===
        daac_id = generate_daac_id(sigma_data["id"])

        # === 11. Créer la règle DaaC ===
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

        # === 12. Validation du schéma ===
        if not validate_rule(daac_rule, sigma_path.name, schema):
            log_conversion(f"VALIDATION_FAILED: {sigma_path.name}")
            return

        # === 13. Sauvegarder ===
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