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

# Directories
SIGMA_DIR = Path("sigma-rules")
DAAC_DIR = Path("rules")
SCHEMA_PATH = Path("schemas/rule-schema.json")
LOG_FILE = Path("logs/conversion.log")

DAAC_DIR.mkdir(exist_ok=True)
LOG_FILE.parent.mkdir(exist_ok=True)

# Mapping des catégories Sigma → Tables ASIM/Sentinel
CATEGORY_TO_TABLE = {
    "process_creation": "imProcessCreate",
    "image_load": "imImageLoad",
    "registry_add": "imRegistry",
    "registry_delete": "imRegistry",
    "registry_event": "imRegistry",
    "file_create": "imFileEvent",
    "file_delete": "imFileEvent",
    "file_access": "imFileEvent",
    "network_connection": "imNetworkConnection",
    "dns_query": "imDnsEvents",
    "driver_load": "imDriverLoad",
    "logon_logoff": "imLogon",
    "authentication": "imLogon",
}

# Mapping des tables ASIM → Tables Sentinel réelles
ASIM_TO_SENTINEL_TABLE = {
    "imProcessCreate": "DeviceProcessEvents",
    "imRegistry": "DeviceRegistryEvents",
    "imNetworkConnection": "DeviceNetworkEvents",
    "imDnsEvents": "DeviceDnsEvents",
    "imFileEvent": "DeviceFileEvents",
    "imImageLoad": "DeviceImageLoadEvents",
    "imLogon": "DeviceLogonEvents",
    "imDriverLoad": "DeviceImageLoadEvents",
}

# Champs valides par table (pour validation/correction)
VALID_FIELDS = {
    "imProcessCreate": [
        "ActingProcessCommandLine", "ActingProcessCreationTime", "ActingProcessFileCompany",
        "ActingProcessFileDescription", "ActingProcessFileInternalName",
        "ActingProcessFileOriginalName", "ActingProcessFileProduct", "ActingProcessFileSize",
        "ActingProcessFileVersion", "ActingProcessGuid", "ActingProcessIMPHASH",
        "ActingProcessId", "ActingProcessInjectedAddress", "ActingProcessIntegrityLevel",
        "ActingProcessIsHidden", "ActingProcessMD5", "ActingProcessName",
        "ActingProcessSHA1", "ActingProcessSHA256", "ActingProcessSHA512",
        "ActingProcessTokenElevation", "InitiatingProcessCommandLine", "DeviceName",
        "ProcessCommandLine", "FileName", "FolderPath"
    ],
    "imRegistry": [
        "RegistryKey", "RegistryValueName", "RegistryValueData", "RegistryValueType",
        "DeviceName", "ActorUsername", "ActorUserId", "AccountName", "RemoteIP"
    ],
    # Ajoute d'autres si nécessaire
}

# Mapping des champs Sigma → ASIM (KQL) - utilisé après génération
FIELD_MAPPING = {
    "Image": "FileName",
    "CommandLine": "ProcessCommandLine",
    "CurrentDirectory": "FolderPath",
    "ParentCommandLine": "InitiatingProcessCommandLine",
    "ParentImage": "InitiatingProcessFolderPath",
    "ParentProcessName": "InitiatingProcessFileName",
    "CreatorProcessName": "InitiatingProcessFileName",
    "Hashes": "SHA1",
    "TargetObject": "RegistryKey",
    "Details": "RegistryValueData",
    "NewName": "RegistryValueName",
    "EventType": "RegistryOperation",
    "TargetFilename": "FileName",
    "FilePath": "FolderPath",
    "SubjectUserName": "AccountName",
    "IpAddress": "RemoteIP",
    "Data": "CommandLine",
    "IntegrityLevel": "ProcessIntegrityLevel",
}


def log_conversion(message: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {message}\n")


def load_schema():
    if not SCHEMA_PATH.exists():
        print(f"❌ Schema file not found: {SCHEMA_PATH}")
        sys.exit(1)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_rule(rule: dict, rule_name: str, schema: dict) -> bool:
    try:
        validate(instance=rule, schema=schema)
        print(f"✅ {rule_name} est valide selon le schéma")
        return True
    except Exception as e:
        print(f"❌ Erreur de validation {rule_name}: {e}")
        log_conversion(f"ERROR: Validation {rule_name} → {str(e)}")
        return False


def generate_daac_id(sigma_id: str, source: str = "sigma") -> str:
    digits = re.sub(r"\D", "", sigma_id or "")
    if len(digits) >= 7:
        prefix = int(digits[:4]) % 10000
        suffix = int(digits[4:7]) % 1000
        return f"SIGMA-{prefix:04d}-{suffix:03d}"
    base = abs(hash(sigma_id or str(uuid.uuid4()))) % 1000
    year = datetime.now().year % 10000
    return f"SIGMA-{year:04d}-{base:03d}"


def correct_invalid_fields(detection_item: dict, table_type: str) -> dict:
    """
    Remplace les champs non valides par un champ générique valide.
    Ex: champ inconnu → ProcessCommandLine (selon table)
    """
    valid_fields = VALID_FIELDS.get(table_type, [])
    if not valid_fields:
        return detection_item

    def recursive_fix(obj):
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if key == "field" and isinstance(obj[key], str):
                    field = obj[key]
                    if field not in valid_fields:
                        # Remplacer par un champ générique pertinent
                        if table_type == "imProcessCreate":
                            print(f"🔧 [CORRECT] Champ invalide '{field}' → 'ProcessCommandLine'")
                            obj["field"] = "ProcessCommandLine"
                        elif table_type == "imRegistry":
                            print(f"🔧 [CORRECT] Champ invalide '{field}' → 'RegistryKey'")
                            obj["field"] = "RegistryKey"
                else:
                    recursive_fix(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                recursive_fix(item)

    recursive_fix(detection_item)
    return detection_item


def convert_sigma_file(sigma_path: Path, schema: dict):
    try:
        with open(sigma_path, 'r', encoding='utf-8') as f:
            sigma_data = yaml.safe_load(f)

        if not sigma_data:
            raise ValueError("Fichier YAML vide ou invalide")

        log_conversion(f"PROCESSING: {sigma_path.name}")

        # === Étape 1 : Déterminer la table cible à partir de la catégorie ===
        category = sigma_data.get("logsource", {}).get("category")
        table_type = CATEGORY_TO_TABLE.get(category)
        if not table_type:
            print(f"⚠️ Catégorie inconnue: {category}, on suppose imProcessCreate")
            table_type = "imProcessCreate"

        # === Étape 2 : Corriger les champs invalides AVANT conversion ===
        if "detection" in sigma_data:
            sigma_data["detection"] = correct_invalid_fields(sigma_data["detection"], table_type)

        # === Étape 3 : Corriger le nom de la catégorie si besoin ===
        if "logsource" in sigma_data and category in CATEGORY_TO_TABLE:
            sigma_data["logsource"]["category"] = table_type

        # === Étape 4 : Générer un ID valide ===
        if not re.match(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", sigma_data.get("id", "")):
            old_id = sigma_data.get("id", "unknown")
            sigma_data["id"] = str(uuid.uuid4())
            print(f"🔁 ID généré: {old_id} → {sigma_data['id']}")

        rule_title = sigma_data.get("title", sigma_path.stem)

        # === Étape 5 : Convertir en collection Sigma ===
        try:
            sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
        except Exception as e:
            if "must be an UUID" in str(e):
                sigma_data["id"] = str(uuid.uuid4())
                sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
            else:
                raise

        # === Étape 6 : Générer la requête KQL ===
        backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline())
        kql_queries = backend.convert(sigma_collection)
        if not kql_queries:
            raise ValueError("Aucune requête KQL générée")
        kql_query = kql_queries[0]

        # === Étape 7 : Appliquer FIELD_MAPPING (champs) ===
        for sigma_field, asim_field in FIELD_MAPPING.items():
            kql_query = re.sub(rf'\b{re.escape(sigma_field)}\b', asim_field, kql_query)

        # === Étape 8 : Remplacer Im_ → _Im_ (si nécessaire) ===
        kql_query = re.sub(r'\b(Im_[A-Za-z_]+)\b', r'_\1', kql_query)

        # === Étape 9 : Remplacer les tables ASIM partout (même entre quotes) ===
        real_table = ASIM_TO_SENTINEL_TABLE.get(table_type, "DeviceProcessEvents")
        kql_query = re.sub(rf'\b{re.escape(table_type)}\b', real_table, kql_query)
        kql_query = re.sub(rf"'{re.escape(table_type)}'", f"'{real_table}'", kql_query)
        kql_query = re.sub(rf'"{re.escape(table_type)}"', f'"{real_table}"', kql_query)

        # Nettoyer les guillemets simples autour de la requête si présents
        kql_query = re.sub(r"^'\s*", "", kql_query.strip())
        kql_query = re.sub(r"\s*'$", "", kql_query)
        kql_query = re.sub(r'^"\s*', "", kql_query)
        kql_query = re.sub(r'\s*"$', "", kql_query)

        # === Étape 10 : Extraire MITRE ===
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

        # === Étape 11 : Générer l'ID DaaC ===
        daac_id = generate_daac_id(sigma_data["id"])

        # === Étape 12 : Créer la règle DaaC ===
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

        # === Étape 13 : Valider le schéma ===
        if not validate_rule(daac_rule, sigma_path.name, schema):
            log_conversion(f"VALIDATION_FAILED: {sigma_path.name}")
            return

        # === Étape 14 : Sauvegarder ===
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
        print(f"❌ Directory not found: {SIGMA_DIR}")
        sys.exit(1)
    if not SCHEMA_PATH.exists():
        print(f"❌ Schema not found: {SCHEMA_PATH}")
        sys.exit(1)

    schema = load_schema()
    sigma_files = list(SIGMA_DIR.glob("*.yml"))

    if not sigma_files:
        print("📭 No .yml files found in sigma-rules/")
        return

    print(f"🔍 Found {len(sigma_files)} Sigma rules. Starting conversion...\n")
    for file in sigma_files:
        convert_sigma_file(file, schema)

    print(f"\n🎉 Conversion completed. Check logs: {LOG_FILE}")


if __name__ == "__main__":
    main()