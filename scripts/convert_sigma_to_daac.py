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

# Mapping des catégories Sigma non standard → catégories standard
CATEGORY_MAPPING = {
    "ps_classic_start": "process_creation",
    "ps_module_load": "image_load",
    "ps_script": "process_creation",
    "registry_add": "registry_add",
    "registry_delete": "registry_add",
    "registry_event": "registry_add",
    "file_create": "file_event",
    "file_delete": "file_event",
    "file_access": "file_event",
    "network_connection": "network_connection",
    "dns_query": "dns_events",
    "driver_load": "driver_load",
    "authentication": "logon_logoff",
    "logon": "logon_logoff",
    "Data": "CommandLine",
}

# Mapping des champs Sigma → ASIM (KQL)
FIELD_MAPPING = {
    # --- Processus ---
    "Image": "FileName",
    "CommandLine": "ProcessCommandLine",
    "CurrentDirectory": "FolderPath",
    "ParentCommandLine": "InitiatingProcessCommandLine",
    "ParentImage": "InitiatingProcessFolderPath",
    "ParentProcessName": "InitiatingProcessFileName",
    "CreatorProcessName": "InitiatingProcessFileName",
    "Hashes": "SHA1",

    # --- Réseau ---
    "DestinationIp": "RemoteIP",
    "DestinationPort": "RemotePort",
    "SourceIp": "LocalIP",
    "SourcePort": "LocalPort",
    "Protocol": "Protocol",

    # --- DNS ---
    "QueryName": "DnsQuery",
    "QueryResults": "DnsResponse",

    # --- Registre ---
    "TargetObject": "RegistryKey",
    "Details": "RegistryValueData",
    "NewName": "RegistryValueName",
    "EventType": "RegistryOperation",

    # --- Fichiers ---
    "TargetFilename": "FileName",
    "FileName": "FileName",
    "FilePath": "FolderPath",
    "FileExtension": "FileExtension",

    # --- Authentification ---
    "SubjectUserName": "AccountName",
    "SubjectUserSid": "AccountSid",
    "TargetUserName": "AccountName",
    "TargetUserSid": "AccountSid",
    "TargetDomainName": "DomainName",
    "IpAddress": "RemoteIP",
    "LogonType": "LogonType",

    # --- Pilotes ---
    "LoadedImage": "FileName",
    "Signature": "Signer",

    # --- Divers ---
    "Data": "CommandLine",
    "IntegrityLevel": "ProcessIntegrityLevel",
}

# Mapping des tables ASIM → Tables Sentinel réelles
ASIM_TABLE_MAPPING = {
    "imProcessCreate": "DeviceProcessEvents",
    "imRegistry": "DeviceRegistryEvents",
    "imNetworkConnection": "DeviceNetworkEvents",
    "imDnsEvents": "DeviceDnsEvents",
    "imFileEvent": "DeviceFileEvents",
    "imImageLoad": "DeviceImageLoadEvents",
    "imLogon": "DeviceLogonEvents",
    "imDriverLoad": "DeviceImageLoadEvents",  # souvent intégré
}


def log_conversion(message: str):
    """Écrit un message dans le fichier de log avec horodatage."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {message}\n")


def load_schema():
    """Charge le schéma JSON pour validation des règles DaaC."""
    if not SCHEMA_PATH.exists():
        print(f"❌ Schema file not found: {SCHEMA_PATH}")
        sys.exit(1)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_rule(rule: dict, rule_name: str, schema: dict) -> bool:
    """Validation JSON Schema d'une règle DaaC"""
    try:
        validate(instance=rule, schema=schema)
        print(f"✅ {rule_name} est valide selon le schéma")
        return True
    except Exception as e:
        print(f"❌ Erreur de validation {rule_name}: {e}")
        log_conversion(f"ERROR: Validation {rule_name} → {str(e)}")
        return False


def generate_daac_id(sigma_id: str, source: str = "sigma") -> str:
    """Génère un ID DaaC formaté : SIGMA-YYYY-XXX"""
    if source == "sigma" and sigma_id:
        digits = re.sub(r"\D", "", sigma_id)
        if len(digits) >= 7:
            prefix = int(digits[:4]) % 10000
            suffix = int(digits[4:7]) % 1000
            return f"SIGMA-{prefix:04d}-{suffix:03d}"
        elif len(digits) >= 3:
            prefix = (hash(digits) % 9000 + 1000) % 10000
            suffix = int(digits[-3:]) % 1000
            return f"SIGMA-{prefix:04d}-{suffix:03d}"

    base = abs(hash(sigma_id or str(uuid.uuid4()))) % 1000
    year = datetime.now().year % 10000
    return f"SIGMA-{year:04d}-{base:03d}"


def fix_sigma_fields(sigma_data: dict) -> dict:
    """
    Corrige les champs Sigma non supportés par le pipeline ASIM.
    Ex: CreatorProcessName → ParentImage
    """
    field_replacements = {
        "CreatorProcessName": "ParentImage",
        "TargetProcessFilename": "Image",
        "NewFileName": "TargetFilename",
        "OriginalFileName": "Image",  # fallback
    }

    if "detection" not in sigma_data:
        return sigma_data

    def recursive_replace(obj):
        if isinstance(obj, dict):
            for key, value in list(obj.items()):
                if key == "field" and isinstance(value, str) and value in field_replacements:
                    old = value
                    new = field_replacements[value]
                    print(f"🔧 [FIX] Champ invalide: {old} → {new}")
                    obj["field"] = new
                else:
                    recursive_replace(value)
        elif isinstance(obj, list):
            for item in obj:
                recursive_replace(item)

    recursive_replace(sigma_data["detection"])
    return sigma_data


def convert_sigma_file(sigma_path: Path, schema: dict):
    """Convertit un fichier Sigma en règle DaaC compatible Sentinel."""
    try:
        # 1. Lire le fichier Sigma
        with open(sigma_path, 'r', encoding='utf-8') as f:
            sigma_data = yaml.safe_load(f)

        if not sigma_data:
            raise ValueError("Fichier YAML vide ou invalide")

        log_conversion(f"PROCESSING: {sigma_path.name}")

        # === PATCH 0 : Corriger les champs Sigma invalides ===
        sigma_data = fix_sigma_fields(sigma_data)

        # === PATCH 1 : Corriger logsource.category si nécessaire ===
        if "logsource" in sigma_data:
            category = sigma_data["logsource"].get("category")
            if category and category in CATEGORY_MAPPING:
                print(f"🔧 [PATCH] logsource.category '{category}' → '{CATEGORY_MAPPING[category]}'")
                sigma_data["logsource"]["category"] = CATEGORY_MAPPING[category]

        # Valider/générer un ID UUID valide
        original_id = sigma_data.get("id", "")
        if not re.match(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", original_id):
            generated_uuid = str(uuid.uuid4())
            print(f"⚠️ [ID] ID invalide ou manquant → généré : {generated_uuid}")
            sigma_data["id"] = generated_uuid

        rule_title = sigma_data.get("title", sigma_path.stem)

        # 2. Charger la collection Sigma
        try:
            sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
        except Exception as e:
            if "must be an UUID" in str(e):
                sigma_data["id"] = str(uuid.uuid4())
                sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
            else:
                raise

        # 3. Générer la requête KQL via le backend ASIM
        backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline())
        kql_queries = backend.convert(sigma_collection)
        if not kql_queries:
            raise ValueError("Aucune requête KQL générée")

        kql_query = kql_queries[0]

        # 🔧 PATCH 1 : Im_Field → _Im_Field
        kql_query = re.sub(r'\b(Im_[A-Za-z_]+)\b', r'_\1', kql_query)

        # 🔧 PATCH 2 : Appliquer FIELD_MAPPING (Sigma → ASIM)
        for sigma_field, asim_field in FIELD_MAPPING.items():
            kql_query = re.sub(rf'\b{re.escape(sigma_field)}\b', asim_field, kql_query)

        # 🔧 PATCH 3 : Remplacer les tables ASIM (im*) par les vraies tables Sentinel
        for asim_table, real_table in ASIM_TABLE_MAPPING.items():
            kql_query = re.sub(rf'\b{asim_table}\b', real_table, kql_query)

        # 4. Extraire MITRE ATT&CK
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

        # 5. Générer l'ID DaaC
        daac_id = generate_daac_id(sigma_data["id"], source="sigma")

        # 6. Créer la règle DaaC
        daac_rule = {
            "id": daac_id,
            "name": rule_title,
            "description": sigma_data.get("description", "No description"),
            "tactics": sorted(list(set(tactics))),
            "techniques": sorted(list(set(techniques))),
            "severity": sigma_data.get("level", "medium").capitalize(),
            "query": kql_query.strip(),
            "status": "test",
            "version": 1.0,
            "clients": ["*"],
            "tags": tags,
            "author": sigma_data.get("author", "community"),
            "last_modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        }

        # 7. Validation du schéma
        if not validate_rule(daac_rule, sigma_path.name, schema):
            log_conversion(f"VALIDATION_FAILED: {sigma_path.name}")
            return

        # 8. Sauvegarder
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
    """Point d'entrée principal."""
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
