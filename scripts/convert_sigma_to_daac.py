#!/usr/bin/env python3
# scripts/convert_sigma_to_daac.py

import yaml
import json
import sys
import re
import uuid
from pathlib import Path
from datetime import datetime
from sigma.rule import SigmaRule
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

# Mapping des catégories Sigma non standard -> catégories standard
CATEGORY_MAPPING = {
    # PowerShell
    "ps_classic_start": "process_creation",
    "ps_module_load": "image_load",
    "ps_script": "process_creation",

    # Registre
    "registry_add": "registry_add",
    "registry_delete": "registry_add",
    "registry_event": "registry_add",

    # Fichiers
    "file_create": "file_event",
    "file_delete": "file_event",
    "file_access": "file_event",

    # Réseau
    "network_connection": "network_connection",
    "dns_query": "dns_events",

    # Pilotes
    "driver_load": "driver_load",

    # Authentification
    "authentication": "logon_logoff",
    "logon": "logon_logoff",

    # Data field fix
    "Data": "CommandLine",
}


def log_conversion(message: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {message}\n")


def load_schema():
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
    """
    Génère un ID DaaC avec padding à zéro :
    - SIGMA-1234-567 → SIGMA-XXXX-YYY (4d-3d)
    - SOC-2025-042 → SOC-YYYY-ZZZ (4d-3d)
    """
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


def convert_sigma_file(sigma_path: Path, schema: dict):
    try:
        # 1. Lire le fichier Sigma
        with open(sigma_path, 'r', encoding='utf-8') as f:
            sigma_data = yaml.safe_load(f)

        # === PATCH AUTOMATIQUE du logsource.category ===
        if "logsource" in sigma_data:
            category = sigma_data["logsource"].get("category")
            if category and category in CATEGORY_MAPPING:
                print(f"🔧 Correction auto: logsource.category '{category}' → '{CATEGORY_MAPPING[category]}'")
                sigma_data["logsource"]["category"] = CATEGORY_MAPPING[category]
        # ==============================================

        # Valider l'ID Sigma
        original_id = sigma_data.get("id", "")
        if not original_id or not re.match(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", original_id):
            print(f"⚠️ ID invalide ou manquant pour {sigma_path.name}, génération automatique")
            sigma_data["id"] = str(uuid.uuid4())

        rule_title = sigma_data.get("title", sigma_path.stem)
        log_conversion(f"CONVERTING: {sigma_data['id']} - {rule_title}")

        # 2. Charger la collection Sigma
        try:
            sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
        except Exception as e:
            if "must be an UUID" in str(e):
                sigma_data["id"] = str(uuid.uuid4())
                sigma_collection = SigmaCollection.from_yaml(yaml.dump(sigma_data))
            else:
                raise

        # 3. Backend KQL avec ASIM
        backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline())
        kql_queries = backend.convert(sigma_collection)
        if not kql_queries:
            raise ValueError("Aucune requête KQL générée")
        
        # 4. 🔧 PATCH : Remplacer Im_ → _Im_ dans la requête KQL
        kql_query = kql_queries[0]
        kql_query = re.sub(r'\b(Im_[A-Za-z]+)\b', r'_\1', kql_query)  # Im_X → _Im_X

        # 5. Extraire MITRE
        tactics, techniques, tags = [], [], []
        for t in sigma_data.get("tags", []):
            t_upper = t.upper()
            if re.match(r"^ATTACK\.T[0-9]{4}(\.[0-9]{3})?$", t_upper):
                techniques.append(t_upper.replace("ATTACK.", "T"))
            elif t_upper.startswith("ATTACK."):
                tactic = t.split(".")[-1].lower()
                if tactic not in tactics:
                    tactics.append(tactic)
            else:
                tags.append(t)

        # 6. Générer l'ID DaaC
        daac_id = generate_daac_id(sigma_data["id"], source="sigma")

        # 7. Créer la règle DaaC
        daac_rule = {
            "id": daac_id,
            "name": rule_title,
            "description": sigma_data.get("description", "No description"),
            "tactics": tactics,
            "techniques": techniques,
            "severity": sigma_data.get("level", "medium").capitalize(),
            "query": kql_query,
            "status": "test",
            "version": 1.0,
            "clients": ["*"],
            "tags": tags,
            "author": sigma_data.get("author", "community"),
            "last_modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        }

        # 8. Validation du schéma
        if not validate_rule(daac_rule, sigma_path.name, schema):
            sys.exit(1)

        # 9. Sauvegarder
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
        sys.exit(1)


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

    for file in sigma_files:
        convert_sigma_file(file, schema)


if __name__ == "__main__":
    main()