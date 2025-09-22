#!/usr/bin/env python3
# scripts/validate_sigma.py
"""
Valide et corrige automatiquement les règles Sigma.
Usage :
  python validate_sigma.py --fix sigma-rules/*.yml
"""

import sys
import yaml
import uuid
import re
from pathlib import Path
from sigma.collection import SigmaCollection

# Champs obligatoires avec valeurs par défaut
REQUIRED_FIELDS = {
    "title": "TODO: add title",
    "status": "experimental",
    "description": "TODO: add description",
    "logsource": {"category": "process_creation"},
    "detection": {"selection": {}, "condition": "selection"},
    "level": "medium",
}

DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def fix_date(value):
    """Convert yyyy/mm/dd → yyyy-mm-dd"""
    if isinstance(value, str) and "/" in value:
        return value.replace("/", "-")
    return value


def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except Exception:
        return False


def make_serializable(obj):
    """
    Convertit les objets non serializables (datetime, date) en chaînes.
    Utile pour yaml.dump().
    """
    if isinstance(obj, (dict,)):
        return {k: make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_serializable(item) for item in obj]
    elif isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    elif isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()  # → "2021-07-21"
    else:
        return str(obj)  # fallback


def validate_and_fix_sigma_file(path, autofix=False):
    file_path = Path(path)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Charger tous les documents YAML
        try:
            docs = list(yaml.safe_load_all(content))
            if not docs or docs == [None]:
                print(f"❌ Fichier vide ou invalide : {path}")
                return False
        except yaml.YAMLError as e:
            print(f"❌ Erreur YAML dans {path} : {e}")
            return False

        modified = False
        valid = True

        for doc in docs:
            if not isinstance(doc, dict):
                print(f"❌ Document non-dict dans {path}")
                valid = False
                continue

            # Champs requis
            for field, default in REQUIRED_FIELDS.items():
                if field not in doc:
                    print(f"⚠️  Champ manquant : {field} dans {path}")
                    if autofix:
                        doc[field] = default
                        modified = True
                        print(f"   ➕ Ajouté : {field}")

            # Correction de date
            if "date" in doc:
                fixed = fix_date(doc["date"])
                if fixed != doc["date"]:
                    print(f"⚠️  Format date corrigé : {doc['date']} → {fixed}")
                    if autofix:
                        doc["date"] = fixed
                        modified = True
                if not DATE_REGEX.match(str(doc["date"])):
                    print(f"❌ Format date invalide : {doc['date']}")
                    if autofix:
                        doc["date"] = "2025-01-01"
                        modified = True
                        print(f"   ➕ Date remplacée par 2025-01-01")
                    else:
                        valid = False

            # Vérification ID
            if "id" in doc and not is_valid_uuid(doc["id"]):
                print(f"⚠️  ID invalide : {doc['id']} dans {path}")
                if autofix:
                    new_id = str(uuid.uuid4())
                    doc["id"] = new_id
                    modified = True
                    print(f"   ➕ ID généré : {new_id}")
                else:
                    valid = False

            # Vérifier condition dans detection
            if "detection" in doc and isinstance(doc["detection"], dict):
                if "condition" not in doc["detection"]:
                    print(f"⚠️  'condition' manquant dans 'detection' ({path})")
                    if autofix:
                        doc["detection"]["condition"] = "selection"
                        modified = True

        # Validation sémantique Sigma
        try:
            SigmaCollection.from_yaml(yaml.dump_all(docs, allow_unicode=True))
        except Exception as e:
            print(f"❌ Échec validation Sigma : {e}")
            valid = False

        # Sauvegarde avec backup
        if autofix and modified:
            backup = file_path.with_suffix(file_path.suffix + ".bak")
            file_path.rename(backup)

            # 🔧 Appliquer make_serializable AVANT dump
            serializable_docs = [make_serializable(doc) for doc in docs]

            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump_all(serializable_docs, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
            print(f"💾 Fichier corrigé : {file_path} (backup: {backup})")

        if valid:
            print(f"✅ Valide : {path}")
        return valid

    except Exception as e:
        print(f"❌ Erreur inattendue : {e}")
        return False


def get_sigma_files(paths):
    """Récupère tous les .yml/.yaml (sans .bak ni fichiers cachés)"""
    files = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            if path.suffix in [".yml", ".yaml"] and not path.name.endswith(".bak") and not path.name.startswith("."):
                files.append(path)
        elif path.is_dir():
            for f in path.rglob("*.yml"):
                if not f.name.endswith(".bak") and not f.name.startswith("."):
                    files.append(f)
            for f in path.rglob("*.yaml"):
                if not f.name.endswith(".bak") and not f.name.startswith("."):
                    files.append(f)
    return files


if __name__ == "__main__":
    from datetime import datetime  # 🔹 Ajoute cette ligne en haut du fichier !

    if len(sys.argv) < 2:
        print("Usage: python validate_sigma.py [--fix] <fichier|dossier> ...")
        sys.exit(1)

    autofix = "--fix" in sys.argv
    args = [arg for arg in sys.argv[1:] if arg != "--fix"]

    files = get_sigma_files(args)
    if not files:
        print("❌ Aucun fichier trouvé")
        sys.exit(1)

    all_valid = True
    for file in files:
        if not validate_and_fix_sigma_file(file, autofix=autofix):
            all_valid = False

    if not all_valid:
        sys.exit(1)
    else:
        print("🎉 Tous les fichiers sont valides.")