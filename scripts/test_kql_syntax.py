#!/usr/bin/env python3
# scripts/test_kql_syntax.py

import sys
import yaml
import re
from pathlib import Path

# Chemins
RULES_DIR = Path("rules")
LOG_FILE = Path("logs/kql-validation.log")

# Créer les dossiers nécessaires
LOG_FILE.parent.mkdir(exist_ok=True)


def log_message(level: str, message: str):
    """Écrit un message dans le log"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        print(f"{level}: {message}")
        f.write(f"{level}: {message}\n")


def is_valid_kql(query: str) -> tuple[bool, list[str]]:
    """
    Vérifie la syntaxe basique d'une requête KQL.
    Retourne (is_valid, errors)
    """
    errors = []

    if not query or not query.strip():
        errors.append("Requête vide ou manquante")
        return False, errors

    lines = [line.strip() for line in query.strip().split('\n') if line.strip()]
    if not lines:
        errors.append("Aucune ligne valide dans la requête")
        return False, errors

    # 1. Doit commencer par un nom de table (ex: DeviceProcessEvents, Event, etc.)
    first_line = lines[0]
    table_pattern = r"^[a-zA-Z_][a-zA-Z0-9_]*"
    match = re.match(table_pattern, first_line)
    if not match:
        errors.append("La requête doit commencer par un nom de table (ex: DeviceProcessEvents)")
    else:
        table_name = match.group()
        if not re.match(r"^(Device|Security|Event|CommonSecurity|Im)\w+", table_name):
            errors.append(f"Nom de table non standard: '{table_name}'")

    # 2. Vérifier les opérateurs courants mal écrits
    forbidden_patterns = [
        ("==", "Utiliser '==' au lieu de '==' peut être redondant ; préférer '=' si intentionnel"),
        ("!==", "Opérateur invalide: utiliser '!has' ou '!= selon le contexte"),
        ("contains*", "Utiliser 'contains' ou 'has_prefix', pas 'contains*'"),
    ]

    for pattern, warning in forbidden_patterns:
        if pattern in query:
            errors.append(warning)

    # 3. Vérifier les guillemets simples/doubles mal fermés
    if query.count("'") % 2 != 0:
        errors.append("Nombre impair de guillemets simples : probablement non fermé")
    if query.count('"') % 2 != 0:
        errors.append("Nombre impair de guillemets doubles : probablement non fermé")

    # 4. Vérifier | suivi d’un mot-clé valide
    pipes = re.findall(r'\|\s*([a-zA-Z]+)', query)
    valid_operators = {
        "where", "project", "summarize", "extend", "order", "sort", "limit",
        "count", "make_list", "join", "union", "parse"
    }
    for op in pipes:
        if op.lower() not in map(str.lower, valid_operators):
            errors.append(f"Opérateur KQL potentiellement invalide : '{op}'")

    return len(errors) == 0, errors


def test_kql_in_rule(file_path: Path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        query = rule.get("query", "").strip()

        if not query:
            log_message("ERROR", f"{file_path.name} : champ 'query' manquant ou vide")
            return False

        is_valid, errors = is_valid_kql(query)

        if is_valid:
            log_message("INFO", f"{file_path.name} : requête KQL syntaxiquement valide")
            return True
        else:
            for error in errors:
                log_message("ERROR", f"{file_path.name} : {error}")
            return False

    except Exception as e:
        log_message("ERROR", f"{file_path.name} : erreur lors de l'analyse - {str(e)}")
        return False


def main():
    rules_files = list(RULES_DIR.glob("*.yml"))
    if not rules_files:
        log_message("WARNING", "Aucune règle trouvée dans /rules/")
        return

    all_valid = True
    for rule_file in rules_files:
        if not test_kql_in_rule(rule_file):
            all_valid = False

    if not all_valid:
        log_message("ERROR", "❌ Une ou plusieurs requêtes KQL sont invalides.")
        sys.exit(1)
    else:
        log_message("INFO", "✅ Toutes les requêtes KQL sont syntaxiquement valides.")
        print("🎉 Validation KQL réussie !")


if __name__ == "__main__":
    main()