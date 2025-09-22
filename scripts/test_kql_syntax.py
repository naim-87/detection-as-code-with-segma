#!/usr/bin/env python3
# scripts/test_kql_syntax.py
"""
Valide la syntaxe basique des requêtes KQL générées dans les règles DaaC.
Compatible avec Microsoft Sentinel et les tables ASIM (imProcessCreate, etc.).
"""

import sys
import yaml
import re
from pathlib import Path

# Chemins
RULES_DIR = Path("rules")
LOG_FILE = Path("logs/kql-validation.log")

# Créer les dossiers nécessaires
LOG_FILE.parent.mkdir(exist_ok=True)

# Tables autorisées dans Microsoft Sentinel (standard + ASIM)
ALLOWED_TABLES = {
    # Tables Device *
    "DeviceProcessEvents", "DeviceFileEvents", "DeviceRegistryEvents",
    "DeviceNetworkEvents", "DeviceImageLoadEvents", "DeviceLogonEvents",
    "DeviceAlertEvents", "DeviceTvmSoftwareInventory",

    # Tables Security *
    "SecurityEvent", "SecurityAlert", "IdentityLogonEvents",
    "AADSignInLogs", "AADDiagnosticLogs", "AzureActivity", "OfficeActivity",

    # Tables ASIM (Analytic Schema Integration Model)
    "imProcessCreate", "imRegistry", "imFile", "imNetwork", "imImageLoad",

    # Autres courantes
    "Event", "Syslog", "CommonSecurityLog", "WireData"
}

# Opérateurs KQL valides
VALID_OPERATORS = {
    "where", "project", "extend", "summarize", "count", "make_list",
    "join", "union", "order", "sort", "limit", "parse", "mv-expand",
    "distinct", "top", "render", "evaluate", "let", "materialize"
}


def log_message(level: str, message: str):
    """Écrit un message dans le log et l’affiche"""
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

    # 1. Vérifier que la première ligne est un nom de table valide
    first_line = lines[0]
    table_match = re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*", first_line)
    if not table_match:
        errors.append("La requête doit commencer par un nom de table (ex: DeviceProcessEvents)")
    else:
        table_name = table_match.group()
        if table_name not in ALLOWED_TABLES:
            errors.append(f"Table non supportée : '{table_name}' (utilisez une table standard ou ASIM)")

    # 2. Vérifier les guillemets mal fermés
    if query.count("'") % 2 != 0:
        errors.append("Nombre impair de guillemets simples : probablement non fermé")
    if query.count('"') % 2 != 0:
        errors.append("Nombre impair de guillemets doubles : probablement non fermé")

    # 3. Vérifier les pipes suivis d'opérateurs valides
    pipe_matches = re.findall(r'\|\s*([a-zA-Z]+)', query)
    for op in pipe_matches:
        if op.lower() not in map(str.lower, VALID_OPERATORS):
            errors.append(f"Opérateur KQL invalide ou mal orthographié : '{op}'")

    # 4. Corriger l’avertissement sur '==' → en fait, c’est valide en KQL
    # On supprime cette vérification car == est correct

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