#!/usr/bin/env python3
# scripts/test_kql_syntax.py
"""
Valide la syntaxe basique des requêtes KQL générées dans les règles DaaC.
Compatible avec :
- Microsoft Sentinel (tables standard)
- MDE (Device*)
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


def log_message(level: str, message: str):
    """Écrit un message dans le log et l'affiche"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        print(f"{level}: {message}")
        f.write(f"{level}: {message}\n")


# ✅ Tables autorisées : seules les versions avec _Im_* sont acceptées
ALLOWED_TABLES = {
    # --- Tables Device (MDE) ---
    "DeviceProcessEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceNetworkEvents",
    "DeviceImageLoadEvents",
    "DeviceLogonEvents",
    "DeviceAlertEvents",
    "DeviceTvmSoftwareInventory",

    # --- Tables Security & Azure ---
    "SecurityEvent",
    "SecurityAlert",
    "IdentityLogonEvents",
    "AADSignInLogs",
    "AADDiagnosticLogs",
    "AzureActivity",
    "OfficeActivity",

    # --- Tables ASIM personnalisées (_Im_*) ---
    "_Im_ProcessCreate",
    "_Im_Registry",
    "_Im_FileEvent",
    "_Im_NetworkSession",
    "_Im_ImageLoad",
    "_Im_Logon",
    "_Im_DnsQuery",
    "_Im_PowerShell",
    "_Im_WinEvent",

    # --- Autres tables courantes ---
    "Event",
    "Syslog",
    "CommonSecurityLog",
    "WireData"
}

# 🔄 Normalisation des alias fréquents vers les noms réels (_Im_*)
ASIM_NORMALIZATION = {
    "imProcessCreate": "_Im_ProcessCreate",
    "imRegistry": "_Im_Registry",
    "imFile": "_Im_FileEvent",
    "imNetwork": "_Im_NetworkSession",
    "imImageLoad": "_Im_ImageLoad",
    "imLogon": "_Im_Logon",
    "imDnsQuery": "_Im_DnsQuery",
    "imPowerShell": "_Im_PowerShell",
    "imWinEvent": "_Im_WinEvent"
}

# ✅ Opérateurs KQL valides
VALID_OPERATORS = {
    "where", "project", "extend", "summarize", "count", "make_list",
    "join", "union", "order", "sort", "limit", "parse", "mv-expand",
    "distinct", "top", "render", "evaluate", "let", "materialize", "has",
    "contains", "startswith", "endswith", "has_any", "in"
}


def normalize_table_name(table: str) -> str:
    """Normalise les noms de tables : imProcessCreate → _Im_ProcessCreate"""
    table = table.strip()
    if not table:
        return ""
    if table in ALLOWED_TABLES:
        return table
    return ASIM_NORMALIZATION.get(table.lower(), table)


def extract_tables(query: str) -> list[str]:
    """Extrait toutes les tables utilisées dans la requête (première + union)"""
    tables = []
    lines = [line.strip() for line in query.split('\n') if line.strip()]

    for line in lines:
        if line.startswith("//") or line.lower().startswith(("let ", "range ")):
            continue
        match = re.match(r"^([_a-zA-Z][_a-zA-Z0-9]*)", line)
        if match:
            tables.append(match.group(1))
            break  # Première table principale

    # Recherche les unions
    union_matches = re.findall(r"union\s+([_a-zA-Z][_a-zA-Z0-9]*(?:\s*,\s*[_a-zA-Z][_a-zA-Z0-9]*)*)", query)
    for match in union_matches:
        for t in match.split(","):
            t_clean = t.strip()
            if t_clean:
                tables.append(t_clean)

    return tables


def is_valid_kql(query: str) -> tuple[bool, list[str]]:
    """
    Vérifie la syntaxe basique d'une requête KQL.
    Retourne (is_valid, errors)
    """
    errors = []

    if not query or not query.strip():
        errors.append("Requête vide ou manquante")
        return False, errors

    # 1. Extraire les tables
    tables = extract_tables(query)
    if not tables:
        errors.append("Impossible de trouver une table cible (ex: _Im_ProcessCreate)")
    else:
        for t in tables:
            norm = normalize_table_name(t)
            if norm not in ALLOWED_TABLES:
                suggestions = [tbl for tbl in ALLOWED_TABLES if t.lower() in tbl.lower()]
                hint = f" Peut-être vouliez-vous : {suggestions[:2]} ?" if suggestions else ""
                errors.append(f"Table non supportée : '{t}'{hint}")

    # 2. Vérifier les guillemets mal fermés
    if query.count("'") % 2 != 0:
        errors.append("Nombre impair de guillemets simples : probablement non fermé")
    if query.count('"') % 2 != 0:
        errors.append("Nombre impair de guillemets doubles : probablement non fermé")

    # 3. Vérifier les pipes suivis d'opérateurs valides
    pipe_matches = re.findall(r'\|\s*([a-zA-Z_]+)', query)
    for op in pipe_matches:
        if op.lower() not in map(str.lower, VALID_OPERATORS):
            errors.append(f"Opérateur KQL invalide ou mal orthographié : '{op}'")

    # 4. Vérifier les join sans "on"
    if "join" in query and " on " not in query:
        errors.append("Clause 'join' sans 'on' détectée")

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