#  Framework Detection-as-Code (DaaC) - SOC MSSP

Ce depott centralise toutes les règles de détection pour nos clients.

## 📁 Structure
- `/rules/` : Règles DaaC (YAML)
- `/sigma-rules/` : Règles Sigma à convertir
- `/schemas/` : Schéma de validation
- `/scripts/` : Automatisations
- `/.github/workflows/` : CI/CD

##  Ajouter une règle
1. Ajoute une règle Sigma dans `/sigma-rules/`
2. Ouvre une Pull Request
3. Le pipeline convertit et valide automatiquement

##  Validation
- Toutes les règles doivent passer le linting et la validation de schéma.
- Les modifications doivent être approuvées par un lead.

## 🔐 Secrets
Accès restreint. Ne jamais exposer de credentials.

---

👉 En cas de doute : contacter le lead detection.