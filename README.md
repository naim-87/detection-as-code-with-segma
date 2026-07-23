# 🛡️ Detection-as-Code (DaaC) Framework | SOC MSSP

Welcome to the central nervous system for our client detection logic. This repository serves as the single source of truth for all Detection-as-Code (DaaC) rules, ensuring our SOC MSSP stays one step ahead of threats.

## 📁 Repository Anatomy
* **`/rules/`** – Production-ready DaaC rules (YAML).
* **`/sigma-rules/`** – Staging area for raw Sigma rules awaiting conversion.
* **`/schemas/`** – Validation schemas to keep syntax strictly standardized.
* **`/scripts/`** – Automation utilities and conversion logic.
* **`/.github/workflows/`** – CI/CD pipelines that keep deployment seamless.

## 🚀 Adding a New Rule
Contributing is simple and heavily automated:
1. **Draft:** Add your new Sigma rule to the `/sigma-rules/` directory.
2. **Propose:** Open a Pull Request.
3. **Deploy:** The CI/CD pipeline will automatically convert, lint, and validate your rule.

## ✅ Quality Assurance
No rule reaches production without passing our checks:
* **Strict Syntax:** All rules must pass automated linting and schema validation.
* **Peer Review:** Every change requires explicit sign-off from a Detection Lead.

## 🔐 Security & Secrets
*Practice what we preach: Zero Trust applies to this repo.*
Access is strictly restricted. **Never** commit credentials, API keys, or sensitive tokens.

---
