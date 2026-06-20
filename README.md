# ARGUS
**A**utomated **R**econnaissance, **G**overnance & **U**nified **S**ecurity Platform

ARGUS is an enterprise-grade, polyglot microservice platform unifying network scanning, packet analysis, vulnerability assessment, and threat-framework correlation. 

## ⚠️ Legal & Ethical Guardrails (Strictly Enforced)
This tool is designed with dual-use capabilities (active reconnaissance and packet manipulation). 
* **Authorized Scope Only:** Active scanning features are strictly gated. The engine will absolutely refuse to execute any job unless the target IP/range exists in a cryptographically signed **Authorized Scope** record.
* **Audit Trail:** Every action, scan, and report is recorded in an immutable, append-only audit log for legal defensibility.
* **Disclaimer:** By deploying or contributing to ARGUS, you acknowledge responsibility for strictly adhering to applicable local and international cyber laws.

## Architecture Overview
ARGUS ships as web, desktop, and mobile from a single backend, leveraging a polyglot microservice strategy:
* **Rust:** Low-level network raw sockets and packet parsing (`scan-engine`, `packet-analyzer`).
* **Java (Spring):** Enterprise correlation, asset inventory, and PDF report generation.
* **Python:** Fast threat-intel scripting, NVD/MITRE sync, and orchestration.

*For full architecture details, refer to the `docs/` directory.*