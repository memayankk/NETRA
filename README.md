# NETRA — SIH26189 Internal Final Prototype

NETRA is a presentation-ready prototype for **SIH26189 — AI-Powered Criminal Network Analysis System**. The prototype uses synthetic/demo investigation data.

## Current capabilities
- Secure investigator login (demo authentication) with role field
- Protected backend APIs and logout
- Interactive D3 relationship graph with search, filtering, focus, auto-fit and re-layout
- Entity extraction: people, phones, vehicles, locations, organizations, accounts and emails
- Evidence-linked entity drill-down and Person 360
- CDR communication analysis and repeated-link leads
- Financial transaction analysis and cross-modal investigation leads
- Timeline and location intelligence
- Network communities, bridge/anomaly-style investigation leads and shortest evidence paths
- AI Evidence Extractor and reviewed-evidence ingest workflow
- Unified investigation view combining network/CDR/financial signals
- Investigation report PDF export
- SHA-256 evidence integrity verification and audit trail

## Demo login
- **Username:** `investigator`
- **Password:** `Netra@2026`
- Role: Investigator

Administrator demo account:
- **Username:** `admin`
- **Password:** `NetraAdmin@2026`

These credentials are for the synthetic internal demonstration only and must be replaced by a proper identity system before deployment.

## Run on Windows
Use Python **3.13**:

```cmd
py -3.13 -m pip install -r requirements.txt
py -3.13 -m uvicorn app.main:app --reload --port 8001
```

Open **http://127.0.0.1:8001** and sign in.

## Important demo/security framing
- The dataset is synthetic/demo data.
- Graph priority and investigation signals are **not findings of guilt or criminality**.
- The current login is a prototype authentication layer, not production identity management.
- Production deployment should add enterprise identity integration, MFA, stronger session management, HTTPS, RBAC enforcement per case, encryption, secure key management, scalable persistent storage, retention controls, legal governance and false-positive safeguards.
