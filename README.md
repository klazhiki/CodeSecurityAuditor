# Aegis Frontend (MVP)

Simple static frontend prototype for **Aegis — AI Code Security Auditor**.

## Features in this prototype

- Scan controls (repo path + language target)
- Simulated scan run
- Findings list with severity filter
- Issue details panel with:
  - severity + confidence
  - attack path
  - patch diff preview
  - verification evidence

## Run locally

```bash
python3 -m http.server 4173
```

Then open `http://localhost:4173`.
