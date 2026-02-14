# Aegis Frontend (MVP)

Simple static frontend prototype for **Aegis — AI Code Security Auditor**.

## Features in this prototype

- Scan controls (repo path + language target)
- Simulated scan run
- Findings list with severity filter
- SARIF export button (`aegis-report.sarif`) after scan
- Attack Surface Graph preview (entrypoint → propagation → sink) in issue details
- Exploit Sketch panel (safe simulation narrative) for each selected finding
- Issue details panel with:
  - severity + confidence
  - attack path
  - patch diff preview
  - verification evidence
- Main UI author credit: **Built by Ethan Joseph**

## Run locally

```bash
python3 -m http.server 4173
```

Then open `http://localhost:4173`.

## Example branch workflow

This commit is an intentionally small example change made on a non-main branch (`demo/github-button-example`) so it can be pushed/merged later via your GitHub UI button flow.
