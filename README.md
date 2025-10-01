# MiTRE-CR911

Editable CR911 Threat Matrix mapping for NG911 / PSAP security.
This repo contains:
- mapping.json : canonical JSON mapping of tactics → techniques → affected i3 functional elements → mitigations
- cr911.-matrix.html : single-file interactive UI that reads mapping.json
- schema/ : JSON Schema for CI validation
- ci/validate_schema.py : simple schema validation script for CI
- playbooks/ : sample playbooks exported per technique
- evidence/ : place source PDF/DOCX files here (sensitive files should be kept internal)

## Quickstart (local)
1. Place the evidence files in `evidence/` (if available).
2. Start a local HTTP server:
   ```
   python -m http.server 8000
   ```
3. Open http://localhost:8000/mitre-cr911.html

## CI
- Use `schema/mapping.schema.json` and `ci/validate_schema.py` to validate mapping.json on PRs.

## How to edit
- Edit `mapping.json` and open the HTML to immediately view changes.
- Follow PR process: validate schema, add evidence pointers when adding techniques.

