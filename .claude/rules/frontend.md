---
paths:
  - "frontend/src/**"
---

# Frontend rules (Angular 22)
- Each screen keeps separate `.html` / `.ts` / `.css` files.
- `core/models.ts` mirrors `src/api/schemas.py`; change both together until T-020 generates the types.
- Alert fields hold attacker-controlled text. No `innerHTML` or `bypassSecurityTrust*`. Leaflet popups are built from DOM nodes with `textContent`, as `attack-map.ts` does.
- API URLs stay relative: the app is served under `/siem/` in the deployment stack.
- Run with `task brief -- frontend`, which prints one line on a pass.
