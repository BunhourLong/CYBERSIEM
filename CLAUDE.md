# CyberSIEM

**OpenWolf-managed project.** Follow `.wolf/OPENWOLF.md` — check `.wolf/cerebrum.md` before coding, read `.wolf/anatomy.md` before file ops.

## Quick Reference

- **Project:** HTTP traffic security monitoring + enforcement (real-time log processing, reputation scoring, NGINX blocking)
- **Tech:** Python 3.12, FastAPI, PostgreSQL 16, NGINX 1.27, Jinja2+HTMX, Docker Compose
- **Containers:** `api` (FastAPI 8000), `security_engine` (LogMonitorService), `postgres` (5432), `nginx` (8088)
- **Core Logic:** `src/security_engine/enforcement.py` (scoring, state machine, decay) + `enforcement_service.py` (analyst overrides)

## Architecture

**Data Flow:**  
NGINX log → LogMonitorService → RateAbuseDetector | BruteForceDetector | PayloadDetector → evaluate_ip_reputation() → NginxBlocklistManager → blocklist.conf

**Key Files:**
- `src/security_engine/enforcement.py` — ReputationConfig, evaluate_ip_reputation(), NginxBlocklistManager
- `src/security_engine/enforcement_service.py` — EnforcementService (manual_block, trust_ip, suppress_auto_block, etc.)
- `docker/postgres/init.sql` — Tables: events, alerts, ip_reputations, ip_reputation_transitions
- `docker/docker-compose.yml` — All REPUTATION_* env vars configurable

## When Working

1. **File ops:** Consult `.wolf/anatomy.md` first (token estimates prevent unnecessary reads)
2. **Code changes:** Check `.wolf/cerebrum.md` → Key Learnings + Do-Not-Repeat before writing
3. **After edits:** Append to `.wolf/memory.md` + update `.wolf/anatomy.md` if files changed
4. **Bugs found:** Log to `.wolf/buglog.json` before fixing

## Guardrails

- **Preserve:** 3-container architecture, state machine in evaluate_ip_reputation(), audit trail in ip_reputation_transitions
- **Prefer:** Env var config (not hardcoded), surgical edits (not rewrites), Detector ABC extensions (not core modifications)
- **Don't:** Bypass EnforcementService, remove logging, rewrite production-tested scoring/decay logic
- **Check first:** Imports, DB schema, env var names, template file existence

## Testing

```bash
curl http://localhost:8000/api/alerts
curl -X POST http://localhost:8000/ingest-event -H "Content-Type: application/json" -d '{"method":"GET","endpoint":"/admin","status_code":401,"ip":"203.0.113.42"}'
docker logs -f cybersiem_security_engine
docker exec cybersiem_nginx cat /etc/nginx/dynamic/blocklist.conf
```

---

**Updated:** 2026-04-21 | **Status:** Production-Ready
