---
paths:
  - "docker/**"
  - "stack/**"
  - ".github/**"
---

# Infra rules
- `$remote_addr` is what the engine trusts, and `set_real_ip_from` decides who can rewrite it. Treat any edit there as a security change.
- The `log_format` must match `NGINX_EXTENDED_LOG_PATTERN` in `src/security_engine/parser.py`. Change them together, with a parser test.
- Any change to what reaches `blocklist.conf` needs `nginx -t` to stay green before reload.
- No plaintext defaults for secrets in compose. Use `${VAR:?}` so a missing value fails at startup.
- Images run non-root, pinned by digest. GitHub Actions are pinned by commit SHA.
- Don't publish a port unless something outside the compose network needs it.
