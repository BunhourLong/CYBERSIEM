# Cappa — Layer 7 Web Threat Monitoring & Response Platform

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![NGINX](https://img.shields.io/badge/NGINX-1.27-009639?logo=nginx&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

Cappa is a self-hosted web security monitoring and automated response platform. It tails NGINX access logs in real time, classifies HTTP traffic through eight specialized threat detectors, scores IP reputation using a multi-state machine, and automatically enforces blocks by rewriting the NGINX blocklist — all without restarting the server.

An analyst dashboard provides live visibility into alerts, geographic threat maps, blocked IPs, and per-alert investigation controls.

---

## Key Features

- **Real-time log monitoring** — tails NGINX `access.log` with zero polling delay
- **8 Layer 7 threat detectors** — brute force, SQL injection, XSS, credential stuffing, rate abuse, path probing, API scraping, user-agent rotation
- **IP reputation state machine** — five states (trusted → unknown → suspicious → throttled → blocked) with automatic score decay
- **Live NGINX blocklist enforcement** — writes `deny` rules to a dynamically included conf file; NGINX hot-reloads it without downtime
- **Analyst dashboard** — alert queue, alert status workflow (unresolved / safe / malicious), live stats, and geographic map view
- **GeoIP & ASN enrichment** — MaxMind GeoLite2 databases for country, city, and network-owner attribution
- **Manual IP controls** — analysts can manually block, trust, whitelist, or suppress auto-blocking for any IP
- **Full audit trail** — every reputation state transition is persisted to PostgreSQL
- **Role-based access** — readonly / analyst / admin tiers enforced per route
- **Dockerized multi-service deployment** — single `docker compose up --build -d` brings the entire stack online

---

## Architecture

```
                        Internet / Attacker
                               │
                               ▼
                    ┌─────────────────────┐
                    │     NGINX (port 80) │
                    │  path routing:      │
                    │    /       → app    │
                    │    /siem/  → Cappa  │
                    │  blocklist enforce  │
                    │  access.log write   │
                    └──────────┬──────────┘
                               │ log file (shared volume)
              ┌────────────────┴───────────────┐
              ▼                                ▼
 ┌────────────────────────┐     ┌──────────────────────────┐
 │  Security Engine       │     │  Cappa API (FastAPI)     │
 │  LogMonitorService     │     │  port 8000               │
 │  ─ tail access.log     │     │  ─ dashboard UI          │
 │  ─ parse log lines     │     │  ─ alerts REST API       │
 │  ─ run 8 detectors     │     │  ─ IP control endpoints  │
 │  ─ score reputation    │     │  ─ session auth (HMAC)   │
 │  ─ write blocklist     │     │  ─ map data endpoint     │
 └──────────┬─────────────┘     └────────────┬─────────────┘
            │                                │
            └──────────────┬─────────────────┘
                           ▼
              ┌────────────────────────┐
              │  PostgreSQL 16         │
              │  ─ events              │
              │  ─ alerts              │
              │  ─ ip_reputations      │
              │  ─ ip_reputation_      │
              │    transitions (audit) │
              └────────────────────────┘
```

**Data flow:**
1. A request hits NGINX → NGINX logs it to `access.log` → NGINX enforces any existing IP blocks
2. `LogMonitorService` reads the new log line → parses it into an `HTTPLogEvent`
3. `SecurityEngine` runs all 8 detectors against the event
4. Alerts are persisted; `EnforcementService` re-scores the IP reputation and rewrites `blocklist.conf` if the score crosses the block threshold
5. The Cappa dashboard (Angular) reflects all changes in near real time by polling the JSON API

---

## Screenshots

> _Add screenshots or GIFs here._

| Dashboard | Alerts | Geographic Map |
|---|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Alerts](docs/screenshots/alerts.png) | ![Map](docs/screenshots/map.png) |

---

## Domain & Routing

All path routing is handled by NGINX. The domain nginx listens on is set via a single environment variable — no nginx config edits required when switching environments.

| Path | Destination | Notes |
|---|---|---|
| `http://<host>/` | BookMark-Publisher (Express) | Public site |
| `http://<host>/admin` | BookMark-Publisher admin panel | Requires admin login |
| `http://<host>/siem` | Cappa dashboard (FastAPI) | Requires analyst/admin login |
| `http://<host>/health` | nginx | Returns `ok` — used for health checks |

To change the domain, edit one line in `stack/.env`:

```bash
# Local development (default)
NGINX_HOST=localhost

# EC2 / production
NGINX_HOST=capnova.duckdns.org
```

Then restart the stack: `docker compose up -d --force-recreate nginx`

---

## Quick Start (Local — Docker Compose)

### Prerequisites

- Docker + Docker Compose (v2)
- GeoLite2 databases — download free from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place in `cybersiem/data/`:
  - `GeoLite2-City.mmdb`
  - `GeoLite2-ASN.mmdb`

### Steps

```bash
# 1. Clone both repos side by side
git clone https://github.com/YOUR_USERNAME/cappa.git          cybersiem
git clone https://github.com/YOUR_USERNAME/bookmark-publisher.git

# Required layout:
# FYP/
#   cybersiem/          ← this repo (stack/ lives inside)
#   bookmark-publisher/

# 2. Create the environment file
cd cybersiem/stack
cp .env.example .env    # NGINX_HOST=localhost is the default — no edits needed for local

# 3. Build and start
docker compose up --build -d

# 4. Verify
curl http://localhost/health        # → ok
curl http://localhost/siem          # → redirects to /siem/login
```

Open `http://localhost/siem/login` and sign in with the credentials from `.env`.

### Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NGINX_HOST` | `localhost` | Domain nginx binds to — change to your DuckDNS/domain for EC2 |
| `SIEM_ADMIN_USERNAME` | `admin` | Dashboard login username |
| `SIEM_ADMIN_PASSWORD` | `Admin123456!!` | Dashboard login password (min 12 chars) |
| `SIEM_SESSION_SECRET` | _(placeholder)_ | HMAC secret for cookies — run `openssl rand -base64 32` |
| `DATABASE_URL` | _(local postgres)_ | PostgreSQL connection string |
| `GEOIP_DB_PATH` | `/data/GeoLite2-City.mmdb` | Container path to GeoIP database |
| `SESSION_SECURE` | `false` | Set `true` only after HTTPS is configured |

See [`stack/.env.example`](stack/.env.example) for the full documented list.

---

## EC2 Deployment

```bash
# 1. Provision: Ubuntu 24.04, t3.small+, ports 22 + 80 open

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu && newgrp docker

# 3. Clone repos
mkdir ~/apps && cd ~/apps
git clone https://github.com/YOUR_USERNAME/cappa.git cybersiem
git clone https://github.com/YOUR_USERNAME/bookmark-publisher.git

# 4. Copy GeoIP databases
scp GeoLite2-*.mmdb ubuntu@<EC2_IP>:~/apps/cybersiem/data/

# 5. Create .env — set NGINX_HOST to your domain
cd ~/apps/cybersiem/stack
cp .env.example .env
nano .env
# Key lines to update:
#   NGINX_HOST=capnova.duckdns.org
#   SIEM_SESSION_SECRET=<openssl rand -base64 32>
#   SIEM_ADMIN_PASSWORD=<strong password>
#   EXPRESS_ADMIN_PASSWORD=<strong password>
#   SECURITY_ADMIN_TOKEN=<openssl rand -hex 32>

# 6. Point capnova.duckdns.org to EC2 IP at duckdns.org

# 7. Launch
docker compose up --build -d

# 8. Tail logs
docker compose logs -f
```

**Keep DuckDNS updated** (if EC2 IP changes on reboot):
```bash
echo "*/5 * * * * curl -s 'https://www.duckdns.org/update?domains=capnova&token=YOUR_TOKEN&ip=' > /dev/null" | crontab -
```

**Switch domain later** — only one line to change:
```bash
# In stack/.env on EC2:
NGINX_HOST=capnova.duckdns.org

# Apply without full rebuild:
docker compose up -d --force-recreate nginx
```

---

## Detection Capabilities

All detectors implement the `Detector` abstract base class (`evaluate(HTTPLogEvent) → list[DetectionAlert]`) and run in sequence per log line.

| Detector | What it catches | Default thresholds | Severity |
|---|---|---|---|
| **BruteForceDetector** | Repeated login failures on `/login` (401/403) | 5 attempts / 300s | High / Medium |
| **RateAbuseDetector** | Abnormally high request volume from one IP | 30 req / 60s | Medium |
| **PayloadDetector** | SQL injection patterns in request targets (UNION SELECT, OR 1=1, DROP TABLE, comment sequences) | Pattern match | High |
| **XSSPayloadDetector** | XSS injection patterns (`<script>`, `onerror`, `javascript:`, `iframe`, `eval`, etc.) — 11 signatures | Pattern match | High |
| **CredentialStuffingDetector** | Auth failures spread across multiple endpoints or paired with user-agent rotation | 10 failures / 300s across 2+ endpoints, or 3+ user agents | High / Medium |
| **PathProbeDetector** | 404 spray (directory guessing) and broad endpoint enumeration | 15 × 404 / 120s; or 20 req to 10+ unique endpoints | Medium |
| **ScrapingDetector** | Systematic API or content enumeration — many successful GETs to distinct endpoints | 50 req to 30+ endpoints / 60s | Medium |
| **UserAgentRotationDetector** | Evasion via user-agent cycling; flags generic bot frameworks (curl, python-requests, wget, go-http-client, okhttp) | 5 distinct UAs / 300s | High / Medium |

### Reputation Scoring

Each alert type carries a score weight. A running score per IP determines the current state:

```
Score     State
──────────────────────────
  < 10    Unknown
  10–24   Suspicious
  25–44   Throttled
  ≥ 70    Blocked → deny rule injected into NGINX
```

Score decays at **8 points per hour**. After a block expires (30 min default), the IP enters a 30-min cooldown before returning to `Unknown`. Every state transition is written to `ip_reputation_transitions` for full audit history.

Alert weights: `payload_sqli=35` · `credential_stuffing=25` · `brute_force=20` · `xss_payload=18` · `path_probe=12` · `scraping=12` · `rate_abuse=10`

### Analyst Actions

From the dashboard, analysts can:
- Mark alerts as **safe**, **malicious**, or leave **unresolved**
- **Manually block** an IP with a custom reason
- **Trust** or **whitelist** known-good IPs to suppress future alerts
- **Unblock** an IP early

---

## Tech Stack

| Layer | Technology |
|---|---|
| API / UI backend | Python 3.12, FastAPI, Uvicorn |
| Database | PostgreSQL 16, psycopg3 |
| Reverse proxy | NGINX 1.27 (Alpine) |
| GeoIP | MaxMind GeoLite2 (City + ASN) |
| Data validation | Pydantic v2 |
| Containerisation | Docker, Docker Compose v2 |
| Frontend | Angular 22 (standalone components, signals), Leaflet — built into the `api` image |

---

## Frontend Development

The UI lives in `frontend/` (Angular 22). Every screen is a standalone component with its own `.html` template, `.ts` logic and `.css` styles; shared colours and primitives are in `frontend/src/styles.css`. The Docker build compiles it automatically, so nothing extra is needed for `docker compose up`.

For live-reload work, run the API on port 8000 (for example with the compose stack) and start the dev server, which proxies `/api` to it:

```bash
cd frontend
npm ci
npm start          # http://localhost:4200
npm test           # unit tests (Vitest)
npm run build      # production bundle → frontend/dist/cappa/browser
```

The UI talks to FastAPI only through JSON endpoints under `/api/`: `/api/auth/*` (login, logout, current user), `/api/ui/dashboard`, `/api/ui/map-points`, `/api/ui/alerts`, and the enforcement actions (`/api/alerts/{id}/status`, `/api/blocked-ips`, `/api/ip-controls`).

---

## Folder Structure

```
cybersiem/
├── data/                        # GeoLite2 .mmdb files (not in git)
├── docker/                      # Dockerfiles and Postgres init SQL
│   ├── api.Dockerfile
│   ├── security_engine.Dockerfile
│   └── postgres/init.sql        # Schema: events, alerts, ip_reputations, transitions
├── src/
│   ├── api/                     # FastAPI app (routes, auth, session management)
│   │   ├── main.py              # 18 route handlers, security headers, RBAC
│   │   ├── auth.py              # PBKDF2 password hashing, HMAC session cookies
│   │   └── schemas.py           # Request / response Pydantic models
│   ├── core/
│   │   ├── http_models.py       # HTTPLogEvent, DetectionAlert dataclasses
│   │   └── geo.py               # GeoIP lookup, IP scope classification
│   └── security_engine/
│       ├── engine.py            # SecurityEngine orchestrator
│       ├── service.py           # LogMonitorService — real-time log tail + dispatch
│       ├── parser.py            # NGINX combined log format parser
│       ├── enforcement.py       # Reputation state machine + NginxBlocklistManager
│       ├── enforcement_service.py # EnforcementService — manual analyst controls
│       ├── repository.py        # PostgreSQL data access layer
│       └── detectors/           # 8 threat detector classes
├── frontend/                    # Angular UI (served by the FastAPI container)
│   └── src/app/
│       ├── core/                # API client, session, guards, shared helpers
│       ├── shared/app-header/   # Top bar (html / ts / css)
│       └── pages/               # One folder per screen, each with .html / .ts / .css
│           ├── login/
│           ├── dashboard/       # + attack-map/ (Leaflet)
│           ├── alerts/
│           └── denied/
├── stack/                       # Docker Compose deployment config
│   ├── docker-compose.yml
│   ├── nginx/nginx.conf.template  # NGINX config — NGINX_HOST substituted at startup
│   ├── .env.example             # Documented template — copy to .env and fill in
│   └── .env                     # Not in git — actual secrets and runtime config
└── tests/                       # Test suite
```

---

## Security Notes

**This repository ships with demo credentials and permissive defaults.** Before any public-facing deployment:

| Setting | Demo value | Production recommendation |
|---|---|---|
| `SIEM_SESSION_SECRET` | short placeholder | `openssl rand -base64 32` |
| `SIEM_ADMIN_PASSWORD` | `Admin123456!!` | 16+ char random password |
| `EXPRESS_ADMIN_PASSWORD` | `password123` | Strong unique password |
| `SECURITY_ADMIN_TOKEN` | `lab-security-token` | `openssl rand -hex 32` |
| `SESSION_SECURE` | `false` | `true` (requires HTTPS first) |
| `SECURITY_LAB_MODE` | `true` | `false` |

Additional recommendations:
- Configure HTTPS (Certbot + Let's Encrypt / DuckDNS) and set `SESSION_SECURE=true`
- Restrict port 22 to your own IP in the EC2 security group
- Rotate all secrets before sharing access with anyone
- The `NGINX_BLOCKLIST_PATH` volume is shared between containers — do not expose it externally

---

## Roadmap

- [ ] HTTPS via Certbot / Let's Encrypt auto-renewal
- [ ] Email / webhook alerting on high-severity detections
- [ ] ML-based anomaly scoring alongside rule-based detectors
- [ ] Multi-tenant / SaaS reverse proxy mode
- [ ] Slack / Discord notification integrations
- [ ] SIEM export (CEF / syslog / JSON stream)
- [ ] Granular RBAC with per-analyst audit logs
- [ ] Alert correlation across multiple IPs (campaign detection)
- [ ] Kubernetes deployment manifests

---

## Portfolio & Resume Value

Cappa demonstrates end-to-end security engineering across several domains:

- **Threat detection design** — 8 independent, composable detectors covering the OWASP Top 10 most common attack patterns, each with tunable thresholds and per-alert confidence scoring
- **Systems programming** — real-time log processing pipeline with zero-copy parsing, sliding-window state across millions of events, and a score-decay model that prevents unbounded memory growth
- **Distributed enforcement** — reputation decisions made in one process propagate to an NGINX gateway in under 2 seconds without a server restart, using a shared volume and a SHA-256 checksum hot-reload loop
- **Secure web application** — HMAC-signed session cookies, PBKDF2 password hashing (260,000 iterations), role-based access control, and security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- **Full-stack delivery** — FastAPI backend, Angular frontend, PostgreSQL schema design with JSONB metadata, and complete Docker Compose orchestration deployable to EC2 in a single command

---

## License

MIT License — see [LICENSE](LICENSE) for details.

> Built as a Final Year Project (2025–2026). Bunhour Long · Student ID: 2023145 · Supervisor: Chandan Mukherjee
