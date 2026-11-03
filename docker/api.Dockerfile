# ── Angular UI (frontend/) ───────────────────────────────────────────────────
FROM node:25-slim AS frontend

ENV NG_CLI_ANALYTICS=false

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# ── FastAPI ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt

COPY src ./src
# Served by src/api/main.py (FRONTEND_DIST_DIR default).
COPY --from=frontend /frontend/dist/cappa/browser ./frontend/dist/cappa/browser

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
