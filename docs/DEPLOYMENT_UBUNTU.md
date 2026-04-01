# Deploying Log AI on Ubuntu Server

This guide explains how to move the Log AI project from your local Mac to a **production Ubuntu server** (Ubuntu 22.04 LTS or 24.04 LTS recommended). It covers two approaches: **Docker Compose** (fastest to operate) and **native systemd + Nginx** (more control).

For a shorter copy/paste setup, use `docs/QUICKSTART_UBUNTU_DOCKER.md`.

---

## Table of Contents

1. [What Changes Between Mac and Server](#1-what-changes-between-mac-and-server)
2. [Server Requirements](#2-server-requirements)
3. [Before You Start: DNS and Firewall](#3-before-you-start-dns-and-firewall)
4. [Option A — Docker Compose (Recommended)](#4-option-a--docker-compose-recommended)
5. [Option B — Native Install (systemd + Nginx)](#5-option-b--native-install-systemd--nginx)
6. [Production Environment Variables](#6-production-environment-variables)
7. [Nginx Reverse Proxy and HTTPS](#7-nginx-reverse-proxy-and-https)
8. [CORS and Frontend API URLs](#8-cors-and-frontend-api-urls)
9. [Background Workers (Celery)](#9-background-workers-celery)
10. [Security Checklist](#10-security-checklist)
11. [Backups and Updates](#11-backups-and-updates)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What Changes Between Mac and Server

| Topic | Local Mac (dev) | Ubuntu Server (production) |
|--------|-----------------|----------------------------|
| Database | SQLite file (`logai.db`) | **PostgreSQL** (recommended) |
| HTTPS | Usually HTTP only | **TLS (Let's Encrypt)** behind Nginx |
| Process | `uvicorn` / `npm run dev` in a terminal | **systemd** or **Docker** (restart on boot) |
| Binding | `127.0.0.1` | Often `0.0.0.0` behind reverse proxy only |
| Secrets | `.env` on disk | Same, but **restrict permissions** (`chmod 600`) |
| Uploads | `backend/uploads/` | Same path; ensure **disk space** and backups |
| AI keys | OpenAI key in `.env` | Same; **never commit** `.env` to Git |

You do **not** need to change application code to deploy on Ubuntu. You change **configuration**, **how processes run**, and **how traffic reaches the app** (Nginx + HTTPS).

---

## 2. Server Requirements

### Minimum (small team / demos)

- **CPU:** 2 vCPU  
- **RAM:** 4 GB (Elasticsearch optional; without ES, 4 GB is enough)  
- **Disk:** 40 GB SSD (more if you store large log uploads)  
- **OS:** Ubuntu 22.04 or 24.04 LTS  

### Recommended (production)

- **CPU:** 4 vCPU  
- **RAM:** 8 GB (if you enable Elasticsearch, plan 8+ GB)  
- **Disk:** 100 GB+ SSD  
- **Network:** Static public IP, domain name pointed to the server  

### Software you will install (depending on path)

- **Docker path:** Docker Engine + Docker Compose plugin  
- **Native path:** Python 3.12+, Node.js 20+, Nginx, PostgreSQL, Redis (optional), Certbot  

---

## 3. Before You Start: DNS and Firewall

1. **Create DNS records** (at your registrar or cloud DNS):
   - `logai.example.com` → A record → your server’s public IP (for the web UI)
   - Optionally `api.example.com` → same IP (if you split frontend and API on different hostnames)

2. **On the server**, allow SSH and (later) HTTP/HTTPS:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

Do **not** expose PostgreSQL (5432) or Redis (6379) to the public internet. Keep them on `127.0.0.1` or a private network only.

---

## 4. Option A — Docker Compose (Recommended)

This matches the `docker/` folder in the repo: Postgres, Redis, optional Elasticsearch, backend, Celery worker, frontend.

### 4.1 Install Docker on Ubuntu

```bash
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
# Log out and back in for group to apply, or use: newgrp docker
```

### 4.2 Copy the project to the server

From your Mac (replace user and host):

```bash
rsync -avz --exclude node_modules --exclude .venv --exclude .next --exclude __pycache__ \
  /path/to/LogAI/ user@YOUR_SERVER_IP:/opt/logai/
```

Or clone from Git if the project is in a repository:

```bash
sudo mkdir -p /opt/logai
sudo chown "$USER:$USER" /opt/logai
cd /opt/logai
git clone YOUR_REPO_URL .
```

### 4.3 Configure production `.env`

On the server:

```bash
cd /opt/logai/backend
cp .env.example .env
nano .env   # or vim
```

Set at least:

```env
DEBUG=false

# PostgreSQL — must match docker-compose postgres service
DATABASE_URL=postgresql+asyncpg://logai:CHANGE_ME_STRONG_PASSWORD@postgres:5432/logai
DATABASE_URL_SYNC=postgresql://logai:CHANGE_ME_STRONG_PASSWORD@postgres:5432/logai

REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

AI_PROVIDER=openai
OPENAI_API_KEY=sk-proj-your-key-here

# CORS: your real frontend origin(s)
CORS_ORIGINS=["https://logai.example.com","http://localhost:3000"]

SECRET_KEY=PASTE_OUTPUT_OF_openssl_rand_hex_32
```

**Important:** Change `POSTGRES_PASSWORD` in `docker/docker-compose.yml` to match `CHANGE_ME_STRONG_PASSWORD`, or override with env files / secrets. The default `logai/logai` password is **not** safe for production.

Generate a secret:

```bash
openssl rand -hex 32
```

### 4.4 Build and start

```bash
cd /opt/logai/docker
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f backend --tail 50
```

- API: `http://SERVER_IP:8000` (bind only to localhost in production and put Nginx in front — see [Section 7](#7-nginx-reverse-proxy-and-https)).
- Frontend container may listen on port 3000 per `docker-compose.yml`.

For production, **do not** leave ports 8000/3000 open to the world. Put **Nginx** on 80/443 and proxy to the containers on `127.0.0.1`.

### 4.5 Run database migrations (if you add Alembic later)

Currently the app uses `create_all` on startup. For production you may add Alembic migrations; until then, tables are created automatically on first boot.

---

## 5. Option B — Native Install (systemd + Nginx)

Use this if you prefer not to use Docker.

### 5.1 System packages

```bash
sudo apt install -y python3.12 python3.12-venv python3-pip build-essential \
  nginx certbot python3-certbot-nginx postgresql postgresql-contrib redis-server git
```

Install Node.js 20 LTS (example using NodeSource):

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 5.2 PostgreSQL

```bash
sudo -u postgres psql <<'SQL'
CREATE USER logai WITH PASSWORD 'STRONG_PASSWORD_HERE';
CREATE DATABASE logai OWNER logai;
GRANT ALL PRIVILEGES ON DATABASE logai TO logai;
SQL
```

### 5.3 Application user and directories

```bash
sudo useradd -r -s /bin/bash -d /opt/logai -m logai 2>/dev/null || true
sudo mkdir -p /opt/logai
sudo chown "$USER:$USER" /opt/logai
# Deploy code to /opt/logai (rsync or git)
```

### 5.4 Backend (venv + systemd)

```bash
cd /opt/logai/backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Create `/etc/systemd/system/logai-backend.service`:

```ini
[Unit]
Description=Log AI FastAPI backend
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=logai
Group=logai
WorkingDirectory=/opt/logai/backend
EnvironmentFile=/opt/logai/backend/.env
ExecStart=/opt/logai/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2 --timeout-keep-alive 300
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Adjust `User`/`Group` and paths if you run as a different user.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now logai-backend
sudo systemctl status logai-backend
```

### 5.5 Frontend (build + static or Node)

**Production build (recommended):**

```bash
cd /opt/logai/frontend
npm ci
# Set build-time env for API URL (see Section 8)
export NEXT_PUBLIC_BACKEND_URL="https://logai.example.com"
export NEXT_PUBLIC_API_URL=""
npm run build
```

Run with systemd, listening on `127.0.0.1:3000`:

```ini
[Unit]
Description=Log AI Next.js
After=network.target

[Service]
Type=simple
User=logai
Group=logai
WorkingDirectory=/opt/logai/frontend
Environment=NEXT_PUBLIC_BACKEND_URL=https://logai.example.com
Environment=NODE_ENV=production
ExecStart=/usr/bin/npm run start -- -p 3000 -H 127.0.0.1
Restart=always

[Install]
WantedBy=multi-user.target
```

Or use **Nginx** to serve the Next.js app via `next start` behind reverse proxy only.

### 5.6 Celery worker (optional, for async uploads)

```ini
[Unit]
Description=Log AI Celery worker
After=network.target redis-server.service postgresql.service

[Service]
Type=simple
User=logai
Group=logai
WorkingDirectory=/opt/logai/backend
EnvironmentFile=/opt/logai/backend/.env
ExecStart=/opt/logai/backend/.venv/bin/celery -A app.workers.celery_app worker --loglevel=info --concurrency=2
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## 6. Production Environment Variables

### Backend (`/opt/logai/backend/.env`)

| Variable | Production notes |
|----------|------------------|
| `DEBUG` | `false` |
| `DATABASE_URL` | `postgresql+asyncpg://user:pass@127.0.0.1:5432/logai` (or Docker hostname `postgres`) |
| `DATABASE_URL_SYNC` | Same DB, sync driver for Celery |
| `UPLOAD_DIR` | Absolute path e.g. `/opt/logai/backend/uploads` |
| `MAX_UPLOAD_SIZE_MB` | Adjust to your disk and policy |
| `OPENAI_API_KEY` | Required for AI features |
| `CORS_ORIGINS` | JSON list of **exact** frontend origins, e.g. `["https://logai.example.com"]` |
| `SECRET_KEY` | Random 32+ bytes, not the default string |

### Frontend build / runtime

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_BACKEND_URL` | **Full URL of the FastAPI API** as seen by the browser, e.g. `https://logai.example.com` if Nginx serves API on same host, or `https://api.example.com` if split. Used for **large file uploads** (direct to backend). |
| `NEXT_PUBLIC_API_URL` | Usually **empty** in production if the UI and API share the same origin and Nginx routes `/api` to FastAPI. If empty, relative `/api` calls go to the same hostname. |

Example: single domain, Nginx routes `/` → Next.js and `/api` → Uvicorn:

- Set `NEXT_PUBLIC_BACKEND_URL=https://logai.example.com` so uploads go to `https://logai.example.com/api/...`.
- Configure Nginx `location /api/` → `proxy_pass http://127.0.0.1:8000/api/;`

---

## 7. Nginx Reverse Proxy and HTTPS

### 7.1 Example: one hostname, UI + API

Create `/etc/nginx/sites-available/logai`:

```nginx
limit_req_zone $binary_remote_addr zone=logai_limit:10m rate=10r/s;

upstream logai_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

upstream logai_frontend {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 80;
    server_name logai.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name logai.example.com;

    ssl_certificate     /etc/letsencrypt/live/logai.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/logai.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    client_max_body_size 500M;
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;
    send_timeout 600s;

    location /api/ {
        limit_req zone=logai_limit burst=20 nodelay;
        proxy_pass http://logai_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /docs {
        proxy_pass http://logai_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /openapi.json {
        proxy_pass http://logai_backend;
    }

    location /health {
        proxy_pass http://logai_backend;
    }

    location / {
        proxy_pass http://logai_frontend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and test:

```bash
sudo ln -sf /etc/nginx/sites-available/logai /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7.2 Let’s Encrypt (Certbot)

```bash
sudo certbot --nginx -d logai.example.com
```

Renewal is installed as a cron/timer automatically.

---

## 8. CORS and Frontend API URLs

FastAPI reads `CORS_ORIGINS` from `.env`. It must include your **browser origin**:

```env
CORS_ORIGINS=["https://logai.example.com"]
```

If the frontend calls the API at `https://logai.example.com/api/...`, that origin must be allowed.

The frontend (`src/lib/api.ts`) uses:

- **`NEXT_PUBLIC_BACKEND_URL`** for **multipart uploads** (large files) — must be the public API base URL.
- **Relative `/api`** for JSON GETs when `NEXT_PUBLIC_API_URL` is empty — works when Nginx serves the same host.

After changing env vars, **rebuild** the frontend (`npm run build`) because `NEXT_PUBLIC_*` is embedded at build time.

---

## 9. Background Workers (Celery)

- Required for **`POST /api/upload-log`** (async pipeline).
- **Not** required if users only use **`POST /api/dev/analyze`** (sync).
- Production: run Redis + Celery worker with the same `.env` as the API (same `DATABASE_URL`, `CELERY_BROKER_URL`).

---

## 10. Security Checklist

- [ ] Change all default passwords (Postgres, Redis if exposed, `SECRET_KEY`).
- [ ] `chmod 600 /opt/logai/backend/.env`
- [ ] Run backend and DB on `127.0.0.1`; only Nginx on `0.0.0.0:443`.
- [ ] Enable HTTPS; redirect HTTP → HTTPS.
- [ ] Firewall: only 22, 80, 443 (and restrict SSH by IP if possible).
- [ ] Rotate OpenAI keys if ever leaked; use a dedicated key per environment.
- [ ] Keep Ubuntu and Docker images updated (`apt upgrade`, `docker compose pull`).
- [ ] Optional: fail2ban for SSH, rate limiting on Nginx (see `limit_req` above).

---

## 11. Backups and Updates

### Backups

- **PostgreSQL:** `pg_dump` daily cron to object storage or another server.
- **Uploads directory:** `rsync` or snapshot the volume containing `/opt/logai/backend/uploads`.
- **`.env`:** store secrets in a password manager; backup encrypted.

### Updates

```bash
cd /opt/logai
git pull
cd backend && source .venv/bin/activate && pip install -r requirements.txt
cd ../frontend && npm ci && npm run build
sudo systemctl restart logai-backend logai-frontend
# or: docker compose build && docker compose up -d
```

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|--------|----------------|-----|
| 502 Bad Gateway | Backend not running or wrong upstream port | `systemctl status logai-backend`, check Nginx `error.log` |
| CORS error in browser | Origin not in `CORS_ORIGINS` | Add `https://your-domain` to `.env`, restart API |
| Large upload fails | Body size / timeout | `client_max_body_size` and `proxy_read_timeout` in Nginx |
| AI returns error | Missing or invalid `OPENAI_API_KEY` | Check `.env`, billing, and API quotas |
| Works on Mac, fails on Ubuntu | Wrong `DATABASE_URL` or firewall | Test `psql` from app host; open only localhost to DB |

---

## Quick Reference: Ports

| Service | Default | Expose publicly? |
|---------|---------|------------------|
| Nginx HTTPS | 443 | Yes |
| Nginx HTTP | 80 | Yes (redirect to HTTPS) |
| Uvicorn | 8000 | **No** (127.0.0.1 only) |
| Next.js | 3000 | **No** (127.0.0.1 only) |
| PostgreSQL | 5432 | **No** |
| Redis | 6379 | **No** |

---

For architecture and feature overview, see the main [README.md](../README.md).
