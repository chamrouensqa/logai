# Deploying Log AI on AWS

This guide covers production deployment of Log AI on AWS with a practical baseline:

- **EC2** for app runtime (frontend + backend + optional Redis/Celery worker)
- **RDS PostgreSQL** for database
- **(Optional) ElastiCache Redis** for Celery broker/result backend
- **Route 53 + ACM + Nginx** for HTTPS and domain routing

---

## 1) Reference Architecture

### Minimum recommended

- 1x EC2 instance (Ubuntu 22.04/24.04, t3.medium or larger)
- 1x RDS PostgreSQL (db.t4g.micro+ for small workloads)
- Security Group rules:
  - Inbound to EC2: `22` (restricted), `80`, `443`
  - Inbound to RDS: `5432` **from EC2 security group only**

### Optional

- ElastiCache Redis (for async `upload-log` + Celery worker)
- S3 for backups of uploaded logs
- CloudWatch agent for logs/metrics

---

## 2) Provision AWS Resources

### 2.1 EC2

1. Launch Ubuntu EC2 in a VPC/subnet with internet egress (NAT/IGW).
2. Attach an IAM role (optional but recommended for S3/CloudWatch access).
3. Assign Security Group:
   - `22` from your office/home IP only
   - `80` from `0.0.0.0/0`
   - `443` from `0.0.0.0/0`

### 2.2 RDS PostgreSQL

1. Create RDS PostgreSQL (same VPC as EC2).
2. Security Group: allow `5432` inbound from EC2 SG only.
3. Record endpoint, db name, username, password.

### 2.3 Domain + TLS

1. Point `A`/`ALIAS` record in Route 53 to EC2 public IP.
2. We use Let's Encrypt via Certbot on the EC2 host in this guide.

---

## 3) Install Runtime on EC2

SSH to EC2:

```bash
ssh -i /path/to/key.pem ubuntu@<EC2_PUBLIC_IP>
```

Install packages:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-venv python3-pip nodejs npm nginx certbot python3-certbot-nginx
```

> If your Ubuntu repo node version is too old, install Node 20+ via NodeSource.

---

## 4) Deploy Project Code

```bash
sudo mkdir -p /opt/logai
sudo chown -R ubuntu:ubuntu /opt/logai
cd /opt/logai
# Option A
git --version
ssh-keygen -t ed25519 -C "ec2-server"
cat ~/.ssh/id_ed25519.pub
cd path/to/your/project
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
ssh -T git@github.com
git clone git@github.com:chamrouensqa/logai.git .
ls


# Option B: rsync from local machine: 👉 GitHub → Settings → SSH and GPG keys → New SSH Key
```

---

## 5) Configure Backend

```bash
cd /opt/logai/backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Edit `backend/.env`:

```env
DEBUG=false

# RDS PostgreSQL
DATABASE_URL=postgresql+asyncpg://<DB_USER>:<DB_PASS>@<RDS_ENDPOINT>:5432/<DB_NAME>
DATABASE_URL_SYNC=postgresql://<DB_USER>:<DB_PASS>@<RDS_ENDPOINT>:5432/<DB_NAME>

# AI
AI_PROVIDER=openai
OPENAI_API_KEY=<YOUR_KEY>
OPENAI_MODEL=gpt-5
OPENAI_FALLBACK_MODEL=gpt-4o

# Auth / sessions
SECRET_KEY=<openssl rand -hex 32 output>
ALPHA_ADMIN_USERNAME=admin
ALPHA_ADMIN_PASSWORD=<strong-temp-password>

# CORS
CORS_ORIGINS=["https://logai.example.com","http://127.0.0.1:3000","http://localhost:3000"]
```

Generate secret:

```bash
openssl rand -hex 32
```

---

## 6) Configure Frontend

```bash
cd /opt/logai/frontend
npm ci
```

Build-time env:

```bash
export NEXT_PUBLIC_BACKEND_URL="https://logai.example.com"
export NEXT_PUBLIC_API_URL=""
npm run build
```

---

## 7) Run as systemd Services

### 7.1 Backend service

Create `/etc/systemd/system/logai-backend.service`:

```ini
[Unit]
Description=Log AI Backend
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/logai/backend
EnvironmentFile=/opt/logai/backend/.env
ExecStart=/opt/logai/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2 --timeout-keep-alive 300
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 7.2 Frontend service

Create `/etc/systemd/system/logai-frontend.service`:

```ini
[Unit]
Description=Log AI Frontend
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/logai/frontend
Environment=NODE_ENV=production
Environment=NEXT_PUBLIC_BACKEND_URL=https://logai.example.com
ExecStart=/usr/bin/npm run start -- --hostname 127.0.0.1 --port 3000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now logai-backend logai-frontend
sudo systemctl status logai-backend logai-frontend
```

---

## 8) Nginx + HTTPS

Create `/etc/nginx/sites-available/logai`:

```nginx
server {
    listen 80;
    server_name logai.example.com;
    client_max_body_size 500M;

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable site:

```bash
sudo ln -sf /etc/nginx/sites-available/logai /etc/nginx/sites-enabled/logai
sudo nginx -t
sudo systemctl reload nginx
```

Issue TLS cert:

```bash
sudo certbot --nginx -d logai.example.com
```

---

## 9) Optional: Celery + Redis

If you need async `/api/upload-log`:

- Use ElastiCache Redis endpoint:

```env
REDIS_URL=redis://<REDIS_ENDPOINT>:6379/0
CELERY_BROKER_URL=redis://<REDIS_ENDPOINT>:6379/1
CELERY_RESULT_BACKEND=redis://<REDIS_ENDPOINT>:6379/2
```

- Create `logai-celery.service`:

```ini
[Unit]
Description=Log AI Celery Worker
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/logai/backend
EnvironmentFile=/opt/logai/backend/.env
ExecStart=/opt/logai/backend/.venv/bin/celery -A app.workers.celery_app worker --loglevel=info --concurrency=2
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## 10) Validation Checklist

```bash
curl -s https://logai.example.com/health
curl -s https://logai.example.com/api/jobs?page=1&page_size=1 -H "Authorization: Bearer <token>"
```

UI checks:

1. Login page loads.
2. Admin can create/delete user.
3. User can change own password in Account page.
4. Upload + dashboard + investigate work.

---

## 11) Security Hardening

- Restrict SSH source IPs.
- Use strong random `SECRET_KEY`.
- Store `.env` with restrictive permissions:
  - `chmod 600 /opt/logai/backend/.env`
- Rotate API keys if exposed.
- Keep EC2 patched (`apt upgrade`) and monitor CloudWatch logs.
- Keep RDS private (no public access).

---

## 12) Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| API unreachable from UI | Nginx or backend not running | `systemctl status logai-backend nginx` |
| CORS error | `CORS_ORIGINS` missing domain | add exact origin, restart backend |
| 502 from Nginx | upstream down | check `journalctl -u logai-backend` |
| Upload fails large file | body limit/timeout | `client_max_body_size`, `proxy_read_timeout` |
| AI fallback message | outbound connectivity/rate limits | verify OpenAI key, egress, retry |

---

For Ubuntu-only deployment details, see `docs/DEPLOYMENT_UBUNTU.md`.
