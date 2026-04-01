# Log AI Transfer + Install (CLI Only)

```bash
# ===== 0) SOURCE MACHINE (create zip) =====
cd ~/Desktop
zip -r LogAI.zip LogAI \
  -x "LogAI/backend/.venv/*" \
     "LogAI/frontend/node_modules/*" \
     "LogAI/frontend/.next/*" \
     "LogAI/backend/__pycache__/*" \
     "LogAI/frontend/.turbo/*" \
     "LogAI/.git/*"
```

```bash
# ===== 1) TRANSFER ZIP TO ANOTHER MACHINE =====
# Option A: scp
scp ~/Desktop/LogAI.zip <user>@<target-host>:~/

# Option B: rsync
rsync -avz ~/Desktop/LogAI.zip <user>@<target-host>:~/
```

```bash
# ===== 2) TARGET MACHINE (extract) =====
cd ~
mkdir -p projects
mv LogAI.zip projects/
cd projects
unzip -o LogAI.zip
cd LogAI
```

```bash
# ===== 3) INSTALL SYSTEM DEPENDENCIES (Ubuntu/Debian) =====
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs npm
```

```bash
# ===== 4) BACKEND SETUP =====
cd ~/projects/LogAI/backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

```bash
# ===== 5) EDIT ENV (required values) =====
# Open editor, then set at least:
# OPENAI_API_KEY=...
# OPENAI_MODEL=gpt-5
# OPENAI_FALLBACK_MODEL=gpt-4o
nano ~/projects/LogAI/backend/.env
```

```bash
# ===== 6) START BACKEND =====
cd ~/projects/LogAI/backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```bash
# ===== 7) FRONTEND SETUP (new terminal) =====
cd ~/projects/LogAI/frontend
npm install
```

```bash
# ===== 8) START FRONTEND (new terminal) =====
cd ~/projects/LogAI/frontend
npm run dev -- --hostname 127.0.0.1 --port 3000
```

```bash
# ===== 9) OPEN APP =====
# Browser:
# http://127.0.0.1:3000/login
```

```bash
# ===== 10) FIRST LOGIN =====
# Username: admin
# Password: changeme
```

```bash
# ===== 11) QUICK HEALTH CHECKS =====
curl -s http://127.0.0.1:8000/health
curl -sI http://127.0.0.1:3000/login | head -n 1
```

```bash
# ===== 12) IF PORT ALREADY USED =====
# backend port 8000
lsof -ti:8000 | xargs kill -9 2>/dev/null || true

# frontend port 3000
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
```
