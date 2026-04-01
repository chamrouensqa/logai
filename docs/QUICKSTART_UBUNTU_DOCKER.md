# Ubuntu Quickstart (Docker Compose)

This is the fastest way to run Log AI on an Ubuntu local server with Docker Compose.

## 1) Install Docker + Compose plugin

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
newgrp docker
docker --version
docker compose version
```

## 2) Prepare project files

Copy or clone the project to Ubuntu, then:

```bash
cd /opt/logai
cp docker/.env.ubuntu.example docker/.env.ubuntu
cp backend/.env.example backend/.env
```

## 3) Set required environment values

Edit `docker/.env.ubuntu`:

```env
POSTGRES_DB=logai
POSTGRES_USER=logai
POSTGRES_PASSWORD=use_a_strong_password_here
SERVER_HOST_IP=YOUR_UBUNTU_SERVER_IP
```

Edit `backend/.env` and set at least:

```env
AI_PROVIDER=openai
OPENAI_API_KEY=sk-proj-your-real-key
SECRET_KEY=run_openssl_rand_hex_32_and_paste_here
ALPHA_ADMIN_USERNAME=admin
ALPHA_ADMIN_PASSWORD=change_me_now
CORS_ORIGINS=["http://YOUR_UBUNTU_SERVER_IP:3000","http://localhost:3000","http://127.0.0.1:3000"]
```

Generate a secure secret:

```bash
openssl rand -hex 32
```

## 4) Start everything

```bash
cd /opt/logai/docker
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml up -d --build
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml ps
```

## 5) Open the app

- Frontend: `http://YOUR_UBUNTU_SERVER_IP:3000`
- Backend docs: `http://YOUR_UBUNTU_SERVER_IP:8000/docs`

Default first login:

- Username: `admin`
- Password: value from `ALPHA_ADMIN_PASSWORD`

## 6) Useful commands

```bash
cd /opt/logai/docker

# View logs
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml logs -f --tail=100

# Restart services
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml restart

# Stop services
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml down

# Stop and remove volumes (DANGER: deletes DB data)
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml down -v
```

## 7) Common fixes

- If frontend loads but API fails: check `CORS_ORIGINS` in `backend/.env`, then restart.
- If upload fails from another machine: verify `SERVER_HOST_IP` in `docker/.env.ubuntu`.
- If containers fail to start: run `docker compose ... logs` and check first error.
