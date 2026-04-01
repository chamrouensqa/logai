# Log AI — AI-Powered Log Investigation Platform

## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Problem Statement](#2-problem-statement)
- [3. Solution](#3-solution)
- [4. System Architecture](#4-system-architecture)
- [5. Features](#5-features)
- [6. Technology Stack](#6-technology-stack)
- [7. Project Structure](#7-project-structure)
- [8. Getting Started](#8-getting-started)
- [9. Configuration](#9-configuration)
- [10. API Reference](#10-api-reference)
- [11. Log Parsing Engine](#11-log-parsing-engine)
- [12. Detection Engine](#12-detection-engine)
- [13. AI Analysis Layer](#13-ai-analysis-layer)
- [14. Frontend Pages](#14-frontend-pages)
- [15. Database Schema](#15-database-schema)
- [16. Background Processing](#16-background-processing)
- [17. Deployment](#17-deployment) — see [Ubuntu](docs/DEPLOYMENT_UBUNTU.md) and [AWS](docs/DEPLOYMENT_AWS.md) guides
- [18. Future Roadmap](#18-future-roadmap)

---

## 1. Project Overview

**Log AI** is a scalable, production-grade security log analysis platform that combines automated threat detection with AI-powered investigation capabilities. It functions as a **lightweight AI-SIEM** (Security Information and Event Management) system designed for Security Operations Center (SOC) environments.

Instead of security teams manually reading through thousands of log lines, Log AI automates the entire workflow:

```
Upload logs → Auto-parse → Detect threats → AI explains findings → Team takes action
```

The platform accepts log files in multiple formats (auth logs, web server logs, firewall logs, JSON application logs, Windows Event logs), automatically detects the format, parses structured fields, runs security detection rules to find suspicious activity, and then uses AI (OpenAI GPT-4o, Anthropic Claude, or local LLMs) to generate human-readable security assessments and answer investigation questions.

---

## 2. Problem Statement

Security teams in organizations face several critical challenges:

- **Log Volume**: Modern systems generate millions of log entries daily across servers, firewalls, applications, and cloud services. Manually reviewing these is impractical.
- **Multiple Formats**: Logs come in dozens of different formats (syslog, JSON, Apache/Nginx, Windows Events, firewall logs), requiring different parsing approaches.
- **Expertise Gap**: Interpreting security events requires deep expertise. Not every team has senior analysts available 24/7.
- **Response Time**: The time between a breach occurring and detection (dwell time) averages 204 days. Faster detection means less damage.
- **Alert Fatigue**: Existing tools generate too many alerts without context, leading analysts to miss real threats.

---

## 3. Solution

Log AI addresses these challenges through a six-layer architecture:

| Layer | Purpose |
|-------|---------|
| **Frontend Interface** | Upload logs, view dashboards, investigate incidents |
| **API Backend** | Handle requests, manage jobs, coordinate analysis pipeline |
| **Log Processing Engine** | Auto-detect format, parse structured fields from raw log lines |
| **Detection Engine** | Apply security rules to find brute force, web attacks, API abuse, etc. |
| **AI Analysis Layer** | Generate executive summaries, risk ratings, and answer investigation questions |
| **Data Storage** | Persist parsed entries, alerts, investigation chats, and job metadata |

The key differentiator is combining **rule-based detection** (fast, deterministic, no false negatives for known patterns) with **AI-powered analysis** (contextual understanding, natural language explanations, recommended actions). The detection engine finds the threats; the AI explains what they mean and what to do about them.

---

## 4. System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Next.js 15)                     │
│                                                                  │
│   ┌─────────┐ ┌───────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ │
│   │ Upload  │ │ Dashboard │ │ Alerts │ │ Timeline │ │ AI     │ │
│   │  Page   │ │   Page    │ │  Page  │ │   Page   │ │ Invest │ │
│   └────┬────┘ └─────┬─────┘ └───┬────┘ └────┬─────┘ └───┬────┘ │
│        │             │           │            │           │      │
│        └─────────────┴───────────┴────────────┴───────────┘      │
│                              │ REST API                          │
└──────────────────────────────┼───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                      BACKEND (FastAPI)                            │
│                                                                  │
│  ┌──────────────┐  ┌───────────────┐  ┌───────────────────────┐ │
│  │ Upload Route │  │ Analysis Route│  │ Investigation Route   │ │
│  │ POST /upload │  │ GET /analysis │  │ POST /ask-ai          │ │
│  └──────┬───────┘  └───────┬───────┘  └───────────┬───────────┘ │
│         │                  │                      │              │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌───────────▼───────────┐ │
│  │   Parsing    │  │  Detection   │  │    AI Analyzer        │ │
│  │   Engine     │  │   Engine     │  │  (OpenAI / Claude /   │ │
│  │              │  │              │  │   Local LLM)          │ │
│  │ • Auth       │  │ • Brute Force│  │                       │ │
│  │ • Nginx      │  │ • Suspicious │  │ • Summaries           │ │
│  │ • JSON       │  │   Login      │  │ • Risk Classification │ │
│  │ • Firewall   │  │ • Web Attack │  │ • MITRE ATT&CK        │ │
│  │ • Auto-detect│  │ • API Abuse  │  │ • Chat Investigation  │ │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬───────────┘ │
│         │                  │                      │              │
│         └──────────────────┴──────────────────────┘              │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
     ┌────────────┐  ┌────────────┐  ┌────────────────┐
     │  SQLite /  │  │   Redis    │  │ Elasticsearch  │
     │ PostgreSQL │  │  (Queue)   │  │  (Search)      │
     │            │  │            │  │  [Optional]    │
     │ • Jobs     │  │ • Celery   │  │                │
     │ • Entries  │  │   tasks    │  │ • Full-text    │
     │ • Alerts   │  │ • Cache    │  │   log search   │
     │ • Chats    │  │            │  │                │
     └────────────┘  └────────────┘  └────────────────┘
```

### Data Flow

1. User uploads a log file through the frontend
2. Frontend sends the file directly to the FastAPI backend (bypasses Next.js proxy for large files)
3. Backend saves the file to disk and creates an analysis job record
4. **Parsing Engine** auto-detects the log format and extracts structured fields (IP, timestamp, username, endpoint, status code, etc.)
5. Parsed entries are batch-inserted into the database (2,000 rows per batch for performance)
6. **Detection Engine** runs all security rules against the parsed entries and generates alerts
7. **AI Analyzer** sends a summary of findings to OpenAI/Claude and receives a security assessment
8. Results are saved and the frontend displays them across Dashboard, Alerts, Timeline, and Investigation pages

---

## 5. Features

### 5.1 Multi-Format Log Parsing

The parsing engine automatically detects and parses five major log formats:

| Format | Example Source | Fields Extracted |
|--------|---------------|------------------|
| **Auth / Syslog** | Linux `auth.log`, `secure` | timestamp, hostname, service, username, source IP, event type |
| **Nginx / Apache** | Web server access logs (Combined Log Format) | IP, user, timestamp, method, endpoint, status code, size, user agent |
| **Nginx Error** | Web server error logs | timestamp, level, PID, message, client IP |
| **JSON / JSONL** | Application logs, Docker logs, Windows Event logs | Auto-maps standard field names (timestamp, ip, user, message, etc.) |
| **Firewall** | iptables, UFW, PF (BSD) logs | source/dest IP, ports, protocol, action (block/allow) |

The engine uses a **confidence scoring** system — each parser scores sample lines from 0.0 to 1.0, and the highest-scoring parser is selected. You can also provide a hint to override auto-detection.

### 5.2 Automated Threat Detection

Seven detection rules run against every uploaded log:

| Detection | What It Finds | Threshold |
|-----------|---------------|-----------|
| **Brute Force** | Many failed logins from one IP in a short window | >10 failures in 5 minutes |
| **Suspicious Login** | Privileged account login outside working hours (6am-10pm) | Any admin/root login outside hours |
| **Credential Compromise** | Successful login following a streak of failures | 5+ failures then success for same user |
| **Privilege Escalation** | Multiple privileged accounts accessed from one IP | 2+ admin accounts from same source |
| **Web Attacks** | SQL injection, XSS, path traversal, command injection patterns in URLs | Regex pattern matching |
| **Vulnerability Scanning** | Scanner user-agents (Nikto, sqlmap, Burp, etc.) and probing paths (`.env`, `.git`, `wp-admin`) | Known scanner signatures |
| **API Abuse** | Excessive request rates or data downloads from single IP | >100 req/min or >50 MB downloaded |

Each alert includes: severity (critical/high/medium/low/info), description, source IP, target account, evidence (JSON), and recommended remediation actions.

### 5.3 AI-Powered Security Analysis

The AI layer serves two functions:

**Automated Summary Generation** — After detection completes, the AI receives the full analysis context and produces:
- Executive summary (2-3 sentences for management)
- Technical summary (detailed analysis for SOC analysts)
- Risk level classification (critical/high/medium/low/info)
- Key findings list
- Attack narrative (step-by-step what the attacker did)
- Indicators of Compromise (IoCs)
- MITRE ATT&CK technique mapping
- Recommended remediation actions

**Interactive Investigation Chat** — Users can ask natural language questions about the logs:
- "Did any brute force attack happen?"
- "Which IP is most suspicious and why?"
- "Was there a successful login after the failed attempts?"
- "Summarize this log for management."
- "What MITRE ATT&CK techniques were used?"

The chat maintains conversation history per job, so follow-up questions have full context.

### 5.4 Security Dashboard

Real-time visualization of analysis results:
- **Stat cards**: Total events, alerts, unique IPs, failed logins, error rate
- **Area chart**: Events distributed by hour of day
- **Pie chart**: Alert severity distribution
- **Bar charts**: Top source IPs, top targeted endpoints, alerts by type
- **Table**: Top targeted user accounts

### 5.5 Event Timeline

Chronological visualization of security-relevant events with:
- Color-coded severity indicators on the timeline
- Filterable by event type
- Shows source IP, username, and description for each event
- Includes both log events and generated alerts

### 5.6 Large File Support

Optimized for production-scale log files:
- Streaming file upload (1 MB chunks, up to 500 MB)
- Streaming line-by-line parsing (never loads entire file into memory)
- Batch database inserts (2,000 rows per commit)
- Detection runs on up to 200,000 entries in memory
- Raw line storage capped at 2,000 characters per entry
- Successfully tested with 239 MB / 647,768 line files

---

## 6. Technology Stack

### Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.12+ | Core language |
| **FastAPI** | 0.115.6 | Async web framework with auto-generated OpenAPI docs |
| **SQLAlchemy** | 2.0.36 | ORM with async support |
| **Pydantic** | 2.10.4 | Request/response validation and settings management |
| **aiosqlite** | 0.22+ | Async SQLite driver (development) |
| **asyncpg** | 0.30.0 | Async PostgreSQL driver (production) |
| **Celery** | 5.4.0 | Distributed task queue for background processing |
| **Redis** | 5.2.1 | Message broker for Celery and caching |
| **OpenAI SDK** | 1.58.1 | GPT-4o integration |
| **Anthropic SDK** | 0.42.0 | Claude integration |
| **python-dateutil** | 2.9.0 | Flexible date/time parsing |
| **Uvicorn** | 0.34.0 | ASGI server |

### Frontend

| Technology | Version | Purpose |
|------------|---------|---------|
| **Next.js** | 15.1+ | React framework with SSR and API rewrites |
| **React** | 19.0 | UI library |
| **TypeScript** | 5.7+ | Type-safe JavaScript |
| **TailwindCSS** | 3.4 | Utility-first CSS framework |
| **Recharts** | 2.15 | Chart library (area, bar, pie charts) |
| **clsx** | 2.1 | Conditional CSS class utility |
| **date-fns** | 4.1 | Date formatting |

### Infrastructure

| Technology | Purpose |
|------------|---------|
| **SQLite** | Development database (zero configuration) |
| **PostgreSQL 16** | Production database |
| **Redis 7** | Task queue broker and caching |
| **Elasticsearch 8** | Full-text log search (optional) |
| **Docker Compose** | Container orchestration |

---

## 7. Project Structure

```
LogAI/
│
├── backend/                          # Python FastAPI backend
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                   # FastAPI application entry point
│   │   │
│   │   ├── api/
│   │   │   └── routes/
│   │   │       ├── upload.py         # POST /upload-log (async with Celery)
│   │   │       ├── analyze_sync.py   # POST /dev/analyze (sync, no Celery needed)
│   │   │       ├── analysis.py       # GET /analysis, /jobs, /logs, /alerts, /timeline, /dashboard
│   │   │       └── investigation.py  # POST /ask-ai, GET /chat-history
│   │   │
│   │   ├── core/
│   │   │   ├── config.py            # Settings from environment / .env file
│   │   │   └── database.py          # SQLAlchemy async engine and session management
│   │   │
│   │   ├── models/
│   │   │   └── models.py            # AnalysisJob, LogEntry, Alert, InvestigationChat
│   │   │
│   │   ├── schemas/
│   │   │   └── schemas.py           # Pydantic request/response models
│   │   │
│   │   ├── services/
│   │   │   ├── ai_analyzer.py       # AI integration (OpenAI, Anthropic, local LLM)
│   │   │   ├── dashboard_service.py  # Dashboard statistics aggregation queries
│   │   │   │
│   │   │   ├── parsers/             # Log format parsers
│   │   │   │   ├── base.py          # BaseLogParser ABC and ParsedLogEntry dataclass
│   │   │   │   ├── engine.py        # LogParsingEngine (auto-detection + orchestration)
│   │   │   │   ├── auth_parser.py   # Linux auth.log / syslog parser
│   │   │   │   ├── nginx_parser.py  # Nginx/Apache access + error log parsers
│   │   │   │   ├── json_parser.py   # JSON/JSONL log parser (Docker, app logs, Windows Events)
│   │   │   │   └── firewall_parser.py # iptables, UFW, PF firewall log parser
│   │   │   │
│   │   │   └── detectors/           # Security detection rules
│   │   │       ├── base.py          # BaseDetector ABC and DetectionResult dataclass
│   │   │       ├── engine.py        # DetectionEngine (runs all detectors)
│   │   │       ├── brute_force.py   # Brute force login detection
│   │   │       ├── suspicious_login.py # Off-hours admin login, credential compromise
│   │   │       ├── web_attack.py    # SQLi, XSS, path traversal, command injection
│   │   │       └── api_abuse.py     # Rate abuse, data exfiltration, error flooding
│   │   │
│   │   └── workers/
│   │       ├── celery_app.py        # Celery application configuration
│   │       └── tasks.py             # Background analysis task
│   │
│   ├── sample_logs/                  # Sample log files for testing
│   │   ├── auth.log                 # Simulated brute force attack scenario
│   │   └── nginx_access.log         # Simulated web attack scenario
│   │
│   ├── tests/                       # Test directory
│   ├── uploads/                     # Uploaded log files (gitignored)
│   ├── requirements.txt             # Python dependencies
│   ├── .env.example                 # Environment variable template
│   └── .env                         # Active environment config (gitignored)
│
├── frontend/                         # Next.js React frontend
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx           # Root layout with sidebar navigation
│   │   │   ├── globals.css          # Global styles, TailwindCSS, component classes
│   │   │   ├── page.tsx             # Upload page (drag & drop, analysis trigger)
│   │   │   ├── dashboard/page.tsx   # Security dashboard with charts
│   │   │   ├── alerts/page.tsx      # Alert list with expandable details
│   │   │   ├── timeline/page.tsx    # Chronological event timeline
│   │   │   └── investigation/page.tsx # AI chat investigation interface
│   │   │
│   │   ├── components/
│   │   │   ├── SeverityBadge.tsx    # Color-coded severity label component
│   │   │   └── StatCard.tsx         # Dashboard statistic card component
│   │   │
│   │   └── lib/
│   │       └── api.ts              # TypeScript API client (types + fetch functions)
│   │
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   ├── next.config.ts               # API rewrites, body size config
│   └── postcss.config.mjs
│
├── docker/                           # Docker configuration
│   ├── docker-compose.yml           # Full stack: Postgres, Redis, Elasticsearch, backend, frontend
│   ├── Dockerfile.backend           # Python backend container
│   └── Dockerfile.frontend          # Node.js frontend container
│
├── .gitignore
└── README.md                        # This file
```

---

## 8. Getting Started

### Prerequisites

- **Python 3.12+** (tested with 3.14)
- **Node.js 20+** (tested with 22)
- **npm 10+**
- **OpenAI API key** (for AI features; get one at https://platform.openai.com/api-keys)

Docker is optional — the development setup uses SQLite and requires no external services.

### Option A: Quick Start (Development — No Docker)

This is the fastest way to get running. Uses SQLite, no Redis or PostgreSQL needed.

**Step 1 — Clone and set up the backend:**

```bash
cd LogAI/backend

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate          # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

**Step 2 — Add your OpenAI API key:**

Edit `backend/.env` and set:

```
OPENAI_API_KEY=sk-proj-your-actual-key-here
```

**Step 3 — Start the backend:**

```bash
cd LogAI/backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000 --timeout-keep-alive 300
```

The backend will:
- Start on http://localhost:8000
- Auto-create the SQLite database (`logai.db`)
- Auto-create all tables on first run
- Serve interactive API docs at http://localhost:8000/docs

**Step 4 — Set up and start the frontend:**

Open a new terminal:

```bash
cd LogAI/frontend
npm install
npm run dev
```

The frontend will start on http://localhost:3000.

**Step 5 — Sign in and use the application:**

1. Open http://localhost:3000/login
2. Sign in with bootstrap admin:
   - Username: `admin`
   - Password: `changeme`
   - Change the password from **Account** after first login
3. Upload and analyze logs
   - Drag and drop a log file (try `backend/sample_logs/auth.log`)
   - Select Processing Mode: **Instant (no Redis needed)**
   - Click **Analyze Log**
4. After analysis completes, navigate to Dashboard, Alerts, Timeline, or AI Investigation

### Option B: Production Setup (Docker Compose)

For production with PostgreSQL, Redis, and Elasticsearch:

**Step 1 — Start all infrastructure:**

```bash
cd LogAI/docker
docker compose up -d
```

This starts: PostgreSQL, Redis, Elasticsearch, Backend API, Celery Worker, and Frontend.

**Step 2 — Configure environment:**

```bash
cd LogAI/backend
cp .env.example .env
```

Edit `.env` and set:

```
DATABASE_URL=postgresql+asyncpg://logai:logai@localhost:5432/logai
DATABASE_URL_SYNC=postgresql://logai:logai@localhost:5432/logai
OPENAI_API_KEY=sk-proj-your-key-here
```

**Step 3 — Access the application:**

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Documentation | http://localhost:8000/docs |
| Elasticsearch | http://localhost:9200 |

---

## 9. Configuration

All configuration is managed through environment variables, loaded from `backend/.env`:

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./logai.db` | Async database URL |
| `DATABASE_URL_SYNC` | `sqlite:///./logai.db` | Sync database URL (for Celery workers) |
| `DEBUG` | `false` | Enable SQL query logging |

For PostgreSQL:
```
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname
DATABASE_URL_SYNC=postgresql://user:pass@host:5432/dbname
```

### AI Provider

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_PROVIDER` | `openai` | AI backend: `openai`, `anthropic`, or `local` |
| `OPENAI_API_KEY` | — | Your OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model to use |
| `ANTHROPIC_API_KEY` | — | Your Anthropic API key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | Claude model to use |
| `LOCAL_LLM_URL` | — | Ollama or compatible API URL (e.g., `http://localhost:11434/api/chat`) |

### Infrastructure

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker URL |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery result backend |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch URL |

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `UPLOAD_DIR` | `uploads` | Directory for uploaded log files |
| `MAX_UPLOAD_SIZE_MB` | `500` | Maximum file upload size in MB |
| `SECRET_KEY` | (placeholder) | Secret key for token signing |
| `CORS_ORIGINS` | `["http://localhost:3000","http://localhost:8000"]` | Allowed CORS origins |

---

## 10. API Reference

Base URL: `http://localhost:8000/api`

### Upload & Analysis

#### `POST /upload-log`
Upload a log file for asynchronous analysis (requires Celery + Redis).

**Request:** `multipart/form-data`
- `file` (required): Log file (.log, .txt, .json, .jsonl, .csv)
- `log_type` (optional): Format hint — `auth`, `nginx`, `json`, `firewall`

**Response:** `JobResponse` with status `pending`

---

#### `POST /dev/analyze`
Upload and analyze a log file synchronously (no Celery required). Recommended for development.

**Request:** `multipart/form-data`
- `file` (required): Log file
- `log_type` (optional): Format hint
- `skip_ai` (optional): Set to `true` to skip AI analysis

**Response:** `JobResponse` with status `completed` and full results

---

#### `GET /analysis/{job_id}`
Get the status and results of an analysis job.

**Response:**
```json
{
  "id": "uuid",
  "filename": "auth.log",
  "file_size": 5159,
  "log_type": "Auth",
  "status": "completed",
  "progress": 100.0,
  "total_lines": 52,
  "parsed_lines": 52,
  "ai_summary": "The logs indicate a brute-force attack...",
  "ai_risk_level": "critical",
  "ai_recommendations": ["Block IP 103.21.55.10", "Reset admin password"],
  "alert_count": 11,
  "created_at": "2026-03-11T08:00:00",
  "completed_at": "2026-03-11T08:00:05"
}
```

---

#### `GET /jobs?page=1&page_size=20`
List all analysis jobs with pagination.

---

### Logs & Alerts

#### `GET /logs/{job_id}?page=1&page_size=50&event_type=login_failed&source_ip=1.2.3.4&username=admin&search=keyword`
Get parsed log entries with filtering and pagination.

---

#### `GET /alerts/{job_id}`
Get all security alerts for a specific job.

**Response:**
```json
{
  "alerts": [
    {
      "id": "uuid",
      "alert_type": "brute_force",
      "severity": "critical",
      "title": "Brute Force Attack from 103.21.55.10",
      "description": "Detected 134 failed login attempts...",
      "source_ip": "103.21.55.10",
      "target_account": "admin, root",
      "evidence": { "failed_attempts": 134, "duration_seconds": 180 },
      "recommended_actions": ["Block IP", "Reset passwords", "Enable MFA"]
    }
  ],
  "total": 11
}
```

---

#### `GET /alerts?job_id=uuid&severity=critical`
Get alerts across all jobs, optionally filtered.

---

### Dashboard & Timeline

#### `GET /dashboard/{job_id}`
Get aggregated dashboard statistics.

**Response includes:** total events, alert counts by severity, unique IPs, failed/successful logins, error rate, top source IPs, top endpoints, top usernames, events by hour, alerts by type, severity distribution.

---

#### `GET /timeline/{job_id}?limit=200`
Get a chronological timeline of notable security events and alerts.

---

### AI Investigation

#### `POST /investigate/ask-ai`
Ask a question about the analyzed logs.

**Request:**
```json
{
  "job_id": "uuid",
  "question": "Which IP is most suspicious and why?"
}
```

**Response:**
```json
{
  "answer": "Based on the analysis, IP 103.21.55.10 is the most suspicious..."
}
```

---

#### `GET /investigate/chat-history/{job_id}`
Get the full investigation chat history for a job.

---

## 11. Log Parsing Engine

### How Auto-Detection Works

1. The engine reads the first 200 lines of the uploaded file
2. Each registered parser scores the sample (0.0 to 1.0 confidence)
3. The highest-scoring parser is selected
4. If a `log_type` hint is provided, it overrides auto-detection

### Parser Details

**Auth/Syslog Parser** (`auth_parser.py`)
- Pattern: `Mar 11 02:14:33 hostname service[pid]: message`
- Detects: failed/successful passwords, invalid users, session open/close, sudo commands, disconnections
- Confidence boost: keywords like `sshd`, `sudo`, `pam_unix`, `Failed password`

**Nginx/Apache Access Parser** (`nginx_parser.py`)
- Pattern: `IP - user [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"`
- Classifies requests: authentication, admin access, unauthorized, forbidden, server error, modification
- Extracts: IP, user, timestamp, method, endpoint, status, size, user agent, referrer

**JSON Parser** (`json_parser.py`)
- Handles: one JSON object per line (JSONL format)
- Auto-maps standard field names across multiple naming conventions
- Supports: Docker container logs, application logs, Windows Event logs, cloud logs
- Maps 9 field categories: timestamp, IP, user, endpoint, method, status, message, event type, severity level

**Firewall Parser** (`firewall_parser.py`)
- Supports: iptables/UFW logs, PF (BSD/macOS) logs, generic key=value firewall logs
- Extracts: source/destination IP, ports, protocol, action (block/allow), interface
- Classifies: firewall_block vs firewall_allow events

### Parsed Entry Schema

Every log line is normalized to this structure:

| Field | Type | Description |
|-------|------|-------------|
| `line_number` | int | Original line number in the file |
| `timestamp` | datetime | Parsed timestamp |
| `source_ip` | string | Source IP address |
| `destination_ip` | string | Destination IP address |
| `username` | string | User account name |
| `endpoint` | string | URL path or target |
| `method` | string | HTTP method (GET, POST, etc.) |
| `status_code` | int | HTTP status code |
| `response_size` | int | Response body size in bytes |
| `user_agent` | string | Browser/client user agent |
| `event_type` | string | Classified event type |
| `message` | string | Human-readable description |
| `raw_line` | string | Original log line (truncated to 2,000 chars) |
| `extra_fields` | JSON | Additional parser-specific fields |

---

## 12. Detection Engine

### Architecture

Each detector implements the `BaseDetector` abstract class with a single `detect(entries)` method. The `DetectionEngine` runs all detectors and returns results sorted by severity.

### Brute Force Detector

- **Input**: Entries with `event_type` in (`login_failed`, `unauthorized`, `invalid_user`)
- **Algorithm**: Groups failures by source IP, uses a sliding window of 5 minutes to find bursts
- **Severity**:
  - CRITICAL: 50+ failures, or any success after failures
  - HIGH: 30+ failures
  - MEDIUM: 20+ failures
  - LOW: 10+ failures
- **Special**: Checks if a successful login occurred from the same IP after the failure window (credential compromise)

### Suspicious Login Detector

Three sub-detections:

1. **Off-hours admin login**: Any `login_success` or `session_opened` for privileged accounts (`root`, `admin`, `administrator`, `sysadmin`, `superuser`) outside 6:00-22:00
2. **Multi-privilege access**: Same IP accessing 2+ privileged accounts (lateral movement indicator)
3. **Login after failure streak**: 5+ consecutive failures for a user, followed by a success

### Web Attack Detector

Pattern-matching against URLs, endpoints, and messages using compiled regex:

- **SQL Injection**: `UNION SELECT`, `OR 1=1`, `sleep()`, `benchmark()`, hex encoding
- **Cross-Site Scripting**: `<script>`, `javascript:`, `onerror=`, `alert()`, `document.cookie`
- **Path Traversal**: `../../`, `/etc/passwd`, `/etc/shadow`, `c:\windows`
- **Command Injection**: `; ls`, `| cat`, backtick execution, `$()` subshells
- **Vulnerability Scanning**: Known scanner user-agents and probing paths (`.env`, `.git`, `wp-admin`, `phpmyadmin`)

### API Abuse Detector

Three sub-detections:

1. **Rate abuse**: Sliding 1-minute window, triggers at 100+ requests/minute per IP
2. **Data exfiltration**: Total response bytes per IP, triggers at 50+ MB
3. **Error flooding**: 50+ HTTP 4xx errors from one IP (directory brute-forcing indicator)

---

## 13. AI Analysis Layer

### System Prompt

The AI is instructed to act as an expert SOC analyst. Its responses are professional, technically accurate, reference specific log evidence, and include actionable recommendations.

### Summary Generation

The AI receives:
- Log type and total entry count
- Event type distribution (top 15)
- Top 10 source IPs with event counts
- Top 10 usernames with event counts
- All security alerts with full details and evidence
- A sample of up to 30 notable log entries (failures, errors, admin actions)

It returns structured JSON with: executive summary, technical summary, risk level, key findings, attack narrative, IoCs, recommended actions, and MITRE techniques.

### Investigation Chat

- Maintains per-job conversation history (stored in database)
- Last 10 messages are included as context for follow-up questions
- Same log analysis context is provided with each question

### Supported Providers

| Provider | Configuration | Models |
|----------|--------------|--------|
| **OpenAI** | `AI_PROVIDER=openai` + `OPENAI_API_KEY` | gpt-4o (default), gpt-4-turbo, gpt-3.5-turbo |
| **Anthropic** | `AI_PROVIDER=anthropic` + `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 (default) |
| **Local LLM** | `AI_PROVIDER=local` + `LOCAL_LLM_URL` | Any Ollama-compatible model (llama3.1, mistral, etc.) |

If no provider is configured, the detection engine still works fully — only AI summaries and investigation chat are unavailable.

---

## 14. Frontend Pages

### Upload Page (`/`)
- Drag-and-drop file upload zone
- Optional log type selector (auto-detect, auth, nginx, JSON, firewall)
- Processing mode toggle (Instant sync vs Background async)
- Shows results inline: line counts, alert count, risk level, AI summary, recommended actions
- Navigation buttons to Dashboard, Alerts, Timeline, Investigation

### Dashboard Page (`/dashboard`)
- Job selector dropdown
- Risk level banner with AI summary
- 5 stat cards: Total Events, Alerts, Unique IPs, Failed Logins, Error Rate
- Events by Hour area chart
- Severity distribution pie chart
- Top Source IPs horizontal bar chart
- Top Endpoints horizontal bar chart
- Alerts by Type bar chart
- Top Targeted Accounts table

### Alerts Page (`/alerts`)
- Severity filter dropdown
- Job selector dropdown
- Expandable alert cards showing: severity badge, title, description, source IP, target account, alert type
- Expanded view: raw evidence JSON, recommended actions list

### Timeline Page (`/timeline`)
- Event type filter dropdown
- Job selector dropdown
- Vertical timeline with color-coded severity dots
- Each event shows: timestamp, event type badge, severity badge, source IP, username, description

### Investigation Page (`/investigation`)
- Job selector dropdown
- Suggested question buttons (8 pre-built security questions)
- Chat interface with user/assistant message bubbles
- Loading indicator while AI processes
- Full conversation history persistence

---

## 15. Database Schema

### `analysis_jobs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID (CHAR 36) | Primary key |
| `filename` | VARCHAR(500) | Original uploaded filename |
| `file_path` | VARCHAR(1000) | Path to stored file |
| `file_size` | INTEGER | File size in bytes |
| `log_type` | VARCHAR(100) | Detected log format |
| `status` | ENUM | pending, parsing, detecting, analyzing, completed, failed |
| `progress` | FLOAT | 0.0 to 100.0 |
| `total_lines` | INTEGER | Total parsed entries |
| `parsed_lines` | INTEGER | Successfully parsed entries |
| `error_message` | TEXT | Error description if failed |
| `ai_summary` | TEXT | AI-generated security summary |
| `ai_risk_level` | ENUM | info, low, medium, high, critical |
| `ai_recommendations` | JSON | List of recommended actions |
| `metadata` | JSON | Key findings, MITRE techniques, IoCs |
| `created_at` | DATETIME | Job creation timestamp |
| `updated_at` | DATETIME | Last update timestamp |
| `completed_at` | DATETIME | Completion timestamp |

### `log_entries`

| Column | Type | Indexed |
|--------|------|---------|
| `id` | UUID | PK |
| `job_id` | UUID FK | Yes (composite with timestamp, source_ip) |
| `line_number` | INTEGER | |
| `timestamp` | DATETIME | Yes |
| `source_ip` | VARCHAR(45) | Yes |
| `destination_ip` | VARCHAR(45) | |
| `username` | VARCHAR(255) | Yes |
| `endpoint` | VARCHAR(1000) | |
| `method` | VARCHAR(10) | |
| `status_code` | INTEGER | |
| `response_size` | INTEGER | |
| `user_agent` | TEXT | |
| `event_type` | VARCHAR(100) | Yes |
| `message` | TEXT | |
| `raw_line` | TEXT | |
| `extra_fields` | JSON | |

### `alerts`

| Column | Type | Indexed |
|--------|------|---------|
| `id` | UUID | PK |
| `job_id` | UUID FK | Yes (composite with alert_type) |
| `alert_type` | ENUM | Yes |
| `severity` | ENUM | Yes |
| `title` | VARCHAR(500) | |
| `description` | TEXT | |
| `source_ip` | VARCHAR(45) | |
| `target_account` | VARCHAR(255) | |
| `evidence` | JSON | |
| `recommended_actions` | JSON | |
| `is_resolved` | BOOLEAN | |
| `created_at` | DATETIME | |

### `investigation_chats`

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | PK |
| `job_id` | UUID FK | Associated analysis job |
| `role` | VARCHAR(20) | "user" or "assistant" |
| `content` | TEXT | Message content |
| `created_at` | DATETIME | Message timestamp |

---

## 16. Background Processing

For production deployments with large files or multiple concurrent users, the system supports asynchronous processing via Celery:

### Starting a Celery Worker

```bash
cd LogAI/backend
source .venv/bin/activate
celery -A app.workers.celery_app worker --loglevel=info --concurrency=4
```

### Task Flow

```
POST /upload-log
     │
     ▼
Create job (status: pending)
     │
     ▼
Dispatch Celery task: analyze_log_file
     │
     ├──► Phase 1: Parse (status: parsing, progress: 10-50%)
     │         Read file → detect parser → parse lines → batch insert
     │
     ├──► Phase 2: Detect (status: detecting, progress: 55-70%)
     │         Run all detectors → save alerts
     │
     ├──► Phase 3: AI Analysis (status: analyzing, progress: 75-100%)
     │         Generate summary → save results
     │
     └──► Complete (status: completed, progress: 100%)
```

The frontend can poll `GET /analysis/{job_id}` to track progress.

### When to Use Async vs Sync

| Mode | Endpoint | When to Use |
|------|----------|-------------|
| **Sync** | `POST /dev/analyze` | Development, small-medium files, no Redis available |
| **Async** | `POST /upload-log` | Production, large files, multiple concurrent users |

---

## 17. Deployment

Use one of the dedicated guides:

- **Fastest Ubuntu path (copy/paste):** [docs/QUICKSTART_UBUNTU_DOCKER.md](docs/QUICKSTART_UBUNTU_DOCKER.md)
- **Ubuntu server (VPS/on-prem):** [docs/DEPLOYMENT_UBUNTU.md](docs/DEPLOYMENT_UBUNTU.md)
- **AWS (EC2 + RDS + optional ElastiCache):** [docs/DEPLOYMENT_AWS.md](docs/DEPLOYMENT_AWS.md)

Both guides include:
- process setup (Docker or native/systemd),
- HTTPS with Nginx,
- CORS and frontend API URL settings,
- production hardening and troubleshooting.

### Docker Compose (Recommended)

For Ubuntu local server, use `docker/docker-compose.ubuntu.yml` with `docker/.env.ubuntu`.

```bash
cp docker/.env.ubuntu.example docker/.env.ubuntu
cp backend/.env.example backend/.env
cd docker
docker compose --env-file .env.ubuntu -f docker-compose.ubuntu.yml up -d --build
```

The `docker/docker-compose.yml` remains available for general development setups.

| Service | Image | Port |
|---------|-------|------|
| `postgres` | postgres:16-alpine | 5432 |
| `redis` | redis:7-alpine | 6379 |
| `elasticsearch` | elasticsearch:8.17.0 | 9200 |
| `backend` | Custom (Python 3.12) | 8000 |
| `celery-worker` | Same as backend | — |
| `frontend` | Custom (Node 20) | 3000 |

```bash
cd docker
docker compose up -d
```

### Manual Deployment Checklist

1. Set `DEBUG=false` in `.env`
2. Use PostgreSQL instead of SQLite for production
3. Set a strong `SECRET_KEY` (generate with `openssl rand -hex 32`)
4. Configure CORS origins to match your domain
5. Run Celery workers for async processing
6. Set up a reverse proxy (Nginx) in front of the backend
7. Enable HTTPS

---

## 18. Future Roadmap

Features planned for future releases:

| Feature | Description |
|---------|-------------|
| **Real-time log streaming** | Accept logs via syslog, Filebeat, or WebSocket |
| **Threat intelligence** | Check IPs against AbuseIPDB, VirusTotal, GreyNoise |
| **Behavioral anomaly detection** | ML-based baseline learning and deviation detection |
| **Log correlation engine** | Cross-reference events across multiple log sources |
| **PDF/DOCX report export** | Generate downloadable incident reports |
| **User authentication** | Multi-user support with roles (analyst, admin, viewer) |
| **SIEM-like features** | Custom alert rules, incident cases, response workflows |
| **Webhook notifications** | Send alerts to Slack, Teams, PagerDuty, email |
| **GeoIP enrichment** | Map source IPs to geographic locations |
| **Windows Event Log parser** | Native parser for EVTX format |

---

## License

This project is proprietary. All rights reserved.
