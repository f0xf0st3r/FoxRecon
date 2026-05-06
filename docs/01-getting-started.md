# Getting Started

## Prerequisites

- **Python** 3.12 or 3.13
- **Docker & Docker Compose** (recommended for full stack)
- **PostgreSQL** 16+ (if running locally)
- **Redis** 7+ (if running locally)

### External Tools (optional)

FoxRecon can run without these, but scan functionality requires:

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | Live host detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| naabu | Port scanning | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| ffuf | Content discovery | `go install github.com/ffuf/ffuf/v2@latest` |
| gowitness | Screenshots | `go install github.com/sensepost/gowitness@latest` |

## Installation

### Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/f0xf0st3r/FoxRecon.git
cd FoxRecon

# Start the full stack (API, PostgreSQL, Redis, Celery Worker)
docker compose up -d

# Verify services are healthy
docker compose ps

# View API documentation
open http://localhost:8000/docs
```

### Option 2: Local Development

```bash
# Clone the repository
git clone https://github.com/f0xf0st3r/FoxRecon.git
cd FoxRecon

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Run database migrations
export DATABASE_URL_SYNC="postgresql+psycopg2://foxrecon:foxrecon_secret@localhost:5432/foxrecon"
alembic upgrade head

# Start the API server
python -m main

# Start Celery worker (separate terminal)
celery -A internal.workers.celery_app.celery_app worker --loglevel=info
```

## Quick Start

### 1. Register a User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@foxrecon.local",
    "username": "admin",
    "password": "SecureP@ssw0rd!"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

### 2. Create an Organization

```bash
curl -X POST http://localhost:8000/api/v1/organizations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "name": "Acme Corp",
    "slug": "acme-corp"
  }'
```

### 3. Add a Target

```bash
curl -X POST http://localhost:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "name": "Acme Production",
    "target_type": "domain",
    "value": "example.com",
    "scope": "in_scope"
  }?organization_id=<org-uuid>'
```

### 4. Run a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "target_id": "<target-uuid>",
    "scan_type": "full",
    "priority": 5,
    "naabu_top_ports": 100,
    "nuclei_rate_limit": 50
  }'
```

### 5. Check Scan Progress

```bash
# Via REST API
curl http://localhost:8000/api/v1/scans/<scan-uuid> \
  -H "Authorization: Bearer <access_token>"

# Via WebSocket (real-time)
wscat -c ws://localhost:8000/ws/scan/<scan-uuid>
```

### 6. View Findings

```bash
curl "http://localhost:8000/api/v1/findings/?severity=high&limit=20" \
  -H "Authorization: Bearer <access_token>"
```

### 7. Generate a Report

```bash
curl -X POST http://localhost:8000/api/v1/reports \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "title": "Monthly Recon Report - May 2026",
    "report_type": "full",
    "format": "markdown"
  }'
```

## Configuration

### Environment Variables

All configuration is managed through environment variables or a `.env` file:

```bash
cp .env.example .env
```

#### Application Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `production` | Environment (development/production) |
| `DEBUG` | `false` | Enable debug mode |
| `SECRET_KEY` | *(required)* | JWT signing key |
| `API_PREFIX` | `/api/v1` | API URL prefix |

#### Database
| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | `foxrecon` | Database user |
| `POSTGRES_PASSWORD` | `foxrecon_secret` | Database password |
| `POSTGRES_HOST` | `localhost` | Database host |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_DB` | `foxrecon` | Database name |
| `POSTGRES_POOL_SIZE` | `20` | Connection pool size |

#### Redis
| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database number |

#### Scan Engine
| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_TIMEOUT_SECONDS` | `3600` | Max scan duration |
| `MAX_CONCURRENT_SCANS` | `10` | Parallel scan limit |
| `NUCLEI_RATE_LIMIT` | `50` | Nuclei requests/sec |
| `NUCLEI_CONCURRENCY` | `25` | Nuclei concurrent templates |

## Next Steps

- Read the [Architecture Guide](02-architecture.md) to understand how FoxRecon works
- Explore the [API Reference](05-api-reference.md) for all endpoints
- Check [Scanner Adapters](03-scanners.md) to understand tool integrations
- Review [Deployment](06-deployment.md) for production setup
