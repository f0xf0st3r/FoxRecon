# FoxRecon

**Production-grade offensive reconnaissance and attack surface management platform.**

<div align="center">

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

## Overview

FoxRecon is a modular, async-first reconnaissance operating system designed for red teams, bug bounty hunters, and security engineers. It orchestrates industry-standard offensive security tools into automated pipelines, normalizes findings, stores results, and generates actionable reports.

### V2 Pipeline

```
domain → subfinder → subdomains → httpx → live hosts → naabu → ports → nuclei → findings
     → ffuf → content discovery
     → gowitness → screenshots
     → js_analysis → endpoints + secrets
     → dns_intel → records + zone transfer + ASN
     → api_discovery → swagger + graphql + endpoints
     → cloud_exposure → S3 + Azure + GCP
```

| Stage | Tool | Purpose |
|-------|------|---------|
| Recon | subfinder | Passive subdomain enumeration |
| Live Hosts | httpx | HTTP/HTTPS detection, fingerprinting |
| Port Scan | naabu | Fast port scanning |
| Vuln Scan | nuclei | Template-based vulnerability detection |
| Content Disc | ffuf | Directory and endpoint enumeration |
| Screenshots | gowitness | Visual asset capture |
| JS Analysis | built-in | Endpoint extraction, secret detection |
| DNS Intel | DoH APIs | Records, zone transfer, ASN mapping |
| API Discovery | built-in | Swagger, GraphQL, REST endpoints |
| Cloud Exposure | built-in | S3, Azure Blob, GCP bucket checks |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FoxRecon Platform                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ FastAPI   │  │ Celery   │  │ Redis    │  │ PostgreSQL     │  │
│  │ REST API  │◄─┤ Workers  │◄─┤ Queue    │  │ Database       │  │
│  │          │  │          │  │          │  │                │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────────┘  │
│       ▲              │                                              │
│       │              ▼                                              │
│  ┌──────────┐  ┌──────────────────────────────────────────┐      │
│  │  Clients  │  │          Recon Engine Pipeline           │      │
│  │ (CLI/Web)│  │                                          │      │
│  └──────────┘  │  subfinder → httpx → naabu → nuclei     │      │
│                │                                          │      │
│                │  ┌────────┐ ┌──────┐ ┌──────┐ ┌───────┐  │      │
│                │  │Subfinder│ │httpx │ │naabu │ │nuclei │  │      │
│                │  └────────┘ └──────┘ └──────┘ └───────┘  │      │
│                └──────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.12+ (for local development)

### Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/foxrecon/foxrecon.git
cd foxrecon

# Start the full stack
docker compose up -d

# Check service health
docker compose ps

# View API docs
open http://localhost:8000/docs
```

### Local Development

```bash
# Create virtual environment
python -m venv .venv && source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env

# Start dependencies
docker compose up -d postgres redis

# Run database migrations
alembic upgrade head

# Start the API server
python -m main

# Start Celery worker (separate terminal)
celery -A internal.workers.celery_app.celery_app worker --loglevel=info
```

## API Usage

### Create a Target

```bash
curl -X POST http://localhost:8000/api/v1/targets/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example Corp",
    "target_type": "domain",
    "value": "example.com",
    "scope": "in_scope"
  }?organization_id=<org-uuid>'
```

### Start a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "<target-uuid>",
    "scan_type": "full",
    "priority": 5,
    "naabu_top_ports": 100,
    "nuclei_rate_limit": 50
  }'
```

### Check Scan Status

```bash
curl http://localhost:8000/api/v1/scans/<scan-uuid>
```

### Get Findings

```bash
curl "http://localhost:8000/api/v1/findings/?severity=high&limit=50"
```

### Generate Report

```bash
curl -X POST http://localhost:8000/api/v1/reports/ \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Monthly Recon Report",
    "report_type": "full",
    "format": "markdown"
  }'
```

## API Endpoints

### Core (V1)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans/` | Create and queue a scan |
| `GET` | `/api/v1/scans/` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan details with stages |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a running scan |
| `POST` | `/api/v1/targets/` | Add a scan target |
| `GET` | `/api/v1/targets/` | List targets |
| `GET` | `/api/v1/targets/{id}` | Get target details |
| `GET` | `/api/v1/targets/{id}/subdomains` | Get discovered subdomains |
| `GET` | `/api/v1/findings/` | List findings (with filters) |
| `GET` | `/api/v1/findings/{id}` | Get finding details |
| `PATCH` | `/api/v1/findings/{id}` | Update finding status |
| `GET` | `/api/v1/findings/vulnerabilities` | List vulnerability results |
| `GET` | `/api/v1/findings/live-hosts` | List live HTTP hosts |
| `GET` | `/api/v1/findings/ports` | List open ports |
| `POST` | `/api/v1/reports/` | Generate a report |
| `GET` | `/api/v1/reports/` | List reports |
| `GET` | `/api/v1/dashboard/` | Dashboard statistics |

### Auth (V2)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Register a new user |
| `POST` | `/api/v1/auth/login` | Authenticate and get tokens |
| `POST` | `/api/v1/auth/refresh` | Refresh access token |
| `GET` | `/api/v1/auth/me` | Get current user profile |
| `POST` | `/api/v1/auth/change-password` | Change password |

### Scheduling (V2)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/schedules/` | Create recurring scan schedule |
| `GET` | `/api/v1/schedules/` | List schedules |
| `PATCH` | `/api/v1/schedules/{id}/toggle` | Enable/disable schedule |
| `DELETE` | `/api/v1/schedules/{id}` | Delete a schedule |

### Intelligence (V2)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/intelligence/js-analysis` | Analyze JS for endpoints/secrets |
| `GET` | `/api/v1/intelligence/dns/{domain}` | DNS intelligence gathering |
| `POST` | `/api/v1/intelligence/api-discovery` | Discover Swagger, GraphQL, APIs |
| `POST` | `/api/v1/intelligence/cloud-exposure` | Check cloud storage exposure |

### WebSocket (V2)
| Endpoint | Description |
|----------|-------------|
| `ws://host/ws/scan/{id}` | Real-time scan progress |
| `ws://host/ws/target/{id}` | Target-level updates |
| `ws://host/ws/notifications` | User notifications |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/` | Service info |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc UI |

## Project Structure

```
foxrecon/
├── main.py                      # Application entry point
├── requirements.txt             # Python dependencies
├── docker-compose.yml           # Full stack orchestration
├── Dockerfile                   # Container image
├── alembic.ini                  # Alembic configuration
├── .env.example                 # Environment template
│
├── internal/                    # Core application code
│   ├── api/
│   │   ├── app.py               # FastAPI application factory
│   │   ├── routes/
│   │   │   ├── scans.py         # Scan management endpoints
│   │   │   ├── targets.py       # Target management endpoints
│   │   │   ├── findings.py      # Findings & results endpoints
│   │   │   ├── reports.py       # Report generation endpoints
│   │   │   └── dashboard.py     # Dashboard statistics
│   │   └── schemas/
│   │       └── __init__.py      # Pydantic request/response models
│   │
│   ├── recon/
│   │   └── engine.py            # Scan pipeline orchestrator
│   │
│   ├── scanners/
│   │   ├── base.py              # Abstract scanner interface
│   │   ├── subfinder.py         # Subfinder adapter
│   │   ├── httpx.py             # httpx adapter
│   │   ├── naabu.py             # Naabu adapter
│   │   └── nuclei.py            # Nuclei adapter
│   │
│   ├── findings/
│   │   └── normalizer.py        # Finding normalization & dedup
│   │
│   ├── reporting/
│   │   └── generator.py         # Report generation (MD, JSON, PDF)
│   │
│   ├── workers/
│   │   ├── celery_app.py        # Celery application config
│   │   └── tasks.py             # Async scan tasks
│   │
│   ├── database/
│   │   ├── base.py              # SQLAlchemy engine & session
│   │   └── models/
│   │       ├── __init__.py      # Model registry
│   │       ├── users.py         # User, Organization models
│   │       ├── targets.py       # Target, Subdomain, Host, Port models
│   │       ├── scans.py         # ScanJob, ScanResult, Finding models
│   │       └── reporting.py     # Report, ActivityLog models
│   │
│   └── utils/
│       ├── logging.py           # Structured logging (structlog)
│       ├── security.py          # Input validation & sanitization
│       └── subprocess.py        # Secure subprocess execution
│
├── alembic/
│   ├── env.py                   # Alembic environment
│   ├── script.py.mako           # Migration template
│   └── versions/
│       └── 001_initial.py       # Initial schema migration
│
├── docker/
│   └── init.sql                 # PostgreSQL initialization
│
├── scripts/
│   └── db.py                    # Database management CLI
│
└── tests/
    ├── unit/
    │   ├── test_security.py     # Security utility tests
    │   ├── test_subprocess.py   # Subprocess wrapper tests
    │   ├── test_scanners.py     # Scanner parser tests
    │   └── test_config.py       # Configuration tests
    └── integration/
        └── test_api.py          # API integration tests
```

## Database Schema

FoxRecon uses a normalized PostgreSQL schema with 21 tables:

### Core (V1)
- **users** - System users with RBAC
- **organizations** - Multi-tenant support
- **user_organizations** - User-org membership
- **targets** - Scan targets (domains, IPs, CIDRs)
- **subdomains** - Discovered subdomains with source tracking
- **live_hosts** - HTTP/HTTPS hosts with fingerprints
- **ports** - Open ports with service detection
- **technologies** - Detected technology stack
- **screenshots** - Visual evidence
- **scan_jobs** - Top-level scan orchestration
- **scan_results** - Per-stage scan results
- **findings** - Normalized security findings
- **vulnerabilities** - Structured vuln records (nuclei)
- **reports** - Generated reports
- **activity_logs** - Audit trail

### V2 Additions
- **scan_schedules** - Recurring scan schedules
- **js_endpoints** - Endpoints from JS analysis
- **js_secrets** - Secrets found in JavaScript
- **dns_records** - DNS record intelligence
- **api_discoveries** - Discovered API endpoints
- **cloud_exposures** - Exposed cloud storage

All tables use UUID primary keys, automatic timestamps, and appropriate indexing.

## Security

FoxRecon implements multiple security layers:

1. **Input Validation** - Strict domain/IP/CIDR validation with injection detection
2. **Secure Subprocess** - No shell execution, argument whitelisting, resource limits
3. **Sandboxed Execution** - Clean environment variables, working directory isolation
4. **RBAC-Ready** - Role-based access control architecture in place
5. **Audit Logging** - All security-relevant actions are logged
6. **Rate Limiting** - Configurable API rate limits
7. **JWT Authentication** - Token-based auth (ready for implementation)

## Configuration

All configuration is managed through environment variables or `.env` file. See `.env.example` for all available options.

Key configuration groups:
- **Application** - Name, environment, debug mode
- **Server** - Host, port, CORS origins
- **PostgreSQL** - Connection, pooling
- **Redis** - Cache and Celery broker
- **Scan Engine** - Timeouts, concurrency, rate limits
- **Tools** - Binary paths, nuclei settings

## Running Tests

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# All tests
pytest -v

# With coverage
pytest --cov=internal --cov-report=html
```

## Development Roadmap

### V1 (Done)
- [x] Core architecture
- [x] PostgreSQL schema (16 tables)
- [x] subfinder integration
- [x] httpx integration
- [x] naabu integration
- [x] nuclei integration
- [x] Celery worker system
- [x] FastAPI REST API
- [x] Report generation (MD/JSON)
- [x] Docker Compose
- [x] 54 unit tests

### V2 (Done)
- [x] ffuf content discovery
- [x] gowitness screenshot capture
- [x] JS analysis (endpoint/secret extraction)
- [x] DNS intelligence (records, zone transfer, ASN)
- [x] API discovery (Swagger, GraphQL, REST)
- [x] Cloud exposure checks (S3, Azure, GCP)
- [x] JWT authentication (register, login, refresh, RBAC)
- [x] WebSocket real-time updates
- [x] Scan scheduling (Celery beat + cron)
- [x] 11 new database tables (21 total)
- [x] 65 unit tests

### V3 (Future)
- [ ] AI-assisted analysis
- [ ] Attack path suggestions
- [ ] Finding prioritization ML
- [ ] Kubernetes deployment
- [ ] Multi-region support
- [ ] Integration APIs (Jira, Slack, etc.)
- [ ] Web dashboard (React)
- [ ] nmap integration
- [ ] dirsearch integration
- [ ] Playwright screenshots

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

FoxRecon is designed for authorized security testing only. Always obtain proper authorization before scanning any target. The authors are not responsible for misuse of this tool.
