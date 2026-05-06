# Architecture

## System Overview

FoxRecon is built on a clean architecture pattern with clear separation between:

- **API Layer** - FastAPI REST + WebSocket interfaces
- **Application Layer** - Business logic and orchestration
- **Domain Layer** - Core entities and rules
- **Infrastructure Layer** - Database, workers, external tools

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLIENTS                                    │
│  CLI │  Web Dashboard  │  Third-party APIs  │  CI/CD Pipelines   │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                     API LAYER (FastAPI)                           │
│                                                                   │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Scans   │ │ Targets  │ │ Findings │ │ Reports  │ │  Auth   │ │
│  │ Routes  │ │ Routes   │ │ Routes   │ │ Routes   │ │ Routes  │ │
│  └─────────┘ └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              WebSocket Manager (Real-time)                   │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌────────────┐ ┌─────────────┐ ┌────────────────────────────┐  │
│  │ JWT Auth   │ │ RBAC Guard  │ │ Rate Limiter / CORS / TLS  │  │
│  │ Middleware │ │ Middleware  │ │ Middlewares                │  │
│  └────────────┘ └─────────────┘ └────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                  APPLICATION LAYER                                │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Recon Engine                              │ │
│  │                                                              │ │
│  │  domain → subfinder → httpx → naabu → nuclei → findings     │ │
│  │         ↓               ↓        ↓         ↓                  │ │
│  │         ffuf          gowitness  js_analysis  api_discovery   │ │
│  │                                  ↓                            │ │
│  │                            dns_intel  cloud_exposure          │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ Findings     │ │ Report       │ │ WebSocket                │ │
│  │ Normalizer   │ │ Generator    │ │ Connection Manager       │ │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘ │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                  DOMAIN LAYER                                     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   Pydantic Schemas                           │ │
│  │   User │ Target │ Scan │ Finding │ Report │ Schedule         │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ ScanConfig   │ │ ScanOutput   │ │ ExecutionPolicy          │ │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘ │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  BaseScanner (Interface)                     │ │
│  │   SubfinderScanner │ HttpxScanner │ NaabuScanner │ ...       │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                INFRASTRUCTURE LAYER                               │
│                                                                   │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ PostgreSQL │ │   Redis    │ │  Celery  │ │  Security      │  │
│  │ 16 Tables  │ │ Queue +    │ │ Workers  │ │  Subprocess    │  │
│  │ 21 V2      │ │ Cache      │ │ Beat     │ │  Wrapper       │  │
│  └────────────┘ └────────────┘ └──────────┘ └────────────────┘  │
│                                                                   │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ Structured │ │ Input      │ │ Config   │ │ Alembic        │  │
│  │ Logging    │ │ Validation │ │ Manager  │ │ Migrations     │  │
│  └────────────┘ └────────────┘ └──────────┘ └────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

## Module Structure

```
foxrecon/
├── internal/
│   ├── api/
│   │   ├── app.py                 # FastAPI application factory
│   │   ├── routes/
│   │   │   ├── scans.py           # Scan CRUD + execution
│   │   │   ├── targets.py         # Target management
│   │   │   ├── findings.py        # Findings, vulns, hosts, ports
│   │   │   ├── reports.py         # Report generation
│   │   │   ├── dashboard.py       # Statistics aggregation
│   │   │   ├── auth.py            # JWT auth (V2)
│   │   │   ├── websocket.py       # WebSocket endpoints (V2)
│   │   │   ├── schedules.py       # Scan scheduling (V2)
│   │   │   └── intelligence.py    # Intelligence modules (V2)
│   │   └── schemas/
│   │       └── __init__.py        # Pydantic request/response models
│   │
│   ├── recon/
│   │   └── engine.py              # Pipeline orchestrator
│   │
│   ├── scanners/
│   │   ├── base.py                # Abstract scanner interface
│   │   ├── subfinder.py           # Subdomain enumeration
│   │   ├── httpx.py               # Live host detection
│   │   ├── naabu.py               # Port scanning
│   │   ├── nuclei.py              # Vulnerability scanning
│   │   ├── ffuf.py                # Content discovery (V2)
│   │   └── gowitness.py           # Screenshots (V2)
│   │
│   ├── findings/
│   │   └── normalizer.py          # Finding dedup + normalization
│   │
│   ├── reporting/
│   │   └── generator.py           # MD/JSON report generation
│   │
│   ├── workers/
│   │   ├── celery_app.py          # Celery configuration
│   │   ├── tasks.py               # Async scan tasks
│   │   └── scheduler.py           # Recurring scan schedules (V2)
│   │
│   ├── integrations/
│   │   ├── js_analysis.py         # JS endpoint/secret extraction (V2)
│   │   ├── dns_intelligence.py    # DNS records, ASN, zone transfer (V2)
│   │   ├── api_discovery.py       # Swagger, GraphQL detection (V2)
│   │   └── cloud_exposure.py      # S3, Azure, GCP checks (V2)
│   │
│   ├── database/
│   │   ├── base.py                # SQLAlchemy engine + sessions
│   │   └── models/
│   │       ├── users.py           # User, Organization, Membership
│   │       ├── targets.py         # Target, Subdomain, Host, Port
│   │       ├── scans.py           # ScanJob, ScanResult, Finding
│   │       ├── reporting.py       # Report, ActivityLog, Schedule
│   │       └── v2_features.py     # JS, DNS, API, Cloud models
│   │
│   ├── websocket/
│   │   └── manager.py             # Connection manager (V2)
│   │
│   ├── auth/
│   │   └── jwt.py                 # JWT utilities, RBAC (V2)
│   │
│   ├── config.py                  # Pydantic settings (all config)
│   │
│   └── utils/
│       ├── logging.py             # Structured logging (structlog)
│       ├── security.py            # Input validation, sanitization
│       └── subprocess.py          # Secure subprocess execution
│
├── alembic/                       # Database migrations
│   ├── versions/
│   │   ├── 001_initial.py         # Core schema (16 tables)
│   │   └── 002_v2_features.py     # V2 schema (5 tables)
│   └── env.py
│
├── docker/
│   └── init.sql                   # PostgreSQL extensions
│
├── docs/                          # Documentation
│
├── tests/
│   ├── unit/                      # Unit tests (65 passing)
│   └── integration/               # Integration tests
│
├── .github/                       # GitHub templates + CI
│
├── docker-compose.yml             # Full stack orchestration
├── Dockerfile                     # Container image
├── pyproject.toml                 # Project metadata
├── requirements.txt               # Python dependencies
└── main.py                        # Entry point
```

## Scan Pipeline

### V1 Pipeline (Core)

```
                    ┌─────────────┐
                    │   Target    │
                    │  (domain)   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  subfinder  │  Passive subdomain enumeration
                    │  (recon)    │  Sources: crt.sh, Shodan, etc.
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │    httpx    │  Live HTTP/HTTPS detection
                    │ (live hosts)│  Titles, status codes, tech
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │                         │
       ┌──────▼──────┐          ┌───────▼───────┐
       │    naabu    │          │   nuclei      │
       │ (port scan) │          │ (vuln scan)   │
       │ top-100     │          │ templates     │
       └──────┬──────┘          └───────┬───────┘
              │                         │
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │  Findings   │
                    │  Storage    │
                    └─────────────┘
```

### V2 Extended Pipeline

```
                    ┌─────────────┐
                    │   Target    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┬────────────┐
              │            │            │            │
       ┌──────▼──────┐ ┌──▼───┐  ┌─────▼─────┐ ┌───▼────┐
       │ subfinder   │ │ httpx│  │  ffuf     │ │  JS    │
       │ httpx       │ │ naabu│  │  gowitness│ │  analysis│
       │ naabu       │ │ nuclei│ │  js_analysis│ │ api     │
       │ nuclei      │ │      │  │  dns_intel│ │ discovery│
       │             │ │      │  │  cloud    │ │ cloud   │
       └──────┬──────┘ └──┬───┘  └─────┬─────┘ └───┬────┘
              │           │            │           │
              └───────────┼────────────┼───────────┘
                          │
                   ┌──────▼──────┐
                   │  Correlated │
                   │  Findings   │
                   └─────────────┘
```

Each stage:
1. Executes via `SecureProcess` (no shell injection)
2. Parses output into normalized `ScanOutput`
3. Persists results to PostgreSQL
4. Sends real-time updates via WebSocket
5. Updates scan job progress

## Database Schema

### Entity Relationships

```
Organization ────< Target ────< Subdomain
      │               │
      │               ├──< LiveHost ────< Port
      │               │                      │
      │               │                      └──< Screenshot
      │               │
      │               ├──< Technology
      │               │
      │               └──< Finding ────< Vulnerability
      │                      │
      │                      └──< JS Endpoint
      │                      └──< JS Secret
      │                      └──< DNS Record
      │                      └──< API Discovery
      │                      └──< Cloud Exposure
      │
      └──< User (many-to-many)
              │
              └──< ScanJob ────< ScanResult
              │
              └──< Report
              │
              └──< ActivityLog

ScanSchedule ──> Target
```

### Table Categories

| Category | Tables | Purpose |
|----------|--------|---------|
| Identity | users, organizations, user_organizations | Multi-tenant auth |
| Assets | targets, subdomains, live_hosts, ports, technologies, screenshots | Discovered infrastructure |
| Scans | scan_jobs, scan_results, scan_schedules | Scan orchestration |
| Findings | findings, vulnerabilities, js_endpoints, js_secrets, dns_records, api_discoveries, cloud_exposures | Security results |
| Reporting | reports, activity_logs | Audit and export |

### Key Design Decisions

- **UUID primary keys** - No auto-increment, safe for distributed systems
- **Timestamps** - `created_at` and `updated_at` on every table
- **JSONB columns** - Flexible metadata storage (PostgreSQL-specific)
- **Cascade deletes** - Deleting a target removes all related data
- **Deduplication** - Findings tracked with `is_duplicate` and `duplicate_of`
- **Soft state** - Scan jobs track status transitions: pending → queued → running → completed/failed

## Worker System

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   FastAPI    │────>│    Redis     │────>│   Celery     │
│   API        │     │   Queue      │     │   Workers    │
│              │<────│   (broker)   │<────│   (consumers)│
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                     ┌──────▼──────┐
                     │   Celery    │
                     │   Beat      │
                     │ (scheduler) │
                     └─────────────┘
```

### Task Queues

| Queue | Purpose | Tasks |
|-------|---------|-------|
| `scans` | Scan execution | `execute_scan`, `execute_recon_only` |
| `reports` | Report generation | `generate_report` |
| `default` | General tasks | Future use |

### Task Lifecycle

1. API creates `ScanJob` (status: `pending`)
2. API queues Celery task → `ScanJob` status: `queued`
3. Worker picks up task → `ScanJob` status: `running`
4. Worker executes pipeline stages
5. Each stage persists results
6. Worker marks `ScanJob` status: `completed` or `failed`
7. WebSocket notifies subscribers
