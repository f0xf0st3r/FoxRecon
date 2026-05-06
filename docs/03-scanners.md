# Scanner Adapters

## Overview

FoxRecon uses the **Strategy Pattern** for tool integration. Every scanner implements the `BaseScanner` interface, enabling:

- Tool interchangeability without pipeline changes
- Consistent output normalization
- Unified error handling
- Test mocking

## BaseScanner Interface

```python
class BaseScanner(ABC):
    tool_name: str = "base"
    tool_version: str = "unknown"

    def __init__(self, binary_path: str, config: ScanConfig | None = None):
        self.binary_path = binary_path
        self.config = config or ScanConfig()

    @abstractmethod
    async def run(self, target: str, **kwargs) -> ScanOutput:
        """Execute the scanner against a target."""

    @abstractmethod
    def parse_output(self, raw: str) -> list[dict]:
        """Parse raw tool output into normalized dictionaries."""
```

### ScanConfig

```python
@dataclass
class ScanConfig:
    timeout: int = 300           # Max execution time
    rate_limit: int = 0          # Requests per second (0 = unlimited)
    threads: int = 10            # Concurrency
    proxy: str | None = None     # HTTP/SOCKS proxy
    extra_args: list[str] = []   # Additional CLI arguments
    wordlist: str | None = None  # Path to wordlist file
    output_dir: str | None = None # Output directory
```

### ScanOutput

```python
@dataclass
class ScanOutput:
    success: bool                         # Whether scan succeeded
    items: list[dict] = []                # Normalized results
    metadata: dict = {}                   # Scan metadata
    errors: list[str] = []                # Error messages
    raw_output: str | None = None         # Raw tool output
    duration_seconds: float = 0.0         # Execution time
```

## Available Scanners

### 1. SubfinderScanner

**Purpose:** Passive subdomain enumeration using OSINT sources.

```python
from internal.scanners import SubfinderScanner, ScanConfig

scanner = SubfinderScanner(
    binary_path="subfinder",
    config=ScanConfig(timeout=300),
)

result = await scanner.run(
    target="example.com",
    sources=None,        # None = use all sources
    recursive=False,     # Enable recursive enumeration
    all_sources=True,    # Use all available sources
)

# result.items:
# [{"domain": "api.example.com", "source": "crtsh", "resolved_ip": "1.2.3.4"}]
```

**Output Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `domain` | str | Discovered subdomain |
| `source` | str | OSINT source that found it |
| `resolved_ip` | str | Resolved IP address |

### 2. HttpxScanner

**Purpose:** Detect live HTTP/HTTPS services and collect fingerprints.

```python
from internal.scanners import HttpxScanner, ScanConfig

scanner = HttpxScanner(
    binary_path="httpx",
    config=ScanConfig(
        timeout=300,
        rate_limit=100,
        threads=50,
    ),
)

# Scan from file
result = await scanner.run(
    target="",
    input_file="/tmp/subdomains.txt",  # One URL per line
    ports=[80, 443, 8080, 8443],
    tech_detect=True,
    title=True,
    status_code=True,
    follow_redirects=True,
)

# result.items:
# [{
#   "url": "https://api.example.com",
#   "host": "api.example.com",
#   "ip": "1.2.3.4",
#   "port": 443,
#   "scheme": "https",
#   "status_code": 200,
#   "title": "API Gateway",
#   "content_type": "application/json",
#   "content_length": 1234,
#   "response_time_ms": 45,
#   "tech": ["Nginx", "React"],
#   "webserver": "nginx/1.24.0",
#   "hash": "abc123...",
# }]
```

### 3. NaabuScanner

**Purpose:** Fast SYN/CONNECT port scanning.

```python
from internal.scanners import NaabuScanner, ScanConfig

scanner = NaabuScanner(
    binary_path="naabu",
    config=ScanConfig(timeout=600),
)

result = await scanner.run(
    target="example.com",
    top_ports=100,        # Scan top N ports
    ports=None,           # Or specific: "80,443,8080"
    syn_scan=True,        # SYN scan (requires root)
)

# result.items:
# [{
#   "host": "example.com",
#   "ip": "1.2.3.4",
#   "port": 80,
#   "protocol": "tcp",
#   "tls": False,
# }]
```

### 4. NucleiScanner

**Purpose:** Template-based vulnerability scanning.

```python
from internal.scanners import NucleiScanner, ScanConfig

scanner = NucleiScanner(
    binary_path="nuclei",
    config=ScanConfig(timeout=1800),
    templates_path="/path/to/nuclei-templates",
    severity_filter="low,medium,high,critical",
    rate_limit=50,
    concurrency=25,
)

result = await scanner.run(
    target="",
    input_file="/tmp/urls.txt",
    severities=["high", "critical"],
    templates=["cves/"],  # Specific template directories
    rate_limit=100,
    concurrency=50,
)

# result.items:
# [{
#   "template_id": "cve-2024-1234",
#   "template_name": "Example CVE Detection",
#   "severity": "high",
#   "host": "example.com",
#   "matched_url": "https://example.com/vulnerable",
#   "cve_ids": ["CVE-2024-1234"],
#   "cwe_ids": ["CWE-79"],
#   "cvss_score": 7.5,
#   "description": "...",
#   "reference": ["https://..."],
#   "tags": ["cve", "xss"],
# }]
```

### 5. FfufScanner (V2)

**Purpose:** Fast web fuzzer for content discovery.

```python
from internal.scanners import FfufScanner, ScanConfig

scanner = FfufScanner(
    binary_path="ffuf",
    config=ScanConfig(timeout=600),
    default_wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt",
)

result = await scanner.run(
    target="https://example.com/FUZZ",  # FUZZ keyword required
    wordlist="/path/to/wordlist.txt",
    extensions="php,html,json,txt",
    methods="GET",
    threads=50,
    recursion=True,
    recursion_depth=4,
    match_status="200,301,403",
)

# result.items:
# [{
#   "url": "https://example.com/admin",
#   "path": "admin",
#   "status": 200,
#   "length": 4521,
#   "words": 120,
#   "lines": 45,
#   "content_type": "text/html",
#   "redirect_location": "",
# }]
```

### 6. GowitnessScanner (V2)

**Purpose:** Web screenshot capture.

```python
from internal.scanners import GowitnessScanner, ScanConfig

scanner = GowitnessScanner(
    binary_path="gowitness",
    config=ScanConfig(timeout=600),
)

result = await scanner.run(
    target="",
    input_file="/tmp/urls.txt",
    screenshot_path="/tmp/screenshots",
    resolution_x=1440,
    resolution_y=900,
    threads=8,
    timeout=30,
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
)

# Results stored in SQLite database at screenshot_path/gowitness.sqlite3
# result.items contain parsed screenshot metadata
```

## Recon Engine

The `ReconEngine` orchestrates the full scan pipeline:

```python
from internal.recon import ReconEngine, ScanPipelineConfig
from internal.config import get_settings

settings = get_settings()
engine = ReconEngine(settings)

config = ScanPipelineConfig(
    run_recon=True,
    run_httpx=True,
    run_naabu=True,
    run_nuclei=True,
    naabu_top_ports=100,
    nuclei_rate_limit=50,
    nuclei_concurrency=25,
    timeout=3600,
)

# Execute pipeline
result = await engine.run_pipeline(
    db=db_session,
    scan_job=scan_job_record,
    target_value="example.com",
    config=config,
)

# result:
# PipelineResult(
#   scan_job_id=uuid,
#   success=True,
#   stages_completed=["recon", "httpx", "naabu", "nuclei"],
#   subdomains_found=42,
#   live_hosts_found=15,
#   ports_found=28,
#   findings_found=7,
#   duration_seconds=245.3,
# )
```

### Pipeline Stages

| Stage | Tool | Database Tables | Output |
|-------|------|----------------|--------|
| `recon` | subfinder | `subdomains` | List of subdomains |
| `live_hosts` | httpx | `live_hosts`, `technologies` | HTTP fingerprints |
| `port_scan` | naabu | `ports` | Open ports + services |
| `vuln_scan` | nuclei | `findings`, `vulnerabilities` | Security findings |

## Worker System

Scans are executed asynchronously via Celery:

```python
from internal.workers.tasks import execute_scan_task

# Queue a scan task
task = execute_scan_task.apply_async(
    kwargs={
        "scan_job_id": str(scan_job.id),
        "target_value": "example.com",
        "target_id": str(target.id),
        "pipeline_config": {
            "run_recon": True,
            "run_httpx": True,
            "run_naabu": True,
            "run_nuclei": True,
        },
    },
    queue="scans",
)

# task.id is the Celery task ID for tracking
```

### Running Workers

```bash
# Single worker
celery -A internal.workers.celery_app.celery_app worker --loglevel=info

# Multiple workers with concurrency
celery -A internal.workers.celery_app.celery_app worker \
  --concurrency=4 \
  --queues=scans,default \
  --max-tasks-per-child=100 \
  --loglevel=info

# Scheduler for recurring scans
celery -A internal.workers.celery_app.celery_app beat --loglevel=info
```

## Secure Subprocess Execution

All tool execution goes through `SecureProcess`:

```python
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

policy = ExecutionPolicy(
    timeout=300,
    max_output_size=50 * 1024 * 1024,  # 50MB
    workdir="/tmp/foxrecon_sandbox",
    allowed_binaries={"subfinder", "httpx", "naabu", "nuclei"},
)

proc = SecureProcess(policy=policy)

result = await proc.execute(
    binary="subfinder",
    args=["-d", "example.com", "-json", "-silent"],
    input_data=None,
    timeout=300,
)

# result.returncode, result.stdout, result.stderr, result.duration_seconds
```

### Security Guarantees

- **No shell=True** - Arguments passed as explicit lists
- **Input validation** - All arguments checked for injection patterns
- **Binary whitelist** - Only allowed binaries can execute
- **Resource limits** - Timeout, memory, and output size caps
- **Clean environment** - No inherited secrets or sensitive variables
- **Sandboxed workdir** - Isolated working directory
