# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ghosted V8 - A security tool that identifies potentially vulnerable "ghosted" domains in Content Security Policy (CSP) headers. It finds domains trusted by websites but available for registration, creating trust inheritance risks.

## Key Commands

### Build & Development

```bash
# Build application
go build -o ghosted cmd/ghosted/main.go

# Install dependencies
go mod download

# Test Route53 connection
go run test_route53.go
```

### Application Usage

```bash
# Single domain scan (passive only)
./ghosted scan example.com

# Single domain with wordlist bruteforce
./ghosted scan example.com --wordlists 1

# Batch scan multiple domains
./ghosted batch targets.txt --wordlists 1

# Beast mode (high-performance, 1000 DNS/sec)
./ghosted beast hosts.txt --wordlists 0  # Passive only
./ghosted beast hosts.txt --wordlists 1  # All wordlists

# PublicWWW research on scan results
./ghosted research output/beast_example.com_20251003_120000
./ghosted research output/beast_example.com_20251003_120000 --all  # Research ALL domains

# Generate executive report
./ghosted sendit output/beast_example.com_20251003_120000

# Regenerate reports from existing scan
./ghosted report output/scan_example.com_20251001_120000

# Organize scans into hot/archive
./ghosted organize
```

### Environment Configuration

Required environment variables (`.env` file):
- `AWS_ACCESS_KEY_ID` - AWS access key for Route53
- `AWS_SECRET_ACCESS_KEY` - AWS secret key
- `AWS_REGION` - AWS region (default: us-east-1)
- `PUBLICWWW_KEY` - PublicWWW API key (optional, for research)

## Architecture

### Core Processing Pipeline

1. **Enumeration Phase** (`scanner/enumerator.go`)
   - Passive discovery via subfinder
   - Active bruteforce via dnsx with wordlists
   - Wordlist progress tracking (resume capability)
   - Configurable DNS concurrency (300 default, 1000 beast mode)

2. **CSP Fetching Phase** (`scanner/csp_fetcher.go`)
   - Concurrent HTTP requests (200 workers)
   - Extract CSP headers from discovered subdomains
   - Store results in isolated scan database

3. **Parsing Phase** (`scanner/parser.go`)
   - Extract external domains from CSP directives
   - Identify trust relationships
   - Root domain extraction
   - Category classification

4. **Availability Checking Phase** (`checker/route53.go`)
   - AWS Route53 CheckDomainAvailability API
   - Rate-limited concurrent checks
   - Cost tracking ($0.01 per check)
   - Results stored with timestamps

5. **Research Phase** (`checker/publicwww.go`)
   - Optional PublicWWW API integration
   - Research domain usage across web
   - 60-second rate limit between requests
   - Store usage statistics

6. **Report Generation Phase** (`reporter/`)
   - High-risk findings (`high_risk.go`)
   - CSP posture analysis (`csp_posture.go`)
   - Bug bounty reports (`bugbounty.go`)
   - Security architecture guidance (`security_architecture.go`)
   - Impact analysis (`impact.go`)
   - Executive "send it" report (`sendit.go`)

### Package Structure

```
cmd/ghosted/main.go      # CLI entry point, command orchestration
scanner/
  enumerator.go         # Subdomain discovery (subfinder + dnsx)
  csp_fetcher.go        # Concurrent CSP header fetching
  parser.go             # CSP parsing and domain extraction
checker/
  route53.go            # AWS Route53 availability checking
  publicwww.go          # PublicWWW domain research
reporter/
  high_risk.go          # Available domain reports
  csp_posture.go        # Organizational security posture
  bugbounty.go          # Per-domain bug bounty submissions
  security_architecture.go  # Strategic guidance
  impact.go             # Domain impact analysis
  sendit.go             # Executive summary report
storage/
  database.go           # SQLite persistence (isolated per scan)
logs/
  logger.go             # Structured logging and receipts
danger/
  danger_list.go        # Threat intelligence flagging
```

### Database Schema

Each scan creates an isolated SQLite database in `scan_dir/database.db` with:

- `subdomains` - Discovered subdomains with sources
- `csp_records` - CSP headers from origin domains
- `external_domains` - Domains found in CSP policies with reference counts
- `trust_relationships` - Origin → External domain mappings
- `availability_checks` - Route53 availability results
- `publicwww_results` - Domain usage research data
- `high_risk_findings` - Critical vulnerability records
- `wordlist_progress` - Completed wordlists (for resume capability)

### Output Structure

```
output/
├── scan_<domain>_<timestamp>/       # Single scan
├── beast_<domain>_<timestamp>/      # Beast mode scan
├── hot/                             # Scans with available domains
└── archive/                         # Clean scans (no findings)

Each scan directory contains:
  database.db              # SQLite database
  logs/                    # Execution logs
  reports/
    high_risk_findings.md
    csp_posture.md
    security_architecture.md
    bugbounty/             # Per-domain reports
  impact/                  # Per-domain impact analysis
  SENDIT_REPORT.md         # Executive summary
```

## Key Features & Implementation Details

### Isolated Scan Architecture
- Each scan is self-contained in its own timestamped directory
- No shared databases between scans
- Easy to archive, share, or delete individual scans
- Automatic organization into `hot/` (findings) and `archive/` (clean)

### Resume Capability
- Wordlist progress tracked in database
- Resume scans with `./ghosted scan <domain> --wordlists N`
- Skips already-completed wordlists automatically
- Preserves all previously discovered subdomains

### Concurrent Processing
- CSP fetching: 200 concurrent HTTP workers
- DNS resolution: 300 concurrent (scan mode) or 1000 (beast mode)
- Route53 checking: 10 concurrent workers
- PublicWWW research: Sequential (60s rate limit)

### Danger List Integration
- External file: `danger_list.txt`
- One domain per line, comments with `#`
- Flags domains in database and reports
- Use with `--danger-list path/to/threat_intel.txt`

### Skip Existing Scans
- Automatically detects existing scans in `output/`, `output/hot/`, `output/archive/`
- Skips re-scanning if domain already scanned
- Use `ghosted report <dir>` to regenerate reports for existing scans

## Important Implementation Notes

### Route53 as Single Provider
V8 uses **only** AWS Route53 for domain availability checking. There is no fallback to other providers (previous versions used WhoAPI). Ensure AWS credentials are configured.

### No WHOIS Expiration Data
V8 does not fetch or track WHOIS expiration dates. It only checks current availability status via Route53 API.

### Database Isolation is Critical
- NEVER create shared databases across scans
- Each scan must have `database.db` in its own directory
- Use `storage.New(scanPath)` for new scans
- Use `storage.OpenExisting(dbPath)` for existing scans

### Report Data Completeness
Reports must show **ALL** data without truncation:
- Complete lists of affected domains
- All trusting relationships
- Full PublicWWW research results
- Use "Top 10 + Complete List" pattern for summaries

### Wordlist Level Behavior
- `--wordlists 0` or no flag = Passive enumeration only (subfinder)
- `--wordlists 1` = Run ALL wordlists in `wordlists/` directory
- Higher numbers ignored (treated as 1)

### Beast Mode Characteristics
- Uses `NewEnumeratorWithConcurrency(db, level, 1000)` for DNS
- Prefix: `beast_<domain>_<timestamp>`
- High performance for large-scale scanning
- Same pipeline, just faster enumeration

## Development Guidelines

### Adding New Commands
Edit `cmd/ghosted/main.go` switch statement and add handler function. Follow existing patterns for scan organization and database isolation.

### Adding New Report Types
Create new file in `reporter/` package. Implement function that accepts `*storage.Database` and `scanPath`. Register in report generation phase in `main.go`.

### Modifying Database Schema
Edit `storage/database.go` `createSchema()` function. Consider backward compatibility with existing scan databases.

### External Tool Dependencies
- `tools/subfinder` - Passive subdomain enumeration (ProjectDiscovery)
- `tools/dnsx` - Active DNS bruteforcing (ProjectDiscovery)
- Both must be present and executable
- Wordlists from SecLists (FUZZSUBS_CYFARE)

## Common Development Tasks

### Testing Route53 Connection
```bash
go run test_route53.go
```

### Querying Scan Results
```bash
sqlite3 output/scan_dir/database.db "SELECT * FROM availability_checks WHERE available = 1"
```

### Debugging PublicWWW Integration
Check for `PUBLICWWW_KEY` in environment or `publicwww.key` file. API enforces 60-second rate limit.

### Monitor Long-Running Scans
```bash
./monitor.sh output/beast_example.com_20251003_120000
```

## API Cost Tracking

- Route53: $0.01 per domain check (tracked in database)
- PublicWWW: Free tier (10 searches/day) or paid tiers
- Cost is logged in `availability_checks.cost_usd` column
