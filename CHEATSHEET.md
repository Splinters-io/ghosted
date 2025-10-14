# Ghosted V8 - Cheat Sheet

## Quick Start

```bash
# 1. Scan target domains
./ghosted beast targets.txt

# 2. Research ALL domains via PublicWWW (automatic intelligence gathering)
./ghosted research output/beast_zoom.us_20251003_091855

# 3. Generate executive report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

---

## Core Commands

### Scanning

```bash
# Single domain scan
./ghosted scan example.com

# Batch scan multiple domains
./ghosted batch targets.txt

# Beast mode (high-performance, 500 DNS concurrency)
./ghosted beast hosts.txt
```

### Domain Research

```bash
# Research ALL CSP domains via PublicWWW (default)
./ghosted research output/beast_zoom.us_20251003_091855

# Research only available domains
./ghosted research output/beast_zoom.us_20251003_091855 --available-only
```

### Report Generation

```bash
# Generate executive "Send It" report
./ghosted sendit output/beast_zoom.us_20251003_091855

# Regenerate individual domain reports
./ghosted report output/beast_zoom.us_20251003_091855
```

---

## Flags & Options

### Wordlist Levels

```bash
# Passive enumeration only (no brute force)
./ghosted beast hosts.txt --wordlists 0

# All wordlists (full brute force)
./ghosted beast hosts.txt --wordlists 1

# Custom wordlist level
./ghosted scan example.com --wordlists 3
```

### Danger List

```bash
# Use custom threat intelligence list
./ghosted beast hosts.txt --danger-list threat_intel.txt
```

---

## Environment Variables

### Required Configuration

```bash
# AWS Credentials (for Route53 domain availability checking)
export AWS_ACCESS_KEY_ID=your_aws_access_key
export AWS_SECRET_ACCESS_KEY=your_aws_secret_key
export AWS_REGION=us-east-1

# PublicWWW (domain usage research - optional)
export PUBLICWWW_KEY=your_publicwww_key
```

### Optional Configuration

```bash
# Database path
export DB_PATH=ghosted.db

# Output directory
export OUTPUT_DIR=output

# DNS Concurrency (default: 300 for scan, 1000 for beast)
export DNS_CONCURRENCY=300

# Route53 Concurrency (default: 10)
export ROUTE53_CONCURRENCY=10
```

---

## Workflow Examples

### Quick Assessment (Available Domains Only)

```bash
# 1. Scan target
./ghosted beast targets.txt

# 2. Research available domains only (~4 min)
./ghosted research output/beast_zoom.us_20251003_091855 --available-only

# 3. Generate report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

### Deep Intelligence (All CSP Domains)

```bash
# 1. Scan target
./ghosted beast targets.txt

# 2. Research ALL CSP domains (~90 min for 86 domains)
./ghosted research output/beast_zoom.us_20251003_091855

# 3. Generate comprehensive report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

### Overnight Run

```bash
# Run research in background overnight
nohup ./ghosted research output/beast_zoom.us_20251003_091855 > research.log 2>&1 &

# Check progress
tail -f research.log

# Next morning: generate report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

---

## Output Structure

```
output/
├── beast_zoom.us_20251003_091855/
│   ├── database.db              # SQLite database with all findings
│   ├── SENDIT_REPORT.md         # Executive report with PublicWWW data
│   ├── impact/                  # Individual domain reports
│   │   ├── dcbap.com.md
│   │   └── apiurl.org.md
│   └── logs/                    # Scan logs and receipts
```

---

## Database Queries

### Find Top Used Domains

```sql
sqlite3 output/beast_zoom.us_20251003_091855/database.db "
SELECT domain, COUNT(*) as site_count
FROM publicwww_results
GROUP BY domain
ORDER BY site_count DESC
"
```

### View Available Domains

```sql
sqlite3 output/beast_zoom.us_20251003_091855/database.db "
SELECT domain, status, checked_at
FROM availability_checks
WHERE status = 'AVAILABLE'
ORDER BY domain
"
```

### Cross-Reference PublicWWW with Available Domains

```sql
sqlite3 output/beast_zoom.us_20251003_091855/database.db "
SELECT p.domain, COUNT(*) as websites_using, a.status
FROM publicwww_results p
LEFT JOIN availability_checks a ON p.domain = a.domain
WHERE a.status = 'AVAILABLE'
GROUP BY p.domain
ORDER BY websites_using DESC
"
```

### View All PublicWWW Results

```sql
sqlite3 output/beast_zoom.us_20251003_091855/database.db "
SELECT domain, site_url, snippet
FROM publicwww_results
ORDER BY domain, site_url
"
```

---

## Time Estimates

| Operation | Domains | Time Required | Notes |
|-----------|---------|--------------|-------|
| Scan | 100 | ~5-10 min | Depends on CSP complexity |
| Research (available) | 4 | ~4 min | 60s rate limit × 4 |
| Research (all) | 86 | ~90 min | 60s rate limit × 86 |
| Report generation | Any | <1 min | Instant |

---

## PublicWWW API Tiers

### Free Tier (Current)
- Returns CSV with domain names and traffic ranks
- 10 searches/day limit
- Good for: Identifying high-usage domains
- Format: `domain;traffic_rank`

### Paid Tiers
- Returns JSON with full data
- Includes code snippets showing actual usage
- Higher daily limits (100+)
- Better for: Detailed attack analysis

---

## Best Practices

### 1. Start Small
```bash
# Test with available domains first
./ghosted research output/scan_dir --available-only

# Then expand to all domains
./ghosted research output/scan_dir
```

### 2. Overnight Runs
```bash
# Schedule large research jobs overnight
nohup ./ghosted research output/scan_dir > research.log 2>&1 &
```

### 3. Database Analysis
```bash
# Query results before generating reports
sqlite3 output/scan_dir/database.db "SELECT * FROM publicwww_results"

# Identify patterns in domain usage
sqlite3 output/scan_dir/database.db "SELECT domain, COUNT(*) FROM publicwww_results GROUP BY domain"
```

### 4. Incremental Research
```bash
# Day 1: Quick assessment
./ghosted beast targets.txt
./ghosted research output/beast_... --available-only
./ghosted sendit output/beast_...

# Day 2: Deep intelligence (overnight)
nohup ./ghosted research output/beast_... > research.log 2>&1 &

# Day 3: Final report
./ghosted sendit output/beast_...
```

---

## Troubleshooting

### AWS Credentials Issues

```bash
# Check if AWS credentials are set
echo $AWS_ACCESS_KEY_ID
echo $AWS_REGION

# Set AWS credentials
export AWS_ACCESS_KEY_ID=your_key_here
export AWS_SECRET_ACCESS_KEY=your_secret_here
export AWS_REGION=us-east-1

# Or use AWS credentials file (~/.aws/credentials)
aws configure
```

### PublicWWW API Key Issues

```bash
# Check if API key is set
echo $PUBLICWWW_KEY

# Set API key
export PUBLICWWW_KEY=your_key_here

# Or use key file
echo "your_key_here" > publicwww.key
```

### Rate Limiting

```bash
# PublicWWW enforces 60s between requests
# This is automatic - no configuration needed
# Plan for long research times on large datasets
```

### Database Errors

```bash
# Check database exists
ls -lh output/beast_zoom.us_20251003_091855/database.db

# View database schema
sqlite3 output/beast_zoom.us_20251003_091855/database.db ".schema"

# Check for results
sqlite3 output/beast_zoom.us_20251003_091855/database.db "SELECT COUNT(*) FROM publicwww_results"
```

---

## Report Sections

### SENDIT_REPORT.md Contains:

1. **Executive Summary**
   - Critical vulnerability overview
   - Impact scale and affected domains
   - PublicWWW statistics
   - Attack cost vs. blast radius

2. **Summary Table**
   - Available domains
   - Affected application counts
   - CSP directives

3. **Per-Domain Analysis**
   - Availability status
   - Affected domains list
   - CSP position and directive
   - Attack scenarios
   - Capabilities granted
   - PublicWWW intelligence with traffic ranks

4. **Critical Risk Assessment**
   - Highest impact domains
   - Multi-domain trust risks

5. **Immediate Actions**
   - CSP removal recommendations
   - Verification steps
   - Monitoring guidance

---

## Common Use Cases

### Bug Bounty Hunting
```bash
./ghosted beast targets.txt
./ghosted research output/beast_... --available-only
./ghosted sendit output/beast_...
# Submit SENDIT_REPORT.md to bug bounty program
```

### Security Assessment
```bash
./ghosted beast enterprise_domains.txt
./ghosted research output/beast_...
./ghosted sendit output/beast_...
# Present executive summary to stakeholders
```

### Threat Intelligence
```bash
./ghosted beast threat_targets.txt
./ghosted research output/beast_...
# Query database for patterns and trends
sqlite3 output/beast_*/database.db "SELECT domain, COUNT(*) FROM publicwww_results GROUP BY domain"
```

### Supply Chain Analysis
```bash
./ghosted beast vendor_domains.txt
./ghosted research output/beast_...
# Identify third-party domain dependencies
# Cross-reference with availability status
```

---

## Tips & Tricks

### Parallel Research (Multiple API Keys)
```bash
# Split domains across multiple keys
# Key 1: domains 1-43
# Key 2: domains 44-86
# Run simultaneously to halve research time
```

### Resume Interrupted Research
```bash
# Check what's already researched
sqlite3 output/beast_*/database.db "SELECT DISTINCT domain FROM publicwww_results"

# Research will skip already-completed domains
./ghosted research output/beast_...
```

### Export Results to CSV
```bash
# Export PublicWWW results
sqlite3 -header -csv output/beast_*/database.db "SELECT * FROM publicwww_results" > publicwww_export.csv

# Export available domains
sqlite3 -header -csv output/beast_*/database.db "SELECT * FROM availability_checks WHERE status='AVAILABLE'" > available_domains.csv
```

### Batch Process Multiple Scans
```bash
# Research all scans in output directory
for dir in output/beast_*/; do
  echo "Researching $dir..."
  ./ghosted research "$dir"
  ./ghosted sendit "$dir"
done
```

---

## Quick Reference

| Command | Purpose | Time |
|---------|---------|------|
| `ghosted beast targets.txt` | High-performance scan | 5-10 min |
| `ghosted research <dir>` | PublicWWW research (all domains) | 60-90 min |
| `ghosted research <dir> --available-only` | PublicWWW research (available only) | 3-5 min |
| `ghosted sendit <dir>` | Generate executive report | <1 min |
| `ghosted report <dir>` | Regenerate individual reports | <1 min |

---

**For full documentation, see:**
- `README.md` - Project overview
- `CLAUDE.md` - Development guide
- `RESEARCH_ALL_GUIDE.md` - PublicWWW research details
- `PUBLICWWW_INTEGRATION.md` - API integration technical docs
