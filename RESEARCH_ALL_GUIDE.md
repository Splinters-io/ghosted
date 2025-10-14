# Research All Domains Guide

## Overview

The `--all` flag for the research command allows you to research **all 86 external domains** found in CSP headers via PublicWWW, not just the 4 available ones.

## Why Research All Domains?

### Use Cases

1. **Find More Available Domain Candidates**
   - Some domains might be expiring soon
   - Some might be available but not checked yet
   - Identify high-value targets for availability checking

2. **Impact Analysis**
   - See which CSP domains are most widely used
   - Prioritize security efforts on high-usage domains
   - Understand supply chain dependencies

3. **Threat Intelligence**
   - Track how third-party domains are used
   - Identify potential future vulnerabilities
   - Monitor domain usage trends

## Commands

### Default: Research Available Domains Only
```bash
ghosted research output/beast_zoom.us_20251003_091855
```
- Researches: 4 domains (available only)
- Time: ~4 minutes (60s rate limit × 4)
- API calls: 4

### Research All CSP Domains
```bash
ghosted research output/beast_zoom.us_20251003_091855 --all
```
- Researches: 86 domains (all external domains from CSP)
- Time: ~86 minutes (~1.5 hours)
- API calls: 86

## Expected Output

### Default Mode
```
Mode: Research AVAILABLE domains only

Found 4 domains to research

[*] PublicWWW Research Phase
    Researching 4 domains
    Rate limit: 1m0s between requests

[1/4] apiurl.org
   [*] Searching PublicWWW for: apiurl.org
   [OK] Found 4 sites using apiurl.org (HTML response)
[2/4] dcbap.com
   [*] Rate limiting (waiting 1m0s)...
   [OK] Found 36 sites using dcbap.com (HTML response)
...
```

### --all Mode
```
Mode: Research ALL external domains

Found 86 domains to research

[*] PublicWWW Research Phase
    Researching 86 domains
    Rate limit: 1m0s between requests

[1/86] zoom.us
   [*] Searching PublicWWW for: zoom.us
   [OK] Found 15234 sites using zoom.us (HTML response)
[2/86] google.com
   [*] Rate limiting (waiting 1m0s)...
   [OK] Found 9876543 sites using google.com (HTML response)
...

[OK] PublicWWW research complete
     Total API requests: 86
     Results saved to database

[*] Next steps:
    1. Check which researched domains show high usage counts
    2. Run availability checks on interesting domains
    3. Generate send it report
```

## Workflow Examples

### Workflow 1: Quick Assessment (Available Only)
```bash
# 1. Scan target
./ghosted beast targets.txt

# 2. Research available domains only (4 min)
./ghosted research output/beast_zoom.us_20251003_091855

# 3. Generate report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

### Workflow 2: Deep Intelligence (All Domains)
```bash
# 1. Scan target
./ghosted beast targets.txt

# 2. Research ALL CSP domains (~90 min)
./ghosted research output/beast_zoom.us_20251003_091855 --all

# 3. Query database to find interesting domains
sqlite3 output/beast_zoom.us_20251003_091855/database.db \
  "SELECT domain, site_url, snippet FROM publicwww_results
   WHERE snippet LIKE '%Found % websites%'
   ORDER BY CAST(substr(snippet, 7, instr(snippet, ' websites') - 7) AS INTEGER) DESC
   LIMIT 20;"

# 4. Identify high-usage domains that might be available
# 5. Run additional availability checks if needed
# 6. Generate report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

### Workflow 3: Overnight Run
```bash
# Run research in background overnight
nohup ./ghosted research output/beast_zoom.us_20251003_091855 --all > research.log 2>&1 &

# Check progress
tail -f research.log

# Next morning: generate report
./ghosted sendit output/beast_zoom.us_20251003_091855
```

## Database Queries

### Find Top Used Domains
```sql
SELECT
  domain,
  snippet
FROM publicwww_results
WHERE snippet LIKE '%Found % websites%'
ORDER BY
  CAST(
    substr(snippet, 7, instr(snippet, ' websites') - 7)
    AS INTEGER
  ) DESC
LIMIT 20;
```

### Find Domains with Code Snippets (Paid API)
```sql
SELECT
  domain,
  COUNT(*) as site_count,
  GROUP_CONCAT(site_url, ', ') as sites
FROM publicwww_results
WHERE snippet NOT LIKE '%HTML response%'
GROUP BY domain
ORDER BY site_count DESC;
```

### Cross-Reference with Available Domains
```sql
SELECT
  p.domain,
  a.status,
  p.snippet
FROM publicwww_results p
LEFT JOIN availability_checks a ON p.domain = a.domain
WHERE a.status = 'AVAILABLE'
ORDER BY p.domain;
```

## Time Estimation

**Rate Limit:** 60 seconds between requests

| Domains | Time Required | Notes |
|---------|--------------|-------|
| 4 (available) | 4 minutes | Quick assessment |
| 20 | 20 minutes | Sample research |
| 50 | 50 minutes | Medium scan |
| 86 (all) | 86 minutes | Full intelligence |
| 100+ | 1.7+ hours | Large targets |

## API Key Tiers

### Free Tier (Current)
- Returns HTML with usage counts
- No code snippets
- Basic intelligence: "Found X websites using domain"
- Good for: Identifying high-usage domains

### Paid Tiers
- Returns JSON with full data
- Includes code snippets showing actual usage
- Site URLs and context
- Better for: Detailed attack analysis

## Best Practices

1. **Start Small**
   - Use default mode first (available only)
   - Test with `--all` on small scans

2. **Overnight Runs**
   - Schedule `--all` for overnight
   - Use `nohup` or `screen` for long runs

3. **Database Analysis**
   - Query results before generating reports
   - Identify patterns in domain usage
   - Prioritize high-impact targets

4. **Incremental Research**
   - Research available domains immediately
   - Research all domains overnight
   - Combine results in final report

## Limitations

1. **Rate Limiting**
   - 60 seconds enforced between requests
   - Cannot be bypassed
   - Plan for long research times

2. **Free Tier Restrictions**
   - HTML responses only
   - Usage counts but no snippets
   - Upgrade for detailed data

3. **API Quotas**
   - Free: 10 searches/day
   - Basic: 100 searches/day
   - Plan research accordingly

## Next Features

Potential enhancements:
- [ ] Parallel research (multiple API keys)
- [ ] Resume interrupted research
- [ ] Smart prioritization (skip known domains)
- [ ] Export research results to CSV
- [ ] Visual charts of domain usage
