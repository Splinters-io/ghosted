# PublicWWW Integration

## Overview

Ghosted V8 now includes PublicWWW integration to research how available domains are being used across the web. This provides additional intelligence for impact analysis and bug bounty submissions.

## Features Added

### 1. Database Schema
- **New table:** `publicwww_results`
  - Stores site URLs and code snippets showing domain usage
  - Links to available domains for impact analysis

### 2. PublicWWW Research Command
```bash
ghosted research <scan_directory>
```

**What it does:**
- Queries PublicWWW API for each available domain
- Searches for websites currently loading resources from these domains
- Stores results in database with snippets showing actual usage
- Respects PublicWWW rate limits (60 seconds between requests)

**Requirements:**
- PublicWWW API key (get from https://publicwww.com)
- Set via environment variable: `export PUBLICWWW_KEY=your_key`
- Or create file: `echo "your_key" > publicwww.key`

### 3. Enhanced Send It Report
```bash
ghosted sendit <scan_directory>
```

**New intelligence included:**
- **PublicWWW data section** for each available domain
- Shows websites currently using the domain
- Code snippets demonstrating actual usage
- Attack analysis based on real-world usage patterns

## Workflow

### Option 1: Research After Scan
```bash
# 1. Run scan to find available domains
./ghosted beast targets.txt

# 2. Research available domains via PublicWWW
./ghosted research output/beast_zoom.us_20251003_091855

# 3. Generate report with PublicWWW data
./ghosted sendit output/beast_zoom.us_20251003_091855
```

### Option 2: Manual Research
If you already have scan results:
```bash
# Research existing scan
./ghosted research output/old_scan_directory

# Regenerate report with new data
./ghosted sendit output/old_scan_directory
```

## Example Output

### Research Command
```
╔══════════════════════════════════════════════════════════════╗
║  GHOSTED V8 - PublicWWW Domain Research                     ║
╚══════════════════════════════════════════════════════════════╝

Scan directory: output/beast_zoom.us_20251003_091855

Found 4 available domains to research

[*] PublicWWW Research Phase
    Researching 4 available domains
    Rate limit: 1m0s between requests

[1/4] dcbap.com
   [*] Searching PublicWWW for: dcbap.com
   [OK] Found 15 sites using dcbap.com
   [*] Rate limiting (waiting 1m0s)...

[2/4] apiurl.org
   [*] Searching PublicWWW for: apiurl.org
   [OK] Found 3 sites using apiurl.org
   ...

[OK] PublicWWW research complete
     Total API requests: 4
     Results saved to database
```

### Send It Report Section
```markdown
### PublicWWW Intelligence

**Found 15 websites currently using dcbap.com:**

- **https://example1.com**
  ```
  <script src="https://s.dcbap.com/analytics.js"></script>
  ```

- **https://example2.com**
  ```
  var endpoint = "https://api.dcbap.com/track";
  ```

**Analysis:**
These websites are currently loading resources from `dcbap.com`. If an attacker registers this domain, they could:
- Replace legitimate resources with malicious ones
- Track which sites/users are accessing the domain
- Identify high-value targets
- Stage watering hole attacks
```

## Rate Limiting

PublicWWW API has rate limits:
- **Recommended:** 60 seconds between requests
- **Automatically enforced** by Ghosted
- Research of 4 domains takes ~4 minutes

## Cost

PublicWWW pricing (as of 2025):
- Free tier: 10 searches/day
- Basic: $29/month for 100 searches/day
- Pro: $99/month for 1000 searches/day

Each available domain = 1 API request

## Benefits

1. **Enhanced Impact Analysis**
   - See real websites affected by domain takeover
   - Quantify actual blast radius beyond CSP

2. **Bug Bounty Evidence**
   - Concrete proof of domain usage
   - Code snippets showing vulnerability context
   - Demonstrates real-world exploitability

3. **Attack Intelligence**
   - Identify high-value targets using the domain
   - Understand how domain is actually used
   - Prioritize domains based on actual usage

4. **Responsible Disclosure**
   - Identify additional affected parties
   - Contact sites using the available domain
   - Prevent widespread exploitation

## Template Integration

The send it report template (`templates/sendit_report.tmpl`) includes:
- Conditional PublicWWW section
- Formatted results with snippets
- Attack analysis based on usage patterns
- Call to action if no data exists

## Database Schema

```sql
CREATE TABLE publicwww_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    site_url TEXT NOT NULL,
    snippet TEXT,
    researched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain, site_url)
);
```

## Implementation Files

- `checker/publicwww.go` - PublicWWW API client
- `reporter/sendit.go` - Report generation with PublicWWW data
- `templates/sendit_report.tmpl` - Report template
- `storage/database.go` - Schema and query methods
- `cmd/ghosted/main.go` - CLI commands

## Future Enhancements

Potential additions:
- [ ] Historical domain usage tracking
- [ ] Automatic notification when domain is used
- [ ] Integration with security.txt detection
- [ ] Export PublicWWW data to CSV
- [ ] Correlation with affected domain infrastructure
