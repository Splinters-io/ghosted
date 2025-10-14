# Ghosted V8 - Requirements Document

## Core Mission
Find subdomain takeover vulnerabilities through CSP trust erosion analysis.

---

## Report Requirements (CRITICAL)

### 1. High-Risk Findings Report
**When:** Domains exist/available that appear in CSP policies
**Format:** Markdown
**Contents:**
- Domain name
- Availability status (AVAILABLE, EXPIRED, REGISTERED)
- Which applications trust this domain (complete list, NO truncation)
- Attack vectors enabled (XSS, HTML injection, CSRF, media replacement, tracking)
- Severity rating
- Proof of concept commands
- Bug bounty submission template

### 2. Organizational CSP Statistics
**Purpose:** High-level security posture view
**Format:** Markdown + CSV
**Contents:**
- Total subdomains scanned
- Subdomains with CSP headers (count + percentage)
- Total unique external domains trusted
- **Top 10 Most Referenced** (highlights for executives)
- **COMPLETE list of ALL external domains** (FULL DATA, zero truncation)
- Breakdown by category (Analytics, CDN, Cloud, Business Services, etc.)
- CSP policy strength distribution (Strong/Moderate/Weak/None)
- Dangerous directives count (unsafe-inline, unsafe-eval, wildcards)
- Number of high-risk external dependencies (referenced >10 times)

**CSV Export:**
- External Domain, Reference Count, Category, Risk Level, Complete List of Trusting Domains
- NO truncation - all trusting domains included

### 3. Bug Bounty Reports
**Format:** Markdown per affected domain
**Location:** `reports/bugbounty/<affected_domain>/`
**Contents:**
- Title (e.g., "Subdomain Takeover via Expired domain.com in CSP")
- Summary (2-3 sentences)
- Affected applications (complete list)
- Available/expired domain details
- Attack scenarios:
  * XSS injection
  * HTML injection
  * CSRF token theft
  * Media/resource replacement
  * Customer tracking/data exfiltration
- Proof of concept:
  * Registration commands
  * DNS configuration
  * Exploitation steps
  * curl commands to replicate
- Impact assessment
- Remediation steps
- Timeline for responsible disclosure

### 4. Security Architecture Reports
**Purpose:** Guide security teams on CSP posture improvements
**Format:** Markdown
**Contents:**
- Executive summary
- Supply chain risk assessment
- Concentration risk (dependencies on few providers)
- Policy weaknesses by application
- Recommendations:
  * Strategic (organization-wide)
  * Tactical (immediate fixes)
  * Monitoring & detection
- Implementation roadmap

### 5. Impact Reports
**When:** Domains witnessed as expired or available
**Format:** Markdown
**Contents:**
- Domain status history
- Current registration status
- Applications affected (COMPLETE list)
- Attack surface analysis:
  * XSS via script-src
  * HTML injection via frame-src/style-src
  * CSRF resurrection (CSP allows cross-origin requests)
  * Media replacement (img-src, media-src)
  * Customer tracking (connect-src)
- Business impact severity
- Proof receipts (screenshots, DNS queries, API responses)

---

## Feature Requirements

### Scanner
- Subdomain enumeration (subfinder)
- Active DNS bruteforcing (dnsx with wordlists)
- CSP header fetching (concurrent HTTP requests)
- Domain extraction from CSP directives
- Root domain extraction (public suffix list)

### Availability Checker
- **AWS Route53 ONLY** (no fallback providers)
- Check domain availability status
- Log all API calls for receipts
- Cost tracking ($0.01 per check)
- NO WHOIS expiration data (removed for V8)

### Danger List (Threat Intelligence)
- External file: `danger_list.txt`
- Format: One domain per line, comments with #
- Flag domains in reports that match danger list
- Categories:
  * Known malicious infrastructure
  * Expired high-value domains
  * Compromised CDNs
  * Threat actor controlled domains

### Storage
- **Isolated per scan:** `scan_<target>_<timestamp>/`
- SQLite database per scan
- No shared databases
- Easy archiving: entire scan in one folder

### Logging (Receipts)
- Command executed
- Timestamp
- API calls made (Route53 requests/responses)
- Errors encountered
- Scan statistics
- Format: Structured logs (JSON + human-readable)
- Location: `scan_<target>_<timestamp>/logs/`

---

## Output Structure

```
scan_<target>_<timestamp>/
├── database.db                          # This scan only
├── logs/
│   ├── scan.log                        # Human readable
│   ├── api_calls.jsonl                 # API receipts
│   └── errors.log                      # Error log
├── reports/
│   ├── high_risk_findings.md           # Available/expired domains
│   ├── csp_posture.md                  # Org stats (Top 10 + FULL DATA)
│   ├── csp_posture_FULL.csv            # Complete data export
│   ├── security_architecture.md        # Security guidance
│   └── bugbounty/
│       ├── <affected1>/
│       │   ├── report.md               # Submission ready
│       │   └── proof.md                # Replication commands
│       └── <affected2>/
│           ├── report.md
│           └── proof.md
├── impact/
│   ├── <available_domain1>.md          # Impact analysis
│   └── <available_domain2>.md
└── raw/
    ├── subdomains.txt                  # All discovered
    ├── csp_policies.jsonl              # All CSP headers
    └── external_domains.csv            # All external domains
```

---

## Commands

### Single Scan
```bash
ghosted scan example.com --wordlist 3

# Output: scan_example_com_20251001_120000/
```

### Batch Scan
```bash
ghosted batch targets.txt --wordlist 3

# Output: scan_batch_targets_20251001_120000/
```

### With Danger List
```bash
ghosted scan example.com --danger-list threat_intel.txt
```

---

## Data Completeness Rules

**ABSOLUTE REQUIREMENTS:**

1. **NO TRUNCATION EVER**
   - All external domains listed
   - All trusting domains listed
   - All affected applications listed
   - If 1000 domains, show all 1000

2. **Top N + Complete Data Pattern**
   - Show "Top 10" for highlights
   - Then show "Complete List (ALL N items)"
   - Provide CSV export with EVERYTHING

3. **CSV Exports Must Be Complete**
   - Every row, every column
   - No "... and N more" abbreviations
   - Suitable for Excel/data analysis

---

## Attack Vectors To Document

### 1. XSS / HTML Injection
- script-src allows domain
- Attacker registers domain
- Serves malicious JavaScript
- Full account takeover

### 2. CSRF Resurrection
- CSP allows cross-origin requests
- CSRF tokens can be stolen
- Cross-site request forgery enabled

### 3. Media Replacement
- img-src, media-src, font-src
- Replace logos, images with phishing content
- Serve malicious fonts with tracking pixels

### 4. Customer Tracking
- connect-src allows domain
- Exfiltrate data to attacker-controlled server
- WebSocket C&C channel

### 5. Supply Chain Attack
- Trusted domain in multiple applications
- Single compromise affects entire organization
- Persistent backdoor

---

## Success Criteria

A V8 scan is successful when:

1. All reports generated
2. All data complete (no truncation)
3. Bug bounty reports ready to submit
4. Proof commands work (can replicate findings)
5. CSV exports load in Excel with all data
6. Logs show every API call made
7. Scan folder is self-contained (can archive/share)
8. Danger list matches flagged in reports

---

## What V8 Does NOT Do

- Multiple provider chains (Route53 only)
- WHOIS expiration tracking (removed)
- Shared databases (always isolated)
- PublicWWW integration (not core)
- Security.txt detection (not core)
- Complex verification modes (simple availability check)

---

## API Keys Required

- AWS_ACCESS_KEY_ID - Your AWS access key
- AWS_SECRET_ACCESS_KEY - Your AWS secret key
- AWS_REGION=us-east-1 (Route53 Domains API only available in us-east-1)

Get AWS credentials from AWS IAM Console: https://console.aws.amazon.com/iam/

---

**Version:** 8.0.0
**Codename:** Clean Slate
**Built:** October 1, 2025
