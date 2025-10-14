# Ghosted V8 - CSP Trust Erosion Scanner

A security tool that identifies potentially vulnerable "ghosted" domains in Content Security Policy (CSP) headers - domains that are trusted by websites but may be available for registration, creating subdomain takeover risks.

## Features

- **CSP Header Analysis**: Scans websites for Content Security Policy headers
- **Domain Extraction**: Identifies all external domains trusted by CSP policies
- **Availability Checking**: Uses AWS Route53 to check if trusted domains are available for registration
- **PublicWWW Research**: Discovers how available domains are used across the web (optional)
- **Bug Bounty Reports**: Auto-generates professional security reports
- **High-Performance Scanning**: Beast mode with 1000 DNS concurrency
- **Resume Capability**: Continue interrupted scans with wordlist tracking
- **Automatic Organization**: Scan results organized into hot/archive folders

## Installation

### Prerequisites

- Go 1.21 or higher
- AWS Account (for Route53 domain checking)
- Optional: PublicWWW API key (for enhanced research)

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod download
   ```

3. Download wordlists (optional, for active enumeration):
   ```bash
   # Clone SecLists
   git clone https://github.com/danielmiessler/SecLists.git

   # Copy wordlists
   cp SecLists/Discovery/DNS/dns-Jhaddix.txt wordlists/FUZZSUBS_CYFARE_1.txt
   cp SecLists/Discovery/DNS/subdomains-top1million-110000.txt wordlists/FUZZSUBS_CYFARE_2.txt
   ```
   Note: Wordlists are only needed for `--wordlists 1` mode. Passive mode (`--wordlists 0`) works without them.

4. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

5. Build:
   ```bash
   go build -o ghosted cmd/ghosted/main.go
   ```

## Usage

### Basic Scanning

```bash
# Scan a single domain
./ghosted scan example.com --wordlists 1

# Beast mode (high concurrency - 1000 DNS/sec)
./ghosted beast hosts.txt --wordlists 0  # Passive only
./ghosted beast hosts.txt --wordlists 1  # Full enumeration
```

### Research & Reporting

```bash
# Research available domains via PublicWWW
./ghosted research output/beast_example.com_20251003_120000

# Generate send it report
./ghosted sendit output/beast_example.com_20251003_120000
```

### Configuration

**Environment Variables** (`.env`):
- `AWS_ACCESS_KEY_ID` - AWS access key (required for Route53)
- `AWS_SECRET_ACCESS_KEY` - AWS secret key (required for Route53)
- `AWS_REGION` - AWS region (must be us-east-1 for Route53 Domains API)
- `PUBLICWWW_KEY` - PublicWWW API key (optional for domain research)

## Output Structure

```
output/
├── beast_example.com_20251003_120000/
│   ├── database.db              # SQLite database
│   ├── SENDIT_REPORT.md         # Comprehensive findings
│   ├── reports/
│   │   ├── high_risk_findings.md
│   │   ├── csp_posture.md
│   │   └── bugbounty/           # Per-domain reports
│   └── logs/                    # Execution logs
```

## Security Notice

This tool is designed for:
- Security research
- Bug bounty hunting
- Defensive security assessment
- Vulnerability discovery

Always obtain proper authorization before scanning domains you don't own.

## License

This project is provided as-is for security research purposes.

## Credits & Attribution

This tool builds upon excellent open-source projects:

- **[ProjectDiscovery](https://github.com/projectdiscovery)** - Subfinder and dnsx tools for subdomain enumeration
  - [subfinder](https://github.com/projectdiscovery/subfinder) - Fast passive subdomain enumeration
  - [dnsx](https://github.com/projectdiscovery/dnsx) - Fast and multi-purpose DNS toolkit
- **[SecLists](https://github.com/danielmiessler/SecLists)** - Security testing wordlists (FUZZSUBS_CYFARE)
- **AWS Route53** - Domain availability checking API
- **[PublicWWW](https://publicwww.com/)** - Source code search engine for domain usage research

Reports include attribution to https://thecontractor.io/ghosted/

## Support

For issues and questions, please open an issue on GitHub.
