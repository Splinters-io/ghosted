# Ghosted V8 - CSP Trust Erosion Scanner

![Version](https://img.shields.io/badge/version-8.0-blue)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-Security%20Research-green)
![AWS](https://img.shields.io/badge/AWS-Route53-FF9900?logo=amazonaws)

A security tool that identifies potentially vulnerable "ghosted" domains in Content Security Policy (CSP) headers - domains that are trusted by websites but may be available for registration, creating subdomain takeover risks.

**Bonus Discovery:** As a side-effect of DNS enumeration, Ghosted also discovers organic typosquatting domains that resolve but weren't intentionally registered by the target organization. These can reveal phishing infrastructure, trademark violations, or forgotten test domains.

## Real-World Impact

Ghosted has successfully identified CSP trust erosions at 122+ major organizations:

| | | | |
|---|---|---|---|
| aaa.com | abc.es | accenture.com | alamy.com |
| americanexpress.com | amtrak.com | anu.edu.au | arizona.edu |
| asahi.com | astm.org | au.dk | azurewebsites.net |
| bankofamerica.com | bcg.com | bham.ac.uk | bhf.org.uk |
| blackrock.com | bloomberg.com | bmw.com | bmwgroup.com |
| burberry.com | cambridge.org | cancerresearchuk.org | capgemini.com |
| case.edu | census.gov | chase.com | cigna.com |
| cloudfront.net | cloudwaysapps.com | cmegroup.com | coca-cola.com |
| cvs.com | de.com | detik.com | dhl.com |
| donorbox.org | ebay.ca | ebay.com | ebay.com.au |
| ebay.de | equifax.com | experian.com | ey.com |
| fao.org | fashionnetwork.com | fifa.com | fujitsu.com |
| gencat.cat | govt.nz | grubhub.com | gulfnews.com |
| heart.org | hermes.com | hollywoodreporter.com | hpe.com |
| huawei.com | icrc.org | impress.co.jp | intel.com |
| ipsos.com | iqiyi.com | jnj.com | jst.go.jp |
| leagueoflegends.com | lexisnexis.com | libero.it | linktr.ee |
| lse.ac.uk | mass.gov | mercedes-benz.com | michelin.com |
| mitre.org | mynavi.jp | nationaltrust.org.uk | netlify.app |
| note.com | ntu.edu.sg | okta.com | on24.com |
| panasonic.com | peatix.com | porsche.com | premierleague.com |
| pwc.com | qatarairways.com | rakuten.com | rmit.edu.au |
| siemens.com | simon.com | sky.it | squareup.com |
| teamviewer.com | thomsonreuters.com | toyota.com | transunion.com |
| uab.edu | uber.com | ucl.ac.uk | uga.edu |
| ui.ac.id | un.org | unicef.org | unity.com |
| universiteitleiden.nl | univision.com | upm.es | usbank.com |
| usc.edu | uu.nl | uva.nl | uw.edu |
| verizon.com | webex.com | wellsfargo.com | wildapricot.org |
| wolterskluwer.com | wur.nl | yamaha.com | york.ac.uk |
| zomato.com | zoom.us | | |

## Features

### Core Capabilities
- **CSP Header Analysis**: Scans websites for Content Security Policy headers
- **Domain Extraction**: Identifies all external domains trusted by CSP policies
- **Availability Checking**: Uses AWS Route53 to check if trusted domains are available for registration
- **PublicWWW Research**: Discovers how available domains are used across the web (optional)
- **Bug Bounty Reports**: Auto-generates professional security reports
- **High-Performance Scanning**: Beast mode with 1000 DNS concurrency
- **Resume Capability**: Continue interrupted scans with wordlist tracking
- **Automatic Organization**: Scan results organized into hot/archive folders

### Bonus Intelligence
- **Typosquatting Discovery**: DNS enumeration naturally uncovers typosquatted domains that resolve but weren't registered by the target
  - Identifies potential phishing domains
  - Reveals trademark infringement
  - Discovers forgotten test/staging domains
  - Exposes defensive registrations that need monitoring

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
