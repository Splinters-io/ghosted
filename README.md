# Ghosted - Trust Erosion Scanner

![Version](https://img.shields.io/badge/version-8.0-blue)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-Security%20Research-green)
![AWS](https://img.shields.io/badge/AWS-Route53-FF9900?logo=amazonaws)

A security tool that finds "ghosted" domains: domains a website trusts, in its CSP, its pages, its scripts and its SPF and DMARC records, that are available for sale, creating [mal-inheritance](https://thecontractor.io/malinheritance/) risks.

**Bonus Discovery:** As a side-effect of DNS enumeration, Ghosted also discovers organic typosquatting domains that resolve but weren't intentionally registered by the target organization. These trusts can be abused in a few different ways, context always applies.

## Real-World Impact / Attention grabbing application *polite chuckle*

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

## Getting started

**1. Download** the binary for your machine from the [latest release](https://github.com/Splinters-io/ghosted/releases/latest):

| System | File |
|---|---|
| macOS, Apple silicon | `ghosted-darwin-arm64` |
| macOS, Intel | `ghosted-darwin-amd64` |
| Linux, x86-64 | `ghosted-linux-amd64` |
| Linux, ARM64 | `ghosted-linux-arm64` |
| Windows | `ghosted-windows-amd64.exe` |

```bash
# macOS / Linux
mv ghosted-darwin-arm64 ghosted
chmod +x ghosted
xattr -d com.apple.quarantine ghosted   # macOS only: the binary isn't notarised
shasum -a 256 -c SHA256SUMS --ignore-missing   # optional: check the download
```

Or build it yourself with Go 1.26 or later: `go build -o ghosted ./cmd/ghosted`

**2. Try it without AWS.** Domains that have nameservers are settled from DNS, and the rest are listed as undecided:

```bash
./ghosted scan --no-aws --dns 1.1.1.1:53 example.com
```

**3. Add AWS** to get a registrar answer for the undecided ones. Any normal AWS credentials work (environment variables, `~/.aws/credentials` or `AWS_PROFILE`), as long as they allow `route53domains:CheckDomainAvailability`. AWS lists no charge for availability checks; Route 53 charges when you register a domain.

```bash
export AWS_PROFILE=ghosted
./ghosted scan example.com
```

**4. Scan more.** Give it a list, or a browser capture for pages that load things lazily or behind a sign-in:

```bash
./ghosted scan -f targets.txt
./ghosted har capture.har
```

Anything listed under "can be bought" is a domain your site trusts that someone else could register today.

## What it reads

Ghosted looks in the same places as the [Ghosteds](https://ghosteds.com) webapp, without the reporting:

| Source | What becomes a domain |
|---|---|
| CSP headers | `Content-Security-Policy` and `Content-Security-Policy-Report-Only`, every host source in every directive |
| HTML | `<meta>` CSP, `script`, `link` (stylesheet, preload, modulepreload, prefetch, preconnect, dns-prefetch, manifest), `img`, `srcset`, `iframe`, `form`/`formaction`, `a`/`area`, `audio`/`video`/`source`/`track`, `object`/`embed`, `use`/`image`, `<base>`, URL-valued `data-*` attributes and `style` attributes |
| Inline blocks | `<style>`, JavaScript `<script>`, import maps, speculation rules and JSON / JSON-LD blocks |
| CSS | `url()`, `@import` and `image-set()` in every stylesheet the page loads |
| JavaScript | `import`/`export from`, dynamic `import()`, and URL-like string and template literals in every script the page loads (comments are ignored) |
| JSON | manifests and import maps: URL values and URL-named keys (`src`, `url`, `href`, `start_url`, `scope`, `action`, `endpoint`) |
| Redirects | every `Location` the landing page and its subresources redirect through |
| SPF | `include`, `redirect`, `a`, `mx`, `exists` and `ptr` terms for the host and its registrable domain, following includes within SPF's ten-lookup limit |
| DMARC | `rua` and `ruf` report addresses for the host and its registrable domain |
| HAR files | every request the browser made, plus the headers and bodies the export carries |

Pages are not rendered. Anything that only loads after scrolling, clicking or signing in comes in through a HAR file (see below).

## How availability is decided

1. Each reference is reduced to the domain you would actually buy (`mail.tripwire-dhs.us` → `tripwire-dhs.us`). Private suffixes such as `googleapis.com` and `github.io` count as registered domains, not suffixes. The target's own domain is left out.
2. **DNS first.** A domain with nameservers of its own is registered, so the registrar is not asked. A random name is probed under each suffix first, so a suffix that answers everything can't make an unregistered domain look delegated.
3. **AWS Route 53** `CheckDomainAvailability` decides everything else, one call every 4 seconds (Route 53 Domains throttles harder than that), retrying throttled calls.
4. Suffixes AWS can't register are listed as `UNSUPPORTED_TLD` for you to check with a registrar for that suffix. Nothing is claimed about them.

Only a registrar answer of `AVAILABLE` (or `AVAILABLE_RESERVED` / `AVAILABLE_PREORDER`) is reported as buyable.

## Installation

Go 1.26 or later.

```bash
go build -o ghosted ./cmd/ghosted
```

AWS credentials come from the usual places (environment, `~/.aws/credentials`, a profile). The account needs `route53domains:CheckDomainAvailability`; the Route 53 Domains API lives in `us-east-1`. Without credentials, use `--no-aws`: domains with nameservers are still settled from DNS and the rest are listed as undecided.

## Usage

```bash
# One or more sites
./ghosted scan example.com www.example.org

# A list, one host per line (# comments allowed)
./ghosted scan -f targets.txt

# Subdomains first, then scan them all
subfinder -d example.com -silent > hosts.txt
./ghosted scan -f hosts.txt

# A browser capture: DevTools > Network > right-click > "Save all as HAR with content"
./ghosted har capture.har
./ghosted har capture.har --target www.example.com
```

| Flag | |
|---|---|
| `-f file` | read targets from a file |
| `--target host` | the site a HAR belongs to (default: host of its first entry) |
| `--no-aws` | DNS checks only, never call AWS |
| `--no-mail` | skip SPF and DMARC |
| `--json` | one JSON object per domain on stdout: status, provider and every reference |
| `-v` | also list registered domains and where each was referenced |
| `--concurrency n` | targets scanned at once (default 4) |
| `--resources n` | scripts, stylesheets and manifests fetched per target (default 60) |
| `--dns host:port` | DNS server for the nameserver checks (default: `/etc/resolv.conf`) |

If your resolver blocks ad and tracking domains, their nameserver checks fail and they fall through to AWS. Point `--dns` at a public resolver to settle them from DNS instead.

### Output

```
AVAILABLE  forgotten-vendor.com  (aws-route53)
    www.example.com  script  <script> src  in https://www.example.com/
      https://cdn.forgotten-vendor.com/widget.js

1 can be bought:
  forgotten-vendor.com  AVAILABLE

2 under suffixes AWS cannot register; check these with a registrar:
  vendor.com.br
  reports.example.ru

Totals:  AVAILABLE 1  REGISTERED 41  UNSUPPORTED_TLD 2
```

Progress and warnings (pages that didn't load, scripts that didn't parse, limits reached) go to stderr.

The older subdomain-enumeration, PublicWWW and reporting packages (`scanner/`, `checker/`, `reporter/`, `storage/`) are still in the repository but are not used by this command.

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

For issues and questions, please open an issue on GitHub, but for those who know me, this is a JC / Claude Code Special, I've spent enough time complaining I can't code to have learned every single syscall from scratch, so ... chat amongst yourselves ? <3 
