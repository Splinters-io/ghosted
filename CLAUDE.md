# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

Ghosted finds domains a website trusts that are available to buy. It reads the same sources as the
Ghosteds webapp (ghosteds.com) without its reporting: CSP headers and meta CSP, HTML, CSS and
JavaScript references, JSON (manifests, import maps), redirects, SPF terms and DMARC report
addresses, and HAR files for anything that only loads in a browser.

## Commands

```bash
go build -o ghosted ./cmd/ghosted
go test ./internal/...

./ghosted scan example.com
./ghosted scan -f targets.txt
./ghosted har capture.har [--target www.example.com]
./ghosted scan --no-aws --dns 1.1.1.1:53 example.com   # no AWS credentials needed
```

## Layout

```
cmd/ghosted/main.go       CLI: scan, har, output
internal/engine/
  extract.go              HTML, CSS, JavaScript, JSON and CSP reference extraction
  mailauth.go             SPF (include/redirect/a/mx/exists/ptr) and DMARC rua/ruf
  scan.go                 fetching a target and its subresources; HAR import
  avail.go                registrable domain, DNS-first availability, AWS Route 53
  aws_tlds.txt            suffixes AWS can register (copied from the webapp)
```

`scanner/`, `checker/`, `reporter/`, `storage/`, `logs/` and `danger/` are the older V8 pipeline
(subdomain enumeration, PublicWWW, reports). The CLI does not use them.

## Rules that matter

- Only a registrar answer of AVAILABLE (or AVAILABLE_RESERVED / AVAILABLE_PREORDER) is reported as
  buyable. Delegated domains are REGISTERED without asking AWS. Suffixes AWS can't sell are
  UNSUPPORTED_TLD for a manual check. Failed or skipped checks make no claim.
- Registrable domains use ICANN suffixes only: `fonts.googleapis.com` is bought as `googleapis.com`.
- AWS calls are serialised, 4 seconds apart, with retries on throttling.
- Extraction rules mirror the webapp's `src/parse.rs` and `src/mailauth.rs`. Change both together.
- `.gitignore` ignores `/ghosted` (the root binary) only. An unanchored `ghosted` once hid
  `cmd/ghosted/` and the CLI was never committed.
