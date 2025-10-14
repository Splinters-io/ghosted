package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"ghosted-v8/storage"
	"golang.org/x/net/publicsuffix"
)

// Parser extracts domains from CSP headers
type Parser struct {
	db              *storage.Database
	validTLDs       map[string]bool
	platformDomains map[string]bool
}

// NewParser creates a new CSP parser
func NewParser(db *storage.Database) *Parser {
	validTLDs := loadRoute53TLDs()
	platformDomains := loadPlatformDomains()
	return &Parser{
		db:              db,
		validTLDs:       validTLDs,
		platformDomains: platformDomains,
	}
}

// loadRoute53TLDs loads valid TLDs from file
func loadRoute53TLDs() map[string]bool {
	tlds := make(map[string]bool)

	f, err := os.Open("tlds/route53_tlds.txt")
	if err != nil {
		fmt.Printf("[WARN]  Could not load Route53 TLDs: %v (will check all domains)\n", err)
		return tlds
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tlds[line] = true
	}

	fmt.Printf("[OK] Loaded %d valid Route53 TLDs\n", len(tlds))
	return tlds
}

// loadPlatformDomains loads platform domains that cannot be registered
func loadPlatformDomains() map[string]bool {
	domains := make(map[string]bool)

	f, err := os.Open("tlds/platform_domains.txt")
	if err != nil {
		fmt.Printf("[WARN]  Could not load platform domains: %v\n", err)
		return domains
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains[line] = true
	}

	fmt.Printf("[OK] Loaded %d platform domains to filter\n", len(domains))
	return domains
}

// CSPDirectives lists ALL CSP directives from MDN spec
var CSPDirectives = []string{
	// Fetch directives
	"child-src",
	"connect-src",
	"default-src",
	"fenced-frame-src",
	"font-src",
	"frame-src",
	"img-src",
	"manifest-src",
	"media-src",
	"object-src",
	"prefetch-src",
	"script-src",
	"script-src-elem",
	"script-src-attr",
	"style-src",
	"style-src-elem",
	"style-src-attr",
	"worker-src",
	// Document directives
	"base-uri",
	"sandbox",
	// Navigation directives
	"form-action",
	"frame-ancestors",
	// Reporting directives
	"report-to",
	// Other directives
	"require-trusted-types-for",
	"trusted-types",
	"upgrade-insecure-requests",
	// Deprecated but still used
	"block-all-mixed-content",
	"report-uri",
	"plugin-types",
}

// ParseAllCSP parses all CSP records and extracts external domains
func (p *Parser) ParseAllCSP() (int, error) {
	// Get all CSP records from database
	rows, err := queryCSPRecords(p.db)
	if err != nil {
		return 0, fmt.Errorf("failed to query CSP records: %w", err)
	}

	fmt.Printf("\n[*] Parsing CSP policies...\n")

	externalDomains := make(map[string]*DomainInfo)
	trustRelationships := make(map[trustKey]string)

	for _, record := range rows {
		domains := p.parseSingle(record.Origin, record.CSPHeader)

		for domain, info := range domains {
			// Track external domain
			if existing, ok := externalDomains[domain]; ok {
				existing.ReferenceCount++
				existing.TrustingDomains = append(existing.TrustingDomains, record.Origin)
			} else {
				externalDomains[domain] = info
			}

			// Track trust relationship
			key := trustKey{origin: record.Origin, external: domain}
			trustRelationships[key] = info.Directive
		}
	}

	// Save to database
	fmt.Printf("[*] Saving %d external domains to database...\n", len(externalDomains))

	for domain, info := range externalDomains {
		if err := p.db.SaveExternalDomain(domain, info.Category, info.IsDangerous); err != nil {
			return 0, fmt.Errorf("failed to save external domain %s: %w", domain, err)
		}
	}

	for key, directive := range trustRelationships {
		if err := p.db.SaveTrustRelationship(key.origin, key.external, directive); err != nil {
			return 0, fmt.Errorf("failed to save trust relationship: %w", err)
		}
	}

	fmt.Printf("[OK] Parsed %d unique external domains from %d CSP policies\n", len(externalDomains), len(rows))
	return len(externalDomains), nil
}

// parseSingle parses a single CSP header
func (p *Parser) parseSingle(origin, cspHeader string) map[string]*DomainInfo {
	domains := make(map[string]*DomainInfo)

	// Split CSP into directives
	directives := strings.Split(cspHeader, ";")

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) < 2 {
			continue
		}

		directiveName := parts[0]
		sources := parts[1:]

		// Only process known directives
		if !isKnownDirective(directiveName) {
			continue
		}

		for _, source := range sources {
			// Skip special keywords
			if strings.HasPrefix(source, "'") {
				continue
			}

			// Skip wildcards
			if source == "*" {
				continue
			}

			// Extract domain from source
			domain := extractDomain(source)
			if domain == "" {
				continue
			}

			// Get root domain
			root, err := getRootDomain(domain)
			if err != nil {
				// Skip domains we can't parse to root level
				continue
			}

			// Skip if same as origin
			if root == origin {
				continue
			}

			// Skip platform/infrastructure domains (AWS, Azure, GCP, CDNs)
			if p.platformDomains[root] {
				continue
			}

			// Check if TLD is valid for Route53 registration
			if len(p.validTLDs) > 0 && !p.isValidRoute53Domain(root) {
				continue
			}

			// Add to results
			if _, exists := domains[root]; !exists {
				domains[root] = &DomainInfo{
					Domain:          root,
					Directive:       directiveName,
					Category:        categorize(root),
					IsDangerous:     false, // Will be set by danger list
					ReferenceCount:  1,
					TrustingDomains: []string{origin},
				}
			}
		}
	}

	return domains
}

// extractDomain extracts domain from CSP source
func extractDomain(source string) string {
	// Remove protocol if present
	source = strings.TrimPrefix(source, "https://")
	source = strings.TrimPrefix(source, "http://")
	source = strings.TrimPrefix(source, "wss://")
	source = strings.TrimPrefix(source, "ws://")

	// Remove path
	if idx := strings.Index(source, "/"); idx != -1 {
		source = source[:idx]
	}

	// Remove port
	if idx := strings.Index(source, ":"); idx != -1 {
		source = source[:idx]
	}

	// Remove wildcard prefix
	source = strings.TrimPrefix(source, "*.")

	// Validate it looks like a domain
	if !strings.Contains(source, ".") {
		return ""
	}

	return source
}

// getRootDomain extracts the root domain using public suffix list
func getRootDomain(domain string) (string, error) {
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", err
	}
	return root, nil
}

// isKnownDirective checks if directive is in our list
func isKnownDirective(directive string) bool {
	for _, known := range CSPDirectives {
		if directive == known {
			return true
		}
	}
	return false
}

// categorize assigns a category to a domain
func categorize(domain string) string {
	domain = strings.ToLower(domain)

	// Analytics
	if strings.Contains(domain, "google-analytics") || strings.Contains(domain, "googletagmanager") ||
		strings.Contains(domain, "analytics") || strings.Contains(domain, "segment") {
		return "Analytics"
	}

	// CDN
	if strings.Contains(domain, "cloudflare") || strings.Contains(domain, "cloudfront") ||
		strings.Contains(domain, "cdn") || strings.Contains(domain, "akamai") {
		return "CDN"
	}

	// Cloud providers
	if strings.Contains(domain, "amazonaws") || strings.Contains(domain, "azure") ||
		strings.Contains(domain, "googleusercontent") || strings.Contains(domain, "s3") {
		return "Cloud Storage"
	}

	// Social media
	if strings.Contains(domain, "facebook") || strings.Contains(domain, "twitter") ||
		strings.Contains(domain, "linkedin") || strings.Contains(domain, "instagram") {
		return "Social Media"
	}

	// Advertising
	if strings.Contains(domain, "doubleclick") || strings.Contains(domain, "ads") ||
		strings.Contains(domain, "adservice") {
		return "Advertising"
	}

	return "Other"
}

// DomainInfo holds information about an external domain
type DomainInfo struct {
	Domain          string
	Directive       string
	Category        string
	IsDangerous     bool
	ReferenceCount  int
	TrustingDomains []string
}

// trustKey uniquely identifies a trust relationship
type trustKey struct {
	origin   string
	external string
}

// CSPRecord represents a CSP record from database
type CSPRecord struct {
	Origin    string
	CSPHeader string
}

// queryCSPRecords queries CSP records from database
// isValidRoute53Domain checks if domain has a valid Route53 TLD
func (p *Parser) isValidRoute53Domain(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	tld := parts[len(parts)-1]
	return p.validTLDs[tld]
}

func queryCSPRecords(db *storage.Database) ([]CSPRecord, error) {
	rows, err := db.Query(`
		SELECT origin_domain, csp_header
		FROM csp_records
		ORDER BY origin_domain
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []CSPRecord
	for rows.Next() {
		var r CSPRecord
		if err := rows.Scan(&r.Origin, &r.CSPHeader); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, rows.Err()
}
