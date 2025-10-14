package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ghosted-v8/storage"
)

// GenerateSecurityArchitectureReport generates security guidance
func GenerateSecurityArchitectureReport(db *storage.Database, scanPath string) error {
	stats, err := db.GetStatistics()
	if err != nil {
		return fmt.Errorf("failed to get statistics: %w", err)
	}

	externalDomains, err := db.GetAllExternalDomains()
	if err != nil {
		return fmt.Errorf("failed to get external domains: %w", err)
	}

	reportsDir := filepath.Join(scanPath, "reports")
	reportPath := filepath.Join(reportsDir, "security_architecture.md")

	f, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}
	defer f.Close()

	// Header
	f.WriteString("# Security Architecture Report: CSP Posture Improvement\n\n")
	f.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format("2006-01-02")))
	f.WriteString("---\n\n")

	// Executive Summary
	f.WriteString("## Executive Summary\n\n")
	f.WriteString(fmt.Sprintf("This report provides security architecture guidance based on analysis of %d subdomains and %d unique external dependencies in Content Security Policies.\n\n", stats.TotalSubdomains, stats.UniqueExternalDomains))

	if stats.AvailableDomains > 0 {
		f.WriteString(fmt.Sprintf("[WARN] **CRITICAL:** %d available/expired domains detected requiring immediate remediation.\n\n", stats.AvailableDomains))
	}

	// Supply Chain Risk Assessment
	f.WriteString("## Supply Chain Risk Assessment\n\n")

	highRisk := 0
	for _, d := range externalDomains {
		if d.ReferenceCount >= 10 {
			highRisk++
		}
	}

	f.WriteString(fmt.Sprintf("**High-Risk Dependencies:** %d domains referenced ≥10 times\n\n", highRisk))
	f.WriteString("**Analysis:** Organizations typically underestimate third-party domain risk. Each external domain represents:\n")
	f.WriteString("- A potential attack vector if compromised\n")
	f.WriteString("- A single point of failure if it becomes unavailable\n")
	f.WriteString("- A privacy/compliance risk if data is shared\n\n")

	// Concentration Risk
	f.WriteString("## Concentration Risk\n\n")
	if len(externalDomains) > 0 {
		top10Count := 0
		if len(externalDomains) >= 10 {
			for i := 0; i < 10; i++ {
				top10Count += externalDomains[i].ReferenceCount
			}
		}

		f.WriteString(fmt.Sprintf("The top 10 most-trusted domains account for %d trust relationships.\n\n", top10Count))
		f.WriteString("**Risk:** Compromise of a single widely-trusted domain creates cascading failures across multiple applications.\n\n")
	}

	// Policy Weaknesses
	f.WriteString("## Common CSP Policy Weaknesses\n\n")
	cspPercentage := float64(stats.SubdomainsWithCSP) / float64(stats.TotalSubdomains) * 100
	f.WriteString(fmt.Sprintf("**CSP Adoption:** %.1f%% (%d of %d subdomains)\n\n", cspPercentage, stats.SubdomainsWithCSP, stats.TotalSubdomains))

	if cspPercentage < 50 {
		f.WriteString("[WARN] **Low CSP adoption.** Many applications lack CSP protection entirely.\n\n")
	}

	f.WriteString("**Common Issues:**\n")
	f.WriteString("1. **Over-permissive policies:** Trusting too many external domains\n")
	f.WriteString("2. **Stale entries:** Domains no longer in use but still trusted\n")
	f.WriteString("3. **No lifecycle management:** Missing tracking of domain expiration dates\n")
	f.WriteString("4. **Wildcard abuse:** Using `*` or overly broad patterns\n")
	f.WriteString("5. **Lack of SRI:** Not using Subresource Integrity for critical scripts\n\n")

	// Recommendations
	f.WriteString("## Recommendations\n\n")

	f.WriteString("### Strategic (Organization-Wide)\n\n")
	f.WriteString("#### 1. CSP Governance Framework\n")
	f.WriteString("- Establish approval process for adding external domains to CSP\n")
	f.WriteString("- Document business justification for each trusted domain\n")
	f.WriteString("- Assign ownership for CSP policy maintenance\n\n")

	f.WriteString("#### 2. Third-Party Domain Lifecycle Management\n")
	f.WriteString("- Track expiration dates of all trusted domains\n")
	f.WriteString("- Set up alerts 90 days before expiration\n")
	f.WriteString("- Establish process for removing unused domains\n\n")

	f.WriteString("#### 3. Supply Chain Security Program\n")
	f.WriteString("- Vendor security assessments for high-risk dependencies\n")
	f.WriteString("- Alternative provider evaluation for critical dependencies\n")
	f.WriteString("- Incident response plan for third-party compromises\n\n")

	f.WriteString("#### 4. Defense in Depth\n")
	f.WriteString("- Don't rely solely on CSP for security\n")
	f.WriteString("- Implement Subresource Integrity (SRI)\n")
	f.WriteString("- Use Content-Security-Policy-Report-Only for testing\n")
	f.WriteString("- Deploy Web Application Firewall (WAF)\n\n")

	f.WriteString("### Tactical (Immediate Fixes)\n\n")

	if stats.AvailableDomains > 0 {
		f.WriteString(fmt.Sprintf("#### 1. Remove %d Available Domains (CRITICAL)\n", stats.AvailableDomains))
		f.WriteString("- Update CSP policies to remove all available/expired domains\n")
		f.WriteString("- Deploy changes to production immediately\n")
		f.WriteString("- Monitor for registration attempts\n\n")
	}

	f.WriteString("#### 2. Policy Tightening\n")
	f.WriteString("- Audit all trusted domains for current usage\n")
	f.WriteString("- Remove domains no longer actively used\n")
	f.WriteString("- Replace wildcards with specific domain names\n\n")

	f.WriteString("#### 3. Subresource Integrity (SRI)\n")
	f.WriteString("- Implement SRI hashes for all external scripts\n")
	f.WriteString("- Automate SRI hash generation in build pipeline\n")
	f.WriteString("- Monitor for SRI failures\n\n")

	f.WriteString("#### 4. CSP Reporting\n")
	f.WriteString("- Enable `report-uri` or `report-to` directives\n")
	f.WriteString("- Set up monitoring for CSP violations\n")
	f.WriteString("- Investigate policy violations for potential attacks\n\n")

	// Monitoring & Detection
	f.WriteString("### Monitoring & Detection\n\n")
	f.WriteString("#### 1. Domain Registration Monitoring\n")
	f.WriteString("- Set up alerts for registration of previously-trusted domains\n")
	f.WriteString("- Monitor WHOIS data for expiration dates\n")
	f.WriteString("- Track DNS changes for trusted domains\n\n")

	f.WriteString("#### 2. CSP Policy Changes\n")
	f.WriteString("- Version control for CSP policies\n")
	f.WriteString("- Code review for CSP modifications\n")
	f.WriteString("- Automated testing of CSP changes\n\n")

	f.WriteString("#### 3. Security Scanning\n")
	f.WriteString("- Run Ghosted V8 quarterly\n")
	f.WriteString("- Integrate into CI/CD pipeline\n")
	f.WriteString("- Alert on new available domains\n\n")

	// Implementation Roadmap
	f.WriteString("## Implementation Roadmap\n\n")

	f.WriteString("### Month 1: Crisis Response\n")
	if stats.AvailableDomains > 0 {
		f.WriteString("- Remove all available domains from CSP\n")
	}
	f.WriteString("- Audit top 10 most-trusted domains\n")
	f.WriteString("- Implement SRI for critical scripts\n\n")

	f.WriteString("### Month 2-3: Foundation\n")
	f.WriteString("- Establish CSP governance framework\n")
	f.WriteString("- Deploy CSP reporting infrastructure\n")
	f.WriteString("- Document all trusted domains with ownership\n\n")

	f.WriteString("### Month 4-6: Maturity\n")
	f.WriteString("- Implement domain lifecycle management\n")
	f.WriteString("- Automate CSP policy testing\n")
	f.WriteString("- Reduce concentration risk (diversify providers)\n\n")

	f.WriteString("### Ongoing: Operations\n")
	f.WriteString("- Quarterly Ghosted V8 scans\n")
	f.WriteString("- Monthly CSP policy reviews\n")
	f.WriteString("- Continuous monitoring of trusted domains\n\n")

	// Success Metrics
	f.WriteString("## Success Metrics\n\n")
	f.WriteString("- **Zero available domains** in CSP policies\n")
	f.WriteString("- **100% SRI coverage** for external scripts\n")
	f.WriteString("- **90-day lead time** on domain expirations\n")
	f.WriteString("- **<5 high-risk dependencies** (referenced ≥10 times)\n")
	f.WriteString("- **Quarterly security audits** completed on schedule\n\n")

	f.WriteString("---\n\n")
	f.WriteString("**Report generated by Ghosted V8** • https://thecontractor.io/ghosted/\n")

	fmt.Printf("[OK] Security architecture report: %s\n", reportPath)
	return nil
}
