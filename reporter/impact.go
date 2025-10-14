package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ghosted-v8/storage"
)

// GenerateImpactReports generates impact analysis per available domain
func GenerateImpactReports(db *storage.Database, scanPath string) error {
	available, err := db.GetAvailableDomains()
	if err != nil {
		return fmt.Errorf("failed to get available domains: %w", err)
	}

	if len(available) == 0 {
		fmt.Println("[OK] No impact reports needed (no available domains)")
		return nil
	}

	impactDir := filepath.Join(scanPath, "impact")
	if err := os.MkdirAll(impactDir, 0755); err != nil {
		return fmt.Errorf("failed to create impact directory: %w", err)
	}

	for _, result := range available {
		reportPath := filepath.Join(impactDir, sanitizeDomainName(result.Domain)+".md")
		if err := generateSingleImpact(reportPath, result); err != nil {
			return err
		}
	}

	fmt.Printf("[OK] Generated %d impact reports\n", len(available))
	return nil
}

func generateSingleImpact(path string, result storage.AvailabilityResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create impact report: %w", err)
	}
	defer f.Close()

	// Header
	f.WriteString(fmt.Sprintf("# Impact Analysis: %s\n\n", result.Domain))
	f.WriteString(fmt.Sprintf("**Status:** %s\n", result.Status))
	f.WriteString(fmt.Sprintf("**Verified:** %s\n\n", result.CheckedAt.Format("2006-01-02 15:04:05")))
	f.WriteString("---\n\n")

	// Domain Status History
	f.WriteString("## Domain Status\n\n")
	f.WriteString(fmt.Sprintf("**Current Status:** %s\n", result.Status))
	f.WriteString(fmt.Sprintf("**Availability:** %v\n", result.Available))
	f.WriteString(fmt.Sprintf("**Check Date:** %s\n\n", result.CheckedAt.Format("2006-01-02")))

	// Affected Applications - COMPLETE LIST
	f.WriteString(fmt.Sprintf("## Affected Applications (%d total)\n\n", len(result.AffectedOrigins)))
	f.WriteString("**NO TRUNCATION** - Complete list below:\n\n")

	for i, origin := range result.AffectedOrigins {
		f.WriteString(fmt.Sprintf("%d. %s\n", i+1, origin))
	}
	f.WriteString("\n")

	// Attack Surface Analysis
	f.WriteString("## Attack Surface Analysis\n\n")

	f.WriteString("### 1. XSS via script-src\n")
	f.WriteString(fmt.Sprintf("If `%s` is trusted in `script-src` directive:\n", result.Domain))
	f.WriteString("- **Attack:** Attacker registers domain and serves malicious JavaScript\n")
	f.WriteString("- **Impact:** Full account takeover, credential theft, session hijacking\n")
	f.WriteString("- **Persistence:** Malicious script runs on every page load\n\n")

	f.WriteString("### 2. HTML Injection via frame-src/style-src\n")
	f.WriteString(fmt.Sprintf("If `%s` is trusted in `frame-src` or `style-src`:\n", result.Domain))
	f.WriteString("- **Attack:** Inject phishing iframes or malicious CSS\n")
	f.WriteString("- **Impact:** Phishing attacks, UI redressing, keylogging via CSS\n")
	f.WriteString("- **Example:** Replace login form with attacker-controlled iframe\n\n")

	f.WriteString("### 3. CSRF Resurrection\n")
	f.WriteString("Content Security Policy allows cross-origin requests:\n")
	f.WriteString("- **Attack:** CSRF protections become ineffective\n")
	f.WriteString("- **Impact:** Unauthorized actions on behalf of users\n")
	f.WriteString("- **Severity:** Depends on application functionality (payments, settings changes, etc.)\n\n")

	f.WriteString("### 4. Media Replacement\n")
	f.WriteString(fmt.Sprintf("If `%s` is trusted in `img-src`, `media-src`, or `font-src`:\n", result.Domain))
	f.WriteString("- **Attack:** Replace logos, images, fonts with malicious content\n")
	f.WriteString("- **Impact:** Brand impersonation, phishing, tracking pixels\n")
	f.WriteString("- **Example:** Replace company logo with phishing message\n\n")

	f.WriteString("### 5. Customer Tracking / Data Exfiltration\n")
	f.WriteString(fmt.Sprintf("If `%s` is trusted in `connect-src`:\n", result.Domain))
	f.WriteString("- **Attack:** Exfiltrate data via fetch/XMLHttpRequest\n")
	f.WriteString("- **Impact:** PII theft, session token theft, activity monitoring\n")
	f.WriteString("- **Method:** WebSocket C&C channel, long-polling for persistence\n\n")

	// Business Impact Severity
	f.WriteString("## Business Impact Severity\n\n")

	severity := "CRITICAL"
	if len(result.AffectedOrigins) > 10 {
		severity = "CRITICAL (WIDESPREAD)"
	}

	f.WriteString(fmt.Sprintf("**Overall Severity:** %s\n\n", severity))

	f.WriteString("**Potential Consequences:**\n")
	f.WriteString(fmt.Sprintf("- **User Impact:** All users of %d affected applications\n", len(result.AffectedOrigins)))
	f.WriteString("- **Data Breach:** Credentials, session tokens, PII, payment data\n")
	f.WriteString("- **Compliance:** GDPR violations, PCI-DSS non-compliance\n")
	f.WriteString("- **Reputation:** Brand damage, customer trust erosion\n")
	f.WriteString("- **Financial:** Incident response costs, regulatory fines, lawsuits\n\n")

	// Exploitation Proof Receipts
	f.WriteString("## Proof Receipts\n\n")

	f.WriteString("### Domain Availability Check\n")
	f.WriteString("```bash\n")
	f.WriteString(fmt.Sprintf("aws route53domains check-domain-availability \\\n  --domain-name %s \\\n  --region us-east-1\n", result.Domain))
	f.WriteString("```\n\n")
	f.WriteString(fmt.Sprintf("**Result:** %s\n\n", result.Status))

	f.WriteString("### CSP Verification\n")
	f.WriteString("```bash\n")
	for _, origin := range result.AffectedOrigins {
		f.WriteString(fmt.Sprintf("curl -I https://%s | grep -i content-security-policy\n", origin))
	}
	f.WriteString("```\n\n")

	f.WriteString("### DNS Query\n")
	f.WriteString("```bash\n")
	f.WriteString(fmt.Sprintf("dig %s\n", result.Domain))
	f.WriteString("nslookup "+result.Domain+"\n")
	f.WriteString("```\n\n")

	// Remediation Steps
	f.WriteString("## Remediation Steps\n\n")

	f.WriteString("### Immediate (Within 24 hours)\n")
	f.WriteString(fmt.Sprintf("1. Remove `%s` from CSP policies on all %d affected domains\n", result.Domain, len(result.AffectedOrigins)))
	f.WriteString("2. Deploy updated CSP headers to production\n")
	f.WriteString("3. Monitor for any registration attempts\n\n")

	f.WriteString("### Short-term (Within 1 week)\n")
	f.WriteString("1. Audit CSP policies for other stale/expired domains\n")
	f.WriteString("2. Implement CSP policy review process\n")
	f.WriteString("3. Document business justification for all trusted domains\n\n")

	f.WriteString("### Long-term (Within 1 month)\n")
	f.WriteString("1. Implement domain lifecycle management system\n")
	f.WriteString("2. Set up automated monitoring for domain expirations\n")
	f.WriteString("3. Use Subresource Integrity (SRI) for critical external scripts\n")
	f.WriteString("4. Establish security review process for CSP changes\n\n")

	// Threat Actor Awareness
	f.WriteString("## Threat Actor Awareness\n\n")
	f.WriteString("**Who might exploit this:**\n")
	f.WriteString("- **Opportunistic attackers:** Monitor for expired domains in CSP policies\n")
	f.WriteString("- **APT groups:** Target high-value organizations via supply chain\n")
	f.WriteString("- **Ransomware gangs:** Initial access for ransomware deployment\n")
	f.WriteString("- **Cybercriminals:** Credential theft, financial fraud\n\n")

	f.WriteString("**Detection difficulty:** LOW (domain registration is public, exploitation is stealthy)\n\n")

	f.WriteString("---\n\n")
	f.WriteString("**Report generated by Ghosted V8** • https://thecontractor.io/ghosted/\n")
	f.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().Format("2006-01-02 15:04:05")))

	return nil
}
