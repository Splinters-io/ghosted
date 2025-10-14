package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghosted-v8/storage"
)

// GenerateCSPPostureReport generates organizational CSP statistics
func GenerateCSPPostureReport(db *storage.Database, scanPath string) error {
	stats, err := db.GetStatistics()
	if err != nil {
		return fmt.Errorf("failed to get statistics: %w", err)
	}

	externalDomains, err := db.GetAllExternalDomains()
	if err != nil {
		return fmt.Errorf("failed to get external domains: %w", err)
	}

	reportsDir := filepath.Join(scanPath, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Markdown report
	reportPath := filepath.Join(reportsDir, "csp_posture.md")
	if err := generateCSPMarkdown(reportPath, stats, externalDomains); err != nil {
		return err
	}

	// CSV export - COMPLETE DATA
	csvPath := filepath.Join(reportsDir, "csp_posture_FULL.csv")
	if err := generateCSPCSV(csvPath, externalDomains); err != nil {
		return err
	}

	fmt.Printf("[OK] CSP posture report: %s\n", reportPath)
	fmt.Printf("[OK] CSV export (FULL DATA): %s\n", csvPath)
	return nil
}

func generateCSPMarkdown(path string, stats storage.ScanStats, domains []storage.ExternalDomain) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}
	defer f.Close()

	// Header
	f.WriteString("# Organizational CSP Security Posture\n\n")
	f.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	f.WriteString("---\n\n")

	// Executive Summary
	f.WriteString("## Executive Summary\n\n")
	f.WriteString(fmt.Sprintf("- **Total Subdomains Scanned:** %d\n", stats.TotalSubdomains))
	f.WriteString(fmt.Sprintf("- **Subdomains with CSP:** %d (%.1f%%)\n", stats.SubdomainsWithCSP, float64(stats.SubdomainsWithCSP)/float64(stats.TotalSubdomains)*100))
	f.WriteString(fmt.Sprintf("- **Unique External Domains Trusted:** %d\n", stats.UniqueExternalDomains))
	f.WriteString(fmt.Sprintf("- **Availability Checks Performed:** %d\n", stats.DomainsChecked))
	f.WriteString(fmt.Sprintf("- **Available/Expired Domains Found:** %d\n\n", stats.AvailableDomains))

	if stats.AvailableDomains > 0 {
		f.WriteString("[WARN] **CRITICAL:** Available domains detected. See high_risk_findings.md\n\n")
	}

	f.WriteString("---\n\n")

	// Top 10 Most Referenced (Executive Focus)
	f.WriteString("## Top 10 Most Referenced External Domains\n\n")
	f.WriteString("These domains are trusted by the most applications and represent concentration risk:\n\n")

	top10 := domains
	if len(top10) > 10 {
		top10 = domains[:10]
	}

	f.WriteString("| Rank | Domain | Times Referenced | Category |\n")
	f.WriteString("|------|--------|------------------|----------|\n")
	for i, d := range top10 {
		f.WriteString(fmt.Sprintf("| %d | %s | %d | %s |\n", i+1, d.Domain, d.ReferenceCount, d.Category))
	}
	f.WriteString("\n")

	f.WriteString("---\n\n")

	// COMPLETE LIST - NO TRUNCATION
	f.WriteString(fmt.Sprintf("## Complete List of ALL External Domains (%d total)\n\n", len(domains)))
	f.WriteString("**NO DATA TRUNCATION** - All domains listed below.\n\n")

	// Group by category
	byCategory := make(map[string][]storage.ExternalDomain)
	for _, d := range domains {
		byCategory[d.Category] = append(byCategory[d.Category], d)
	}

	categories := []string{"Analytics", "CDN", "Cloud Storage", "Social Media", "Advertising", "Other"}
	for _, category := range categories {
		categoryDomains := byCategory[category]
		if len(categoryDomains) == 0 {
			continue
		}

		f.WriteString(fmt.Sprintf("### %s (%d domains)\n\n", category, len(categoryDomains)))

		for _, d := range categoryDomains {
			f.WriteString(fmt.Sprintf("**%s** (referenced %d times)\n\n", d.Domain, d.ReferenceCount))
			f.WriteString(fmt.Sprintf("Trusted by %d applications:\n\n", len(d.TrustingDomains)))

			// COMPLETE list of trusting domains - NO TRUNCATION
			for _, origin := range d.TrustingDomains {
				f.WriteString(fmt.Sprintf("- %s\n", origin))
			}
			f.WriteString("\n")
		}
	}

	f.WriteString("---\n\n")

	// Supply Chain Risk Analysis
	f.WriteString("## Supply Chain Risk Analysis\n\n")

	highRisk := 0
	for _, d := range domains {
		if d.ReferenceCount >= 10 {
			highRisk++
		}
	}

	f.WriteString(fmt.Sprintf("**High-Risk Dependencies:** %d domains referenced ≥10 times\n\n", highRisk))
	f.WriteString("**Risk:** Compromise of a widely-trusted domain affects multiple applications simultaneously.\n\n")

	f.WriteString("### Concentration Risk\n\n")
	if len(top10) > 0 {
		topRefs := 0
		for _, d := range top10 {
			topRefs += d.ReferenceCount
		}
		f.WriteString(fmt.Sprintf("The top 10 domains account for %d trust relationships.\n\n", topRefs))
	}

	f.WriteString("---\n\n")

	// Recommendations
	f.WriteString("## Recommendations\n\n")
	f.WriteString("### Strategic (Organization-Wide)\n\n")
	f.WriteString("1. **CSP Governance:** Establish approval process for adding external domains\n")
	f.WriteString("2. **Dependency Tracking:** Monitor lifecycle of all trusted third-party domains\n")
	f.WriteString("3. **Concentration Risk:** Reduce reliance on single highly-referenced domains\n")
	f.WriteString("4. **Security Audits:** Quarterly CSP policy reviews\n\n")

	f.WriteString("### Tactical (Immediate)\n\n")
	f.WriteString("1. **Remove Available Domains:** Update CSP policies immediately\n")
	f.WriteString("2. **Subresource Integrity:** Implement SRI for critical external scripts\n")
	f.WriteString("3. **Policy Tightening:** Remove unused trusted domains\n")
	f.WriteString("4. **Monitoring:** Set up alerts for domain registration attempts\n\n")

	f.WriteString("---\n\n")
	f.WriteString("**Report generated by Ghosted V8** • https://thecontractor.io/ghosted/\n")
	f.WriteString("\n**Full dataset available in:** `csp_posture_FULL.csv`\n")

	return nil
}

func generateCSPCSV(path string, domains []storage.ExternalDomain) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create CSV: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"External Domain", "Reference Count", "Category", "Complete List of Trusting Domains"})

	// ALL domains - NO TRUNCATION
	for _, d := range domains {
		trustingList := strings.Join(d.TrustingDomains, "; ")
		w.Write([]string{
			d.Domain,
			fmt.Sprintf("%d", d.ReferenceCount),
			d.Category,
			trustingList, // COMPLETE list, comma-separated
		})
	}

	return nil
}
