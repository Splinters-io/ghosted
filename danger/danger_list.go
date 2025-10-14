package danger

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"ghosted-v8/storage"
)

// DangerList manages threat intelligence domain list
type DangerList struct {
	domains map[string]bool
	path    string
}

// LoadDangerList loads danger list from file
func LoadDangerList(path string) (*DangerList, error) {
	dl := &DangerList{
		domains: make(map[string]bool),
		path:    path,
	}

	// File is optional
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("ℹ️  No danger list found at %s (optional)\n", path)
		return dl, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open danger list: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		dl.domains[strings.ToLower(line)] = true
		count++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read danger list: %w", err)
	}

	fmt.Printf("[OK] Loaded %d domains from danger list\n", count)
	return dl, nil
}

// IsDangerous checks if a domain is in the danger list
func (dl *DangerList) IsDangerous(domain string) bool {
	return dl.domains[strings.ToLower(domain)]
}

// FlagDangerousInDatabase marks dangerous domains in database
func (dl *DangerList) FlagDangerousInDatabase(db *storage.Database) error {
	if len(dl.domains) == 0 {
		return nil
	}

	externalDomains, err := db.GetAllExternalDomains()
	if err != nil {
		return fmt.Errorf("failed to get external domains: %w", err)
	}

	flagged := 0
	for _, ed := range externalDomains {
		if dl.IsDangerous(ed.Domain) {
			if err := db.FlagDangerous(ed.Domain); err != nil {
				return fmt.Errorf("failed to flag dangerous domain %s: %w", ed.Domain, err)
			}
			flagged++
			fmt.Printf("[CRITICAL] DANGEROUS: %s (matched danger list)\n", ed.Domain)
		}
	}

	if flagged > 0 {
		fmt.Printf("[OK] Flagged %d dangerous domains\n", flagged)
	}

	return nil
}

// CreateExampleDangerList creates an example danger_list.txt file
func CreateExampleDangerList(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create danger list: %w", err)
	}
	defer f.Close()

	f.WriteString("# Ghosted V8 - Danger List\n")
	f.WriteString("# One domain per line, comments start with #\n")
	f.WriteString("#\n")
	f.WriteString("# Categories:\n")
	f.WriteString("# - Known malicious infrastructure\n")
	f.WriteString("# - Expired high-value domains\n")
	f.WriteString("# - Compromised CDNs\n")
	f.WriteString("# - Threat actor controlled domains\n")
	f.WriteString("#\n")
	f.WriteString("# Example entries:\n")
	f.WriteString("# malicious-cdn.com\n")
	f.WriteString("# compromised-analytics.net\n")
	f.WriteString("# expired-high-value.org\n")

	fmt.Printf("[OK] Created example danger list: %s\n", path)
	return nil
}
