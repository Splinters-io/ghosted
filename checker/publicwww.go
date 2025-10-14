package checker

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// PublicWWWChecker performs domain research via PublicWWW API
type PublicWWWChecker struct {
	apiKey     string
	httpClient *http.Client
	db         interface {
		Exec(string, ...interface{}) (sql.Result, error)
	}
	requestCount int
	rateLimit    time.Duration
}

// PublicWWWResult represents a search result
type PublicWWWResult struct {
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
	Title   string `json:"title"`
}

// PublicWWWResponse from API
type PublicWWWResponse struct {
	Results []PublicWWWResult `json:"results"`
	Total   int               `json:"total"`
}

// NewPublicWWWChecker creates a new PublicWWW checker
func NewPublicWWWChecker(db interface{ Exec(string, ...interface{}) (sql.Result, error) }) (*PublicWWWChecker, error) {
	apiKey := os.Getenv("PUBLICWWW_KEY")
	if apiKey == "" {
		// Try reading from file
		data, err := os.ReadFile("publicwww.key")
		if err == nil {
			apiKey = strings.TrimSpace(string(data))
		}
	}

	if apiKey == "" {
		return nil, fmt.Errorf("PUBLICWWW_KEY not set (export PUBLICWWW_KEY=your_key or create publicwww.key file)")
	}

	return &PublicWWWChecker{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		db:           db,
		requestCount: 0,
		rateLimit:    60 * time.Second, // PublicWWW recommends 60s between requests
	}, nil
}

// ResearchDomain searches PublicWWW for domain usage
func (p *PublicWWWChecker) ResearchDomain(domain string) (int, error) {
	// Rate limiting
	if p.requestCount > 0 {
		fmt.Printf("   [*] Rate limiting (waiting %s)...\n", p.rateLimit)
		time.Sleep(p.rateLimit)
	}

	// Try CSV export first (works with free tier)
	csvURL := fmt.Sprintf("https://publicwww.com/websites/%%22%s%%22/?export=csv&key=%s",
		url.QueryEscape(domain),
		p.apiKey,
	)

	fmt.Printf("   [*] Searching PublicWWW for: %s\n", domain)
	fmt.Printf("   [*] Downloading CSV export...\n")

	// Make CSV request
	resp, err := p.httpClient.Get(csvURL)
	if err != nil {
		return 0, fmt.Errorf("publicwww request failed: %w", err)
	}
	defer resp.Body.Close()

	p.requestCount++

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("publicwww returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	bodyStr := string(body)

	// Check for empty response
	if len(bodyStr) == 0 || strings.TrimSpace(bodyStr) == "" {
		fmt.Printf("   [INFO] No results found (empty response from PublicWWW)\n")
		return 0, nil
	}

	// Check if it's CSV (semicolon-separated: domain;traffic_rank)
	if !strings.HasPrefix(bodyStr, "<!DOCTYPE") && !strings.HasPrefix(bodyStr, "<html") && !strings.HasPrefix(bodyStr, "{") {
		// Parse semicolon-separated CSV
		lines := strings.Split(bodyStr, "\n")
		count := 0

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Split by semicolon: domain;traffic_rank
			parts := strings.Split(line, ";")
			if len(parts) < 1 {
				continue
			}

			siteURL := strings.TrimSpace(parts[0])
			traffic := ""
			if len(parts) >= 2 {
				traffic = strings.TrimSpace(parts[1])
			}

			if siteURL == "" {
				continue
			}

			// Build snippet with traffic info
			snippet := fmt.Sprintf("Traffic rank: %s", traffic)
			if traffic == "" {
				snippet = "Website uses this domain (no traffic data)"
			}

			// Store in database
			_, err := p.db.Exec(`
				INSERT OR REPLACE INTO publicwww_results (domain, site_url, snippet)
				VALUES (?, ?, ?)
			`, domain, siteURL, snippet)
			if err != nil {
				fmt.Printf("   [WARN] Failed to save result: %v\n", err)
				continue
			}
			count++
		}

		if count > 0 {
			fmt.Printf("   [OK] Found %d sites using %s (CSV export)\n", count, domain)
			return count, nil
		}
	}

	// Check if response is HTML (fallback)
	if strings.HasPrefix(bodyStr, "<!DOCTYPE") || strings.HasPrefix(bodyStr, "<html") {
		// Try to extract count from HTML title
		if strings.Contains(bodyStr, " - ") && strings.Contains(bodyStr, " Web pages") {
			// Extract: "dcbap.com" - 36 Web pages - PublicWWW.com
			parts := strings.Split(bodyStr, " - ")
			if len(parts) >= 2 {
				countStr := strings.TrimSpace(parts[1])
				countStr = strings.Split(countStr, " ")[0]
				var count int
				fmt.Sscanf(countStr, "%d", &count)
				if count > 0 {
					// Store a placeholder result
					_, err := p.db.Exec(`
						INSERT OR REPLACE INTO publicwww_results (domain, site_url, snippet)
						VALUES (?, ?, ?)
					`, domain, "https://publicwww.com/websites/%22"+domain+"%22/",
					   fmt.Sprintf("Found %d websites using this domain (HTML response - CSV export unavailable)", count))
					if err != nil {
						return 0, fmt.Errorf("failed to save result: %w", err)
					}
					fmt.Printf("   [OK] Found %d sites using %s (HTML response - no CSV data)\n", count, domain)
					return count, nil
				}
			}
		}
		return 0, fmt.Errorf("received HTML instead of CSV (API key may be invalid or free tier limited)")
	}

	// Try JSON fallback (paid tier)
	var pwwResp PublicWWWResponse
	if err := json.Unmarshal(body, &pwwResp); err == nil {
		// Store results in database
		for _, result := range pwwResp.Results {
			_, err := p.db.Exec(`
				INSERT OR REPLACE INTO publicwww_results (domain, site_url, snippet)
				VALUES (?, ?, ?)
			`, domain, result.URL, result.Snippet)
			if err != nil {
				return 0, fmt.Errorf("failed to save result: %w", err)
			}
		}

		fmt.Printf("   [OK] Found %d sites using %s (JSON export)\n", pwwResp.Total, domain)
		return pwwResp.Total, nil
	}

	return 0, fmt.Errorf("unknown response format from PublicWWW")
}

// ResearchAvailableDomains researches all available domains
func (p *PublicWWWChecker) ResearchAvailableDomains(availableDomains []string) error {
	fmt.Printf("\n[*] PublicWWW Research Phase\n")
	fmt.Printf("    Researching %d available domains\n", len(availableDomains))
	fmt.Printf("    Rate limit: %s between requests\n\n", p.rateLimit)

	for i, domain := range availableDomains {
		fmt.Printf("[%d/%d] %s\n", i+1, len(availableDomains), domain)

		count, err := p.ResearchDomain(domain)
		if err != nil {
			fmt.Printf("   [WARN] Research failed: %v\n", err)
			continue
		}

		if count == 0 {
			fmt.Printf("   [INFO] No results found\n")
		}
	}

	fmt.Printf("\n[OK] PublicWWW research complete\n\n")
	return nil
}

// GetTotalRequests returns number of API requests made
func (p *PublicWWWChecker) GetTotalRequests() int {
	return p.requestCount
}
