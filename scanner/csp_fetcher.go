package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"ghosted-v8/storage"
)

// CSPFetcher fetches CSP headers from subdomains
type CSPFetcher struct {
	db          *storage.Database
	client      *http.Client
	concurrency int
}

// NewCSPFetcher creates a new CSP fetcher
func NewCSPFetcher(db *storage.Database, concurrency int) *CSPFetcher {
	if concurrency <= 0 {
		concurrency = 50 // Much higher concurrency
	}

	return &CSPFetcher{
		db: db,
		client: &http.Client{
			Timeout: 3 * time.Second, // Shorter timeout for faster failures
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    500,
				MaxConnsPerHost: 50,
				IdleConnTimeout: 10 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		concurrency: concurrency,
	}
}

// FetchCSP fetches CSP headers from all subdomains
func (f *CSPFetcher) FetchCSP(ctx context.Context, subdomains []string) (int, error) {
	fmt.Printf("\n🌐 Fetching CSP headers from %d subdomains (concurrency: %d)...\n", len(subdomains), f.concurrency)

	semaphore := make(chan struct{}, f.concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	cspCount := 0

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return cspCount, ctx.Err()
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			csp, err := f.fetchSingle(ctx, sub)
			if err != nil {
				// Silent failure - most domains won't have CSP
				return
			}

			if csp != "" {
				if err := f.db.SaveCSPRecord(sub, csp); err != nil {
					fmt.Printf("Warning: failed to save CSP for %s: %v\n", sub, err)
					return
				}

				mu.Lock()
				cspCount++
				fmt.Printf("[OK] Found CSP on %s (%d total)\n", sub, cspCount)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()

	fmt.Printf("\n[OK] Completed CSP fetching: %d subdomains with CSP policies\n", cspCount)
	return cspCount, nil
}

// fetchSingle fetches CSP header from a single domain
func (f *CSPFetcher) fetchSingle(ctx context.Context, subdomain string) (string, error) {
	// Try HTTPS first
	csp, err := f.tryScheme(ctx, "https", subdomain)
	if err == nil && csp != "" {
		return csp, nil
	}

	// Fallback to HTTP
	csp, err = f.tryScheme(ctx, "http", subdomain)
	if err == nil && csp != "" {
		return csp, nil
	}

	return "", fmt.Errorf("no CSP found")
}

// tryScheme attempts to fetch CSP with a specific scheme
func (f *CSPFetcher) tryScheme(ctx context.Context, scheme, subdomain string) (string, error) {
	url := fmt.Sprintf("%s://%s", scheme, subdomain)

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Ghosted-V8-CSP-Scanner")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check for CSP headers
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		csp = resp.Header.Get("Content-Security-Policy-Report-Only")
	}

	return csp, nil
}
