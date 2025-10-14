package checker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/aws/aws-sdk-go-v2/service/route53domains/types"

	"ghosted-v8/storage"
)

// Route53Checker checks domain availability using AWS Route53
type Route53Checker struct {
	client *route53domains.Client
	db     *storage.Database
	mu     sync.Mutex
}

// NewRoute53Checker creates a new Route53 checker
func NewRoute53Checker(db *storage.Database) (*Route53Checker, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"), // Route53 Domains API only in us-east-1
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &Route53Checker{
		client: route53domains.NewFromConfig(cfg),
		db:     db,
	}, nil
}

// CheckDomains checks availability of all domains
func (c *Route53Checker) CheckDomains(ctx context.Context, domains []string, concurrency int) (int, error) {
	if concurrency <= 0 {
		concurrency = 10
	}

	fmt.Printf("\n[*] Checking %d domains via Route53 (concurrency: %d)...\n", len(domains), concurrency)

	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	availableCount := 0
	var countMu sync.Mutex

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return availableCount, ctx.Err()
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(d string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			available, status, apiResponse := c.checkSingle(ctx, d)

			// Save to database
			if err := c.db.SaveAvailabilityCheck(d, status, available, apiResponse); err != nil {
				fmt.Printf("[WARN]  Failed to save availability check for %s: %v\n", d, err)
			}

			if available {
				countMu.Lock()
				availableCount++
				fmt.Printf("[CRITICAL] AVAILABLE: %s (status: %s) - %d total\n", d, status, availableCount)
				countMu.Unlock()
			} else if status != "API_ERROR" {
				fmt.Printf("[OK] %s - %s\n", d, status)
			}
		}(domain)

		// Rate limiting: small delay between requests
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()

	fmt.Printf("\n[OK] Availability checks complete\n")
	fmt.Printf("  Available domains: %d\n", availableCount)

	return availableCount, nil
}

// checkSingle checks a single domain
func (c *Route53Checker) checkSingle(ctx context.Context, domain string) (bool, string, string) {
	input := &route53domains.CheckDomainAvailabilityInput{
		DomainName: aws.String(domain),
	}

	resp, err := c.client.CheckDomainAvailability(ctx, input)
	if err != nil {
		errMsg := fmt.Sprintf("Error: %v", err)
		fmt.Printf("[ERROR] Route53 check failed for %s: %v\n", domain, err)
		return false, "API_ERROR", errMsg
	}

	availability := string(resp.Availability)

	// Map Route53 availability to our status
	// AVAILABLE, AVAILABLE_RESERVED, AVAILABLE_PREORDER = available
	// UNAVAILABLE, PENDING, RESERVED, DONT_KNOW = not available
	isAvailable := availability == string(types.DomainAvailabilityAvailable) ||
		availability == string(types.DomainAvailabilityAvailableReserved) ||
		availability == string(types.DomainAvailabilityAvailablePreorder)

	return isAvailable, availability, fmt.Sprintf("Route53 response: %s", availability)
}

