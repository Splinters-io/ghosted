package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
)

func main() {
	fmt.Println("Testing Route53 Domain Availability API...")
	fmt.Println("==========================================\n")

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
	)
	if err != nil {
		fmt.Printf("❌ Failed to load AWS config: %v\n", err)
		return
	}

	fmt.Println("✅ AWS config loaded successfully")
	fmt.Printf("   Region: %s\n\n", cfg.Region)

	client := route53domains.NewFromConfig(cfg)

	// Test domains
	domains := []string{
		"thecontractor.io",
		"m00m00000thecontractor.io",
	}

	for _, domain := range domains {
		fmt.Printf("Checking: %s\n", domain)
		fmt.Printf("─────────────────────────────────────\n")

		input := &route53domains.CheckDomainAvailabilityInput{
			DomainName: aws.String(domain),
		}

		resp, err := client.CheckDomainAvailability(context.Background(), input)
		if err != nil {
			fmt.Printf("❌ API Error: %v\n\n", err)
			continue
		}

		availability := string(resp.Availability)
		fmt.Printf("✅ Response: %s\n", availability)

		switch availability {
		case "AVAILABLE":
			fmt.Printf("   💰 This domain CAN be registered!\n")
		case "UNAVAILABLE":
			fmt.Printf("   🔒 This domain is already registered\n")
		case "DONT_KNOW":
			fmt.Printf("   ❓ Route53 cannot determine availability\n")
		default:
			fmt.Printf("   ℹ️  Status: %s\n", availability)
		}
		fmt.Printf("   Cost: $0.01\n\n")
	}
}
