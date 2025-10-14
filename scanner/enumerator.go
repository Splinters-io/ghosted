package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"ghosted-v8/storage"
)

// Enumerator handles subdomain discovery
type Enumerator struct {
	db              *storage.Database
	toolsPath       string
	wordlistsPath   string
	wordlistLevel   int
	subfinderPath   string
	dnsxPath        string
	dnsxConcurrency int
}

// NewEnumerator creates a new enumerator
func NewEnumerator(db *storage.Database, wordlistLevel int) (*Enumerator, error) {
	return NewEnumeratorWithConcurrency(db, wordlistLevel, 300)
}

// NewEnumeratorWithConcurrency creates enumerator with custom dnsx concurrency
func NewEnumeratorWithConcurrency(db *storage.Database, wordlistLevel int, dnsxConcurrency int) (*Enumerator, error) {
	// Get paths relative to binary
	toolsPath := "tools"
	wordlistsPath := "wordlists"

	subfinderPath := filepath.Join(toolsPath, "subfinder")
	dnsxPath := filepath.Join(toolsPath, "dnsx")

	// Verify tools exist
	if _, err := os.Stat(subfinderPath); err != nil {
		return nil, fmt.Errorf("subfinder not found at %s: %w", subfinderPath, err)
	}
	if _, err := os.Stat(dnsxPath); err != nil {
		return nil, fmt.Errorf("dnsx not found at %s: %w", dnsxPath, err)
	}

	return &Enumerator{
		db:              db,
		toolsPath:       toolsPath,
		wordlistsPath:   wordlistsPath,
		wordlistLevel:   wordlistLevel,
		subfinderPath:   subfinderPath,
		dnsxPath:        dnsxPath,
		dnsxConcurrency: dnsxConcurrency,
	}, nil
}

// Enumerate discovers subdomains using subfinder + dnsx
func (e *Enumerator) Enumerate(ctx context.Context, target string) ([]string, error) {
	var allSubdomains []string
	var mu sync.Mutex

	// Phase 1: Passive enumeration with subfinder
	fmt.Printf("[*] Running subfinder for %s...\n", target)
	passive, err := e.runSubfinder(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("subfinder failed: %w", err)
	}

	for _, sub := range passive {
		if err := e.db.SaveSubdomain(sub, "subfinder"); err != nil {
			fmt.Printf("Warning: failed to save subdomain %s: %v\n", sub, err)
		}
	}

	mu.Lock()
	allSubdomains = append(allSubdomains, passive...)
	mu.Unlock()

	fmt.Printf("[OK] Subfinder found %d subdomains\n", len(passive))

	// Phase 2: Active bruteforcing with dnsx
	// Level 0 or no flag = passive only
	// Level 1+ = ALL wordlists in folder
	if e.wordlistLevel > 0 {
		wordlists, err := e.findWordlists()
		if err != nil {
			return nil, fmt.Errorf("failed to find wordlists: %w", err)
		}

		if len(wordlists) == 0 {
			fmt.Println("[WARN]  No wordlists found in wordlists/ directory")
		} else {
			// Filter out already completed wordlists
			var pendingWordlists []string
			var skippedCount int

			for _, wl := range wordlists {
				wordlistName := filepath.Base(wl)
				completed, err := e.db.IsWordlistCompleted(wordlistName)
				if err != nil {
					fmt.Printf("[WARN]  Failed to check wordlist status for %s: %v\n", wordlistName, err)
					pendingWordlists = append(pendingWordlists, wl)
					continue
				}

				if completed {
					fmt.Printf("  [SKIP] Wordlist %s already processed\n", wordlistName)
					skippedCount++
				} else {
					pendingWordlists = append(pendingWordlists, wl)
				}
			}

			if skippedCount > 0 {
				fmt.Printf("[*] Skipped %d already-processed wordlist(s)\n", skippedCount)
			}

			if len(pendingWordlists) == 0 {
				fmt.Println("[*] All wordlists already processed, skipping enumeration phase")
			} else {
				fmt.Printf("[*] Running dnsx with %d pending wordlist(s) in parallel...\n", len(pendingWordlists))

				// Run all pending wordlists concurrently
				var wg sync.WaitGroup
				results := make(chan []string, len(pendingWordlists))
				errors := make(chan error, len(pendingWordlists))
				wordlistResults := make(chan struct {
					name  string
					path  string
					count int
				}, len(pendingWordlists))

				for i, wordlist := range pendingWordlists {
					wg.Add(1)
					go func(idx int, wl string) {
						defer wg.Done()
						wordlistName := filepath.Base(wl)
						fmt.Printf("  Wordlist %d/%d: %s (starting)\n", idx+1, len(pendingWordlists), wordlistName)

						active, err := e.runDNSXWithWordlist(ctx, target, wl)
						if err != nil {
							errors <- fmt.Errorf("dnsx failed on wordlist %d: %w", idx+1, err)
							return
						}

						fmt.Printf("  [OK] Wordlist %d/%d: %s found %d subdomains\n", idx+1, len(pendingWordlists), wordlistName, len(active))
						results <- active
						wordlistResults <- struct {
							name  string
							path  string
							count int
						}{wordlistName, wl, len(active)}
					}(i, wordlist)
				}

				// Wait for all wordlists to complete
				go func() {
					wg.Wait()
					close(results)
					close(errors)
					close(wordlistResults)
				}()

				// Collect results
				for active := range results {
					for _, sub := range active {
						if err := e.db.SaveSubdomain(sub, "dnsx"); err != nil {
							fmt.Printf("Warning: failed to save subdomain %s: %v\n", sub, err)
						}
					}

					mu.Lock()
					allSubdomains = append(allSubdomains, active...)
					mu.Unlock()
				}

				// Save wordlist progress
				for wr := range wordlistResults {
					if err := e.db.SaveWordlistProgress(wr.name, wr.path, wr.count); err != nil {
						fmt.Printf("[WARN]  Failed to save wordlist progress for %s: %v\n", wr.name, err)
					}
				}

				// Check for errors
				for err := range errors {
					return nil, err
				}
			}
		}
	}

	// Deduplicate
	unique := make(map[string]bool)
	var result []string
	for _, sub := range allSubdomains {
		if !unique[sub] {
			unique[sub] = true
			result = append(result, sub)
		}
	}

	return result, nil
}

// runSubfinder executes subfinder for passive enumeration
func (e *Enumerator) runSubfinder(ctx context.Context, target string) ([]string, error) {
	cmd := exec.CommandContext(ctx, e.subfinderPath, "-d", target, "-silent", "-all", "-t", "50", "-timeout", "3")

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %w", err)
	}

	var subdomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	return subdomains, scanner.Err()
}

// runDNSXWithWordlist executes dnsx with a specific wordlist
func (e *Enumerator) runDNSXWithWordlist(ctx context.Context, target string, wordlist string) ([]string, error) {
	// Run dnsx with wordlist and custom concurrency
	concurrencyFlag := fmt.Sprintf("%d", e.dnsxConcurrency)
	cmd := exec.CommandContext(ctx, e.dnsxPath, "-d", target, "-w", wordlist, "-silent", "-t", concurrencyFlag)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dnsx execution failed: %w", err)
	}

	var subdomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	return subdomains, scanner.Err()
}

// findWordlists discovers all .txt files in wordlists/ directory
func (e *Enumerator) findWordlists() ([]string, error) {
	var wordlists []string

	entries, err := os.ReadDir(e.wordlistsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wordlists directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".txt") {
			wordlists = append(wordlists, filepath.Join(e.wordlistsPath, entry.Name()))
		}
	}

	return wordlists, nil
}
