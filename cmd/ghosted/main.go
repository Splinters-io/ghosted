// Command ghosted finds the outside domains a site trusts and checks whether any can be bought.
//
//	ghosted scan example.com [more.example ...]
//	ghosted scan -f targets.txt
//	ghosted har capture.har [--target www.example.com]
//
// Domains come from the same places the Ghosteds webapp reads: CSP headers and meta CSP, HTML,
// CSS and JavaScript references, JSON data, redirects, SPF terms and DMARC report addresses.
// Availability is decided DNS-first: a domain with its own nameservers is registered. Anything
// else under a suffix AWS sells is checked with AWS Route 53 CheckDomainAvailability.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"

	"ghosted-v8/internal/engine"
)

func usage() {
	fmt.Fprint(os.Stderr, `ghosted: find trusted outside domains that are up for sale

Usage:
  ghosted scan [flags] <host> [host ...]
  ghosted scan [flags] -f targets.txt
  ghosted har  [flags] <file.har>

Scan fetches each landing page (following redirects), reads its CSP headers, HTML, the scripts,
stylesheets and manifests it loads, and the host's SPF and DMARC records.

HAR reads a browser export instead (DevTools > Network > Save all as HAR with content). Use it
for lazy loads and anything that only happens after scrolling, clicking or signing in.

Flags:
`)
	flag.CommandLine.PrintDefaults()
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	file := fs.String("f", "", "read targets from a file, one per line (scan)")
	target := fs.String("target", "", "the site the HAR belongs to (har; default: host of the first entry)")
	noAWS := fs.Bool("no-aws", false, "DNS checks only; never call AWS")
	noMail := fs.Bool("no-mail", false, "skip SPF and DMARC")
	asJSON := fs.Bool("json", false, "print one JSON object per domain")
	verbose := fs.Bool("v", false, "list registered domains and their references too")
	workers := fs.Int("concurrency", 4, "targets scanned at once (scan)")
	resources := fs.Int("resources", 60, "subresources fetched per target (scan)")
	server := fs.String("dns", "", "DNS server host:port for nameserver checks (default: /etc/resolv.conf)")
	flag.CommandLine = fs
	fs.Usage = usage
	if command != "scan" && command != "har" {
		usage()
		os.Exit(2)
	}
	_ = fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var results []engine.Result
	switch command {
	case "scan":
		targets := fs.Args()
		if *file != "" {
			more, err := readLines(*file)
			if err != nil {
				fatal(err)
			}
			targets = append(targets, more...)
		}
		if len(targets) == 0 {
			usage()
			os.Exit(2)
		}
		o := engine.DefaultOptions()
		o.MaxResources = *resources
		results = make([]engine.Result, len(targets))
		var wg sync.WaitGroup
		sem := make(chan struct{}, max(1, *workers))
		for i, t := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				fmt.Fprintf(os.Stderr, "scanning %s\n", t)
				r := engine.Scan(ctx, t, o, !*noMail)
				results[i] = r
			}()
		}
		wg.Wait()
	case "har":
		if fs.NArg() != 1 {
			usage()
			os.Exit(2)
		}
		r, err := engine.HAR(fs.Arg(0), *target)
		if err != nil {
			fatal(err)
		}
		if !*noMail {
			engine.Mail(ctx, &r)
		}
		results = []engine.Result{r}
	}

	checker, err := engine.NewChecker(ctx, !*noAWS, *server)
	if err != nil {
		fatal(err)
	}
	report(ctx, checker, results, *asJSON, *verbose)
}

type domainOutput struct {
	engine.Availability
	References []engine.Found `json:"references"`
}

func report(ctx context.Context, checker *engine.Checker, results []engine.Result, asJSON, verbose bool) {
	byDomain := map[string][]engine.Found{}
	for _, r := range results {
		for _, w := range r.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s: %s\n", r.Target, w)
		}
		for _, f := range r.Found {
			byDomain[f.Registrable] = append(byDomain[f.Registrable], f)
		}
	}
	domains := make([]string, 0, len(byDomain))
	for d := range byDomain {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	fmt.Fprintf(os.Stderr, "checking %d outside domains\n", len(domains))

	counts := map[string]int{}
	var available, unsupported, unchecked []domainOutput
	enc := json.NewEncoder(os.Stdout)
	for _, d := range domains {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "interrupted")
			break
		}
		out := domainOutput{checker.Check(ctx, d), byDomain[d]}
		counts[out.Status]++
		switch {
		case out.Purchasable():
			available = append(available, out)
		case out.Status == engine.StatusUnsupportedTLD:
			unsupported = append(unsupported, out)
		case out.Status == engine.StatusUnchecked || out.Status == engine.StatusError:
			unchecked = append(unchecked, out)
		}
		if asJSON {
			_ = enc.Encode(out)
		} else if verbose || out.Purchasable() {
			printDomain(out)
		}
	}
	if asJSON {
		return
	}
	fmt.Println()
	if len(available) == 0 {
		fmt.Println("No outside domain can be bought (registrar answer AVAILABLE).")
	} else {
		fmt.Printf("%d can be bought:\n", len(available))
		for _, a := range available {
			fmt.Printf("  %s  %s\n", a.Domain, a.Status)
		}
	}
	if len(unsupported) > 0 {
		fmt.Printf("\n%d under suffixes AWS cannot register; check these with a registrar:\n", len(unsupported))
		for _, a := range unsupported {
			fmt.Printf("  %s\n", a.Domain)
		}
	}
	if len(unchecked) > 0 {
		fmt.Printf("\n%d not decided (not delegated in DNS and no registrar answer):\n", len(unchecked))
		for _, a := range unchecked {
			fmt.Printf("  %s  %s  %s\n", a.Domain, a.Status, a.Detail)
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Print("\nTotals:")
	for _, k := range keys {
		fmt.Printf("  %s %d", k, counts[k])
	}
	fmt.Println()
}

func printDomain(d domainOutput) {
	fmt.Printf("%s  %s  (%s)\n", d.Status, d.Domain, d.Provider)
	for _, f := range d.References {
		fmt.Printf("    %s  %s  %s  in %s\n", f.Target, f.Kind, f.Location, f.Document)
		if f.URL != f.Host {
			fmt.Printf("      %s\n", f.URL)
		}
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := strings.TrimSpace(s.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, s.Err()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ghosted:", err)
	os.Exit(1)
}
